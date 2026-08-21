import { betterAuth, type BetterAuthOptions } from "better-auth";
import { APIError } from "better-auth";
import { memoryAdapter, type MemoryDB } from "better-auth/adapters/memory";
import { emailOTP } from "better-auth/plugins";
import { describe, expect, it } from "vitest";
import {
	invite,
	type InviteOptions,
	type ListedInvitation,
	type SendInvitationEmailData,
} from "../src/index";

const ADMIN_EMAIL = "admin@example.com";
const ADMIN_PASSWORD = "admin-password-123";
const REDIRECT_URL = "https://app.example.com/accept-invite";

interface TestAuthConfig {
	/** Extra `databaseHooks` passed to betterAuth. */
	databaseHooks?: BetterAuthOptions["databaseHooks"];
	/** Override the `user` config (additionalFields, ...). */
	user?: BetterAuthOptions["user"];
	/** Extra plugins mounted alongside `invite()`. */
	plugins?: BetterAuthOptions["plugins"];
	/** Skip creating the seed admin — for first-user scenarios. */
	withoutAdmin?: boolean;
	/** Extra top-level options (advanced, ...). */
	options?: Partial<BetterAuthOptions>;
}

async function createTestAuth(
	overrides: Partial<InviteOptions> = {},
	config: TestAuthConfig = {},
) {
	const db: MemoryDB = {
		user: [],
		session: [],
		account: [],
		verification: [],
		invite: [],
	};
	const emails: SendInvitationEmailData[] = [];
	const auth = betterAuth({
		baseURL: "http://localhost:3000",
		secret: "better-auth-invite-test-secret-0123456789",
		database: memoryAdapter(db),
		emailAndPassword: {
			enabled: true,
		},
		user: config.user ?? {
			additionalFields: {
				role: {
					type: "string",
					required: false,
					input: false,
				},
			},
		},
		databaseHooks: config.databaseHooks,
		...config.options,
		plugins: [
			invite({
				sendInvitationEmail: async (data) => {
					emails.push(data);
				},
				inviteRedirectURL: REDIRECT_URL,
				...overrides,
			}),
			...(config.plugins ?? []),
		],
	});

	if (config.withoutAdmin) {
		return { auth, db, emails, adminHeaders: new Headers() };
	}

	// create an admin user and grab their session cookie
	const res = await auth.api.signUpEmail({
		body: {
			email: ADMIN_EMAIL,
			password: ADMIN_PASSWORD,
			name: "Admin",
		},
		returnHeaders: true,
	});
	const adminRow = db["user"]!.find((u: any) => u.email === ADMIN_EMAIL);
	adminRow.role = "admin";
	const adminHeaders = toCookieHeaders(res.headers);

	return { auth, db, emails, adminHeaders };
}

function toCookieHeaders(headers: Headers) {
	const cookie = headers
		.getSetCookie()
		.map((c) => c.split(";")[0])
		.join("; ");
	return new Headers({ cookie });
}

async function expectAPIError(
	promise: Promise<unknown>,
	statusCode: number,
	code?: string,
) {
	try {
		await promise;
	} catch (error) {
		expect(error).toBeInstanceOf(APIError);
		const apiError = error as APIError;
		expect(apiError.statusCode).toBe(statusCode);
		if (code) {
			expect((apiError.body as any)?.code).toBe(code);
		}
		return apiError;
	}
	throw new Error(
		`Expected an APIError with status ${statusCode}, but no error was thrown`,
	);
}

function expireInvite(db: MemoryDB, invitationId: string) {
	const row = db["invite"]!.find((i: any) => i.id === invitationId);
	if (!row) throw new Error("invite row not found");
	row.expiresAt = new Date(Date.now() - 60_000);
}

/**
 * Intercept reads of the `user` table in the memory adapter to simulate
 * writes committed by a concurrent request between two adapter operations
 * of the same handler. `onAccess` runs before each read, with a 1-based
 * access counter.
 */
function trapUserAccess(
	db: MemoryDB,
	onAccess: (accessCount: number, rows: any[]) => void,
) {
	const rows = db["user"] as any[];
	let count = 0;
	Object.defineProperty(db, "user", {
		configurable: true,
		get() {
			count += 1;
			onAccess(count, rows);
			return rows;
		},
		set(value) {
			Object.defineProperty(db, "user", {
				value,
				writable: true,
				configurable: true,
			});
		},
	});
}

describe("invite plugin", () => {
	describe("send", () => {
		it("sends an invitation, delivers the email, and never leaks the token hash", async () => {
			const { auth, db, emails, adminHeaders } = await createTestAuth();
			const invitation = await auth.api.sendInvite({
				body: {
					email: "Invitee@Example.com",
					name: "Invitee",
					role: "member",
				},
				headers: adminHeaders,
			});

			expect(invitation.email).toBe("invitee@example.com");
			expect(invitation.name).toBe("Invitee");
			expect(invitation.role).toBe("member");
			expect(invitation.status).toBe("pending");
			expect(invitation.id).toBeTruthy();
			expect(invitation.expiresAt).toBeInstanceOf(Date);
			expect((invitation as any).tokenHash).toBeUndefined();
			expect(JSON.stringify(invitation)).not.toContain(
				db["invite"]![0].tokenHash,
			);

			expect(emails).toHaveLength(1);
			expect(emails[0]!.invitation.email).toBe("invitee@example.com");
			expect(emails[0]!.token).toMatch(/^[a-zA-Z0-9]{32}$/);
			expect(emails[0]!.url).toBe(`${REDIRECT_URL}?token=${emails[0]!.token}`);
			expect(emails[0]!.inviter.email).toBe(ADMIN_EMAIL);
			expect((emails[0]!.invitation as any).tokenHash).toBeUndefined();

			// the stored hash is not the raw token
			expect(db["invite"]![0].tokenHash).not.toBe(emails[0]!.token);
			expect(db["invite"]![0].tokenHash).toMatch(/^[0-9a-f]{64}$/);
		});

		it("builds the url from inviteRedirectURL, appending with & when it already has a query", async () => {
			const { auth, emails, adminHeaders } = await createTestAuth({
				inviteRedirectURL: "https://other.example.com/welcome?source=email",
			});
			await auth.api.sendInvite({
				body: { email: "invitee@example.com" },
				headers: adminHeaders,
			});
			expect(emails[0]!.url).toBe(
				`https://other.example.com/welcome?source=email&token=${emails[0]!.token}`,
			);
		});

		it("requires inviteRedirectURL at plugin creation", () => {
			expect(() =>
				invite({
					sendInvitationEmail: async () => {},
				} as unknown as InviteOptions),
			).toThrow(/inviteRedirectURL/);
		});

		it("rejects an out-of-range expiresIn option at plugin creation", () => {
			expect(() =>
				invite({
					sendInvitationEmail: async () => {},
					inviteRedirectURL: REDIRECT_URL,
					expiresIn: 1e15,
				}),
			).toThrow(/expiresIn/);
		});

		it("rejects an extreme per-call expiresIn that would overflow the expiry date", async () => {
			const { auth, adminHeaders } = await createTestAuth();
			// body validation errors are thrown by better-call's APIError
			// class, so assert on the error shape instead of instanceof
			await expect(
				auth.api.sendInvite({
					body: { email: "invitee@example.com", expiresIn: 1e15 },
					headers: adminHeaders,
				}),
			).rejects.toMatchObject({ statusCode: 400 });
			await expect(
				auth.api.resendInvite({
					body: { invitationId: "irrelevant", expiresIn: 1e15 },
					headers: adminHeaders,
				}),
			).rejects.toMatchObject({ statusCode: 400 });
		});

		it("enforces allowedRoles when configured", async () => {
			const { auth, adminHeaders } = await createTestAuth({
				allowedRoles: ["member", "viewer"],
			});
			await expectAPIError(
				auth.api.sendInvite({
					body: { email: "invitee@example.com", role: "admin" },
					headers: adminHeaders,
				}),
				400,
				"ROLE_NOT_ALLOWED",
			);
			await expectAPIError(
				auth.api.sendInvite({
					body: { email: "invitee@example.com", role: "user,admin" },
					headers: adminHeaders,
				}),
				400,
				"ROLE_NOT_ALLOWED",
			);
			const invitation = await auth.api.sendInvite({
				body: { email: "invitee@example.com", role: "member" },
				headers: adminHeaders,
			});
			expect(invitation.role).toBe("member");
		});

		it("stores metadata as JSON and returns it parsed everywhere", async () => {
			const { auth, db, emails, adminHeaders } = await createTestAuth();
			const metadata = { teamId: "team-1", plan: "pro" };
			const invitation = await auth.api.sendInvite({
				body: { email: "invitee@example.com", metadata },
				headers: adminHeaders,
			});
			expect(invitation.metadata).toEqual(metadata);
			expect(typeof db["invite"]![0].metadata).toBe("string");
			expect(emails[0]!.invitation.metadata).toEqual(metadata);

			const got = await auth.api.getInvite({
				query: { token: emails[0]!.token },
			});
			expect(got.metadata).toEqual(metadata);

			const { invitations } = await auth.api.listInvites({
				query: {},
				headers: adminHeaders,
			});
			expect(invitations[0]!.metadata).toEqual(metadata);
		});

		it("rejects unauthenticated requests with 401", async () => {
			const { auth } = await createTestAuth();
			await expectAPIError(
				auth.api.sendInvite({
					body: { email: "invitee@example.com" },
					headers: new Headers(),
				}),
				401,
			);
		});

		it("rejects non-admin users with 403", async () => {
			const { auth } = await createTestAuth();
			const res = await auth.api.signUpEmail({
				body: {
					email: "regular@example.com",
					password: "regular-password-123",
					name: "Regular",
				},
				returnHeaders: true,
			});
			await expectAPIError(
				auth.api.sendInvite({
					body: { email: "invitee@example.com" },
					headers: toCookieHeaders(res.headers),
				}),
				403,
				"NOT_AUTHORIZED_TO_INVITE",
			);
		});

		it("rejects inviting an email that already belongs to a user", async () => {
			const { auth, adminHeaders } = await createTestAuth();
			await expectAPIError(
				auth.api.sendInvite({
					body: { email: ADMIN_EMAIL },
					headers: adminHeaders,
				}),
				400,
				"USER_ALREADY_EXISTS",
			);
		});

		it("re-invite cancels the old invitation: old token dies, new token works", async () => {
			const { auth, emails, adminHeaders } = await createTestAuth();
			await auth.api.sendInvite({
				body: { email: "invitee@example.com" },
				headers: adminHeaders,
			});
			await auth.api.sendInvite({
				body: { email: "invitee@example.com" },
				headers: adminHeaders,
			});
			expect(emails).toHaveLength(2);
			const [first, second] = emails;

			await expectAPIError(
				auth.api.getInvite({ query: { token: first!.token } }),
				400,
				"INVITATION_CANCELED",
			);
			const valid = await auth.api.getInvite({
				query: { token: second!.token },
			});
			expect(valid.email).toBe("invitee@example.com");
			expect(valid.status).toBe("pending");
		});

		it("rejects re-invite when allowReInvite is false", async () => {
			const { auth, adminHeaders } = await createTestAuth({
				allowReInvite: false,
			});
			await auth.api.sendInvite({
				body: { email: "invitee@example.com" },
				headers: adminHeaders,
			});
			await expectAPIError(
				auth.api.sendInvite({
					body: { email: "invitee@example.com" },
					headers: adminHeaders,
				}),
				400,
				"INVITATION_ALREADY_SENT",
			);
		});

		it("honors a custom canInvite callback", async () => {
			const { auth, adminHeaders } = await createTestAuth({
				canInvite: (user) => user.email === "boss@example.com",
			});
			// the admin (role "admin") is no longer allowed
			await expectAPIError(
				auth.api.sendInvite({
					body: { email: "invitee@example.com" },
					headers: adminHeaders,
				}),
				403,
				"NOT_AUTHORIZED_TO_INVITE",
			);

			const res = await auth.api.signUpEmail({
				body: {
					email: "boss@example.com",
					password: "boss-password-123",
					name: "Boss",
				},
				returnHeaders: true,
			});
			const invitation = await auth.api.sendInvite({
				body: { email: "invitee@example.com" },
				headers: toCookieHeaders(res.headers),
			});
			expect(invitation.status).toBe("pending");
		});
	});

	describe("get", () => {
		it("returns invitation details for a valid token", async () => {
			const { auth, emails, adminHeaders } = await createTestAuth();
			await auth.api.sendInvite({
				body: { email: "invitee@example.com", name: "Invitee", role: "member" },
				headers: adminHeaders,
			});
			const result = await auth.api.getInvite({
				query: { token: emails[0]!.token },
			});
			expect(result).toMatchObject({
				email: "invitee@example.com",
				name: "Invitee",
				role: "member",
				status: "pending",
			});
			expect((result as any).tokenHash).toBeUndefined();
			expect((result as any).inviterId).toBeUndefined();
		});

		it("returns 404 for a bogus token", async () => {
			const { auth } = await createTestAuth();
			await expectAPIError(
				auth.api.getInvite({ query: { token: "not-a-real-token" } }),
				404,
				"INVITATION_NOT_FOUND",
			);
		});

		it("returns 410 for an expired token", async () => {
			const { auth, db, emails, adminHeaders } = await createTestAuth();
			const invitation = await auth.api.sendInvite({
				body: { email: "invitee@example.com" },
				headers: adminHeaders,
			});
			expireInvite(db, invitation.id);
			await expectAPIError(
				auth.api.getInvite({ query: { token: emails[0]!.token } }),
				410,
				"INVITATION_EXPIRED",
			);
		});
	});

	describe("accept", () => {
		it("creates a verified user with the invited role, signs them in, and marks the invite accepted", async () => {
			const { auth, db, emails, adminHeaders } = await createTestAuth();
			const invitation = await auth.api.sendInvite({
				body: { email: "invitee@example.com", name: "Invitee", role: "member" },
				headers: adminHeaders,
			});

			const { headers, response } = await auth.api.acceptInvite({
				body: {
					token: emails[0]!.token,
					password: "invitee-password-123",
				},
				returnHeaders: true,
			});

			// session returned + cookie set (autoSignIn default)
			expect(response.token).toBeTruthy();
			expect(
				headers.getSetCookie().some((c) => c.includes("session_token")),
			).toBe(true);

			// user created correctly
			expect(response.user.email).toBe("invitee@example.com");
			expect(response.user.name).toBe("Invitee");
			expect(response.user.emailVerified).toBe(true);
			const userRow = db["user"]!.find(
				(u: any) => u.email === "invitee@example.com",
			);
			expect(userRow.role).toBe("member");
			expect(userRow.emailVerified).toBe(true);

			// invite row updated
			const inviteRow = db["invite"]!.find((i: any) => i.id === invitation.id);
			expect(inviteRow.status).toBe("accepted");
			expect(inviteRow.acceptedUserId).toBe(response.user.id);

			// credential account works: sign in with the chosen password
			const signIn = await auth.api.signInEmail({
				body: {
					email: "invitee@example.com",
					password: "invitee-password-123",
				},
			});
			expect(signIn.token).toBeTruthy();
			expect(signIn.user.id).toBe(response.user.id);
		});

		it("does not create a session when autoSignIn is false", async () => {
			const { auth, emails, adminHeaders } = await createTestAuth({
				autoSignIn: false,
			});
			await auth.api.sendInvite({
				body: { email: "invitee@example.com" },
				headers: adminHeaders,
			});
			const { headers, response } = await auth.api.acceptInvite({
				body: {
					token: emails[0]!.token,
					password: "invitee-password-123",
				},
				returnHeaders: true,
			});
			expect(response.token).toBeNull();
			expect(
				headers.getSetCookie().some((c) => c.includes("session_token=")),
			).toBe(false);
		});

		it("cannot be accepted twice", async () => {
			const { auth, emails, adminHeaders } = await createTestAuth();
			await auth.api.sendInvite({
				body: { email: "invitee@example.com" },
				headers: adminHeaders,
			});
			await auth.api.acceptInvite({
				body: {
					token: emails[0]!.token,
					password: "invitee-password-123",
				},
			});
			await expectAPIError(
				auth.api.acceptInvite({
					body: {
						token: emails[0]!.token,
						password: "another-password-123",
					},
				}),
				400,
				"INVITATION_ALREADY_ACCEPTED",
			);
		});

		it("rejects an expired invitation", async () => {
			const { auth, db, emails, adminHeaders } = await createTestAuth();
			const invitation = await auth.api.sendInvite({
				body: { email: "invitee@example.com" },
				headers: adminHeaders,
			});
			expireInvite(db, invitation.id);
			await expectAPIError(
				auth.api.acceptInvite({
					body: {
						token: emails[0]!.token,
						password: "invitee-password-123",
					},
				}),
				410,
				"INVITATION_EXPIRED",
			);
		});

		it("rejects a canceled invitation", async () => {
			const { auth, emails, adminHeaders } = await createTestAuth();
			const invitation = await auth.api.sendInvite({
				body: { email: "invitee@example.com" },
				headers: adminHeaders,
			});
			await auth.api.cancelInvite({
				body: { invitationId: invitation.id },
				headers: adminHeaders,
			});
			await expectAPIError(
				auth.api.acceptInvite({
					body: {
						token: emails[0]!.token,
						password: "invitee-password-123",
					},
				}),
				400,
				"INVITATION_CANCELED",
			);
		});

		it("requires a password by default", async () => {
			const { auth, emails, adminHeaders } = await createTestAuth();
			await auth.api.sendInvite({
				body: { email: "invitee@example.com" },
				headers: adminHeaders,
			});
			await expectAPIError(
				auth.api.acceptInvite({
					body: { token: emails[0]!.token },
				}),
				400,
				"PASSWORD_REQUIRED",
			);
		});

		it("accepts without a password when requirePassword is false (no credential account)", async () => {
			const { auth, db, emails, adminHeaders } = await createTestAuth({
				requirePassword: false,
			});
			await auth.api.sendInvite({
				body: { email: "invitee@example.com" },
				headers: adminHeaders,
			});
			const result = await auth.api.acceptInvite({
				body: { token: emails[0]!.token },
			});
			expect(result.user.email).toBe("invitee@example.com");
			expect(result.user.emailVerified).toBe(true);
			expect(result.token).toBeTruthy(); // autoSignIn still works
			const accounts = db["account"]!.filter(
				(a: any) => a.userId === result.user.id,
			);
			expect(accounts).toHaveLength(0);
		});

		it("fails fast at init when emailAndPassword is disabled and requirePassword is on", async () => {
			const db: MemoryDB = {
				user: [],
				session: [],
				account: [],
				verification: [],
				invite: [],
			};
			const auth = betterAuth({
				baseURL: "http://localhost:3000",
				secret: "better-auth-invite-test-secret-0123456789",
				database: memoryAdapter(db),
				plugins: [
					invite({
						sendInvitationEmail: async () => {},
						inviteRedirectURL: REDIRECT_URL,
					}),
				],
			});
			await expect(
				auth.api.getInvite({ query: { token: "whatever" } }),
			).rejects.toThrow(/emailAndPassword/);
		});

		it("forwards user.additionalFields from the body to the created user, like sign-up", async () => {
			const { auth, db, emails, adminHeaders } = await createTestAuth(
				{},
				{
					user: {
						additionalFields: {
							role: { type: "string", required: false, input: false },
							department: { type: "string", required: false },
						},
					},
				},
			);
			await auth.api.sendInvite({
				body: { email: "invitee@example.com", role: "member" },
				headers: adminHeaders,
			});
			const result = await auth.api.acceptInvite({
				body: {
					token: emails[0]!.token,
					password: "invitee-password-123",
					department: "engineering",
				},
			});
			const userRow = db["user"]!.find((u: any) => u.id === result.user.id);
			expect(userRow.department).toBe("engineering");
			expect(userRow.role).toBe("member");
		});

		it("rejects body fields marked input: false instead of writing them", async () => {
			const { auth, emails, adminHeaders } = await createTestAuth(
				{},
				{
					user: {
						additionalFields: {
							role: { type: "string", required: false, input: false },
							internalNote: {
								type: "string",
								required: false,
								input: false,
							},
						},
					},
				},
			);
			await auth.api.sendInvite({
				body: { email: "invitee@example.com" },
				headers: adminHeaders,
			});
			await expectAPIError(
				auth.api.acceptInvite({
					body: {
						token: emails[0]!.token,
						password: "invitee-password-123",
						internalNote: "injected",
					},
				}),
				400,
			);
		});

		it("never takes `role` from the accept body, whatever the user schema allows", async () => {
			// `role` declared input: true — without the plugin stripping it,
			// an invitee could pick their own role while accepting
			const { auth, db, emails, adminHeaders } = await createTestAuth(
				{},
				{
					user: {
						additionalFields: {
							role: { type: "string", required: false, input: true },
						},
					},
				},
			);
			await auth.api.sendInvite({
				body: { email: "invitee@example.com", role: "member" },
				headers: adminHeaders,
			});
			await auth.api.acceptInvite({
				body: {
					token: emails[0]!.token,
					password: "invitee-password-123",
					role: "admin",
				},
			});
			const userRow = db["user"]!.find(
				(u: any) => u.email === "invitee@example.com",
			);
			expect(userRow.role).toBe("member");
		});

		it("rolls back the created user when account creation fails, so the invite can be retried", async () => {
			const state = { fail: false };
			const { auth, db, emails, adminHeaders } = await createTestAuth(
				{},
				{
					databaseHooks: {
						account: {
							create: {
								before: async () => {
									if (state.fail) {
										state.fail = false;
										throw new Error("transient db failure");
									}
								},
							},
						},
					},
				},
			);
			const invitation = await auth.api.sendInvite({
				body: { email: "invitee@example.com" },
				headers: adminHeaders,
			});

			state.fail = true;
			await expectAPIError(
				auth.api.acceptInvite({
					body: {
						token: emails[0]!.token,
						password: "invitee-password-123",
					},
				}),
				500,
				"FAILED_TO_CREATE_USER",
			);

			// no orphaned half-registered user, invite back to pending
			expect(
				db["user"]!.find((u: any) => u.email === "invitee@example.com"),
			).toBeUndefined();
			expect(db["invite"]![0].status).toBe("pending");

			// retrying the same token now succeeds
			const retried = await auth.api.acceptInvite({
				body: {
					token: emails[0]!.token,
					password: "invitee-password-123",
				},
			});
			expect(retried.user.email).toBe("invitee@example.com");
			const inviteRow = db["invite"]!.find((i: any) => i.id === invitation.id);
			expect(inviteRow.status).toBe("accepted");
			expect(inviteRow.acceptedUserId).toBe(retried.user.id);
		});

		it("does not create a duplicate user when the email signs up concurrently (re-check inside the claim)", async () => {
			const { auth, db, emails, adminHeaders } = await createTestAuth();
			await auth.api.sendInvite({
				body: { email: "invitee@example.com" },
				headers: adminHeaders,
			});

			// simulate an independent sign-up committing between accept's
			// pre-claim existing-user check (access #1) and its post-claim
			// re-check (access #2)
			trapUserAccess(db, (accessCount, rows) => {
				if (accessCount === 2) {
					rows.push({
						id: "raced-user",
						email: "invitee@example.com",
						emailVerified: false,
						name: "Raced",
						createdAt: new Date(),
						updatedAt: new Date(),
					});
				}
			});

			await expectAPIError(
				auth.api.acceptInvite({
					body: {
						token: emails[0]!.token,
						password: "invitee-password-123",
					},
				}),
				400,
				"USER_ALREADY_EXISTS",
			);

			const rows = db["user"]!.filter(
				(u: any) => u.email === "invitee@example.com",
			);
			expect(rows).toHaveLength(1);
			expect(rows[0].id).toBe("raced-user");
			// the claim was released
			expect(db["invite"]![0].status).toBe("pending");
		});

		it("cannot accept with a token superseded by a concurrent resend (claim is conditioned on the token hash)", async () => {
			const { auth, db, emails, adminHeaders } = await createTestAuth();
			await auth.api.sendInvite({
				body: { email: "invitee@example.com" },
				headers: adminHeaders,
			});

			// simulate a resend committing a rotated token hash after accept
			// looked the row up but before it claims it (the pre-claim
			// existing-user check is the first `user` access)
			trapUserAccess(db, (accessCount) => {
				if (accessCount === 1) {
					db["invite"]![0].tokenHash = "0".repeat(64);
				}
			});

			await expectAPIError(
				auth.api.acceptInvite({
					body: {
						token: emails[0]!.token,
						password: "invitee-password-123",
					},
				}),
				404,
				"INVITATION_NOT_FOUND",
			);

			expect(db["invite"]![0].status).toBe("pending");
			expect(
				db["user"]!.find((u: any) => u.email === "invitee@example.com"),
			).toBeUndefined();
		});

		it("invokes onInvitationAccepted with the accepted invitation and the created user", async () => {
			const calls: { invitation: any; user: any }[] = [];
			const { auth, emails, adminHeaders } = await createTestAuth({
				onInvitationAccepted: async (data) => {
					calls.push(data);
				},
			});
			const invitation = await auth.api.sendInvite({
				body: {
					email: "invitee@example.com",
					role: "member",
					metadata: { teamId: "team-1" },
				},
				headers: adminHeaders,
			});
			const result = await auth.api.acceptInvite({
				body: {
					token: emails[0]!.token,
					password: "invitee-password-123",
				},
			});
			expect(calls).toHaveLength(1);
			expect(calls[0]!.invitation.id).toBe(invitation.id);
			expect(calls[0]!.invitation.status).toBe("accepted");
			expect(calls[0]!.invitation.acceptedUserId).toBe(result.user.id);
			expect(calls[0]!.invitation.role).toBe("member");
			expect(calls[0]!.invitation.metadata).toEqual({ teamId: "team-1" });
			expect(calls[0]!.user.email).toBe("invitee@example.com");
		});
	});

	describe("cancel", () => {
		it("cancels a pending invitation", async () => {
			const { auth, db, emails, adminHeaders } = await createTestAuth();
			const invitation = await auth.api.sendInvite({
				body: { email: "invitee@example.com" },
				headers: adminHeaders,
			});
			const canceled = await auth.api.cancelInvite({
				body: { invitationId: invitation.id },
				headers: adminHeaders,
			});
			expect(canceled.status).toBe("canceled");
			expect((canceled as any).tokenHash).toBeUndefined();
			expect(db["invite"]![0].status).toBe("canceled");
			await expectAPIError(
				auth.api.getInvite({ query: { token: emails[0]!.token } }),
				400,
				"INVITATION_CANCELED",
			);
		});

		it("returns 404 for an unknown invitation id", async () => {
			const { auth, adminHeaders } = await createTestAuth();
			await expectAPIError(
				auth.api.cancelInvite({
					body: { invitationId: "does-not-exist" },
					headers: adminHeaders,
				}),
				404,
				"INVITATION_NOT_FOUND",
			);
		});

		it("cannot cancel an accepted invitation", async () => {
			const { auth, emails, adminHeaders } = await createTestAuth();
			const invitation = await auth.api.sendInvite({
				body: { email: "invitee@example.com" },
				headers: adminHeaders,
			});
			await auth.api.acceptInvite({
				body: {
					token: emails[0]!.token,
					password: "invitee-password-123",
				},
			});
			await expectAPIError(
				auth.api.cancelInvite({
					body: { invitationId: invitation.id },
					headers: adminHeaders,
				}),
				400,
				"INVITATION_ALREADY_ACCEPTED",
			);
		});

		it("requires canInvite permission", async () => {
			const { auth, adminHeaders } = await createTestAuth();
			const invitation = await auth.api.sendInvite({
				body: { email: "invitee@example.com" },
				headers: adminHeaders,
			});
			const res = await auth.api.signUpEmail({
				body: {
					email: "regular@example.com",
					password: "regular-password-123",
					name: "Regular",
				},
				returnHeaders: true,
			});
			await expectAPIError(
				auth.api.cancelInvite({
					body: { invitationId: invitation.id },
					headers: toCookieHeaders(res.headers),
				}),
				403,
				"NOT_AUTHORIZED_TO_INVITE",
			);
		});
	});

	describe("list", () => {
		it("lists invitations without token hashes and computes the expired virtual status", async () => {
			const { auth, db, adminHeaders } = await createTestAuth();
			const first = await auth.api.sendInvite({
				body: { email: "one@example.com" },
				headers: adminHeaders,
			});
			await auth.api.sendInvite({
				body: { email: "two@example.com" },
				headers: adminHeaders,
			});
			expireInvite(db, first.id);

			const { invitations } = await auth.api.listInvites({
				query: {},
				headers: adminHeaders,
			});
			expect(invitations).toHaveLength(2);
			for (const invitation of invitations) {
				expect((invitation as any).tokenHash).toBeUndefined();
			}
			const one = invitations.find((i) => i.email === "one@example.com");
			const two = invitations.find((i) => i.email === "two@example.com");
			expect(one?.status).toBe("expired");
			expect(two?.status).toBe("pending");
		});

		it("filters by status, including the virtual expired status", async () => {
			const { auth, db, emails, adminHeaders } = await createTestAuth();
			const first = await auth.api.sendInvite({
				body: { email: "one@example.com" },
				headers: adminHeaders,
			});
			await auth.api.sendInvite({
				body: { email: "two@example.com" },
				headers: adminHeaders,
			});
			await auth.api.sendInvite({
				body: { email: "three@example.com" },
				headers: adminHeaders,
			});
			expireInvite(db, first.id);
			await auth.api.acceptInvite({
				body: {
					token: emails[2]!.token,
					password: "invitee-password-123",
				},
			});

			const expired = await auth.api.listInvites({
				query: { status: "expired" },
				headers: adminHeaders,
			});
			expect(expired.invitations.map((i) => i.email)).toEqual([
				"one@example.com",
			]);

			const pending = await auth.api.listInvites({
				query: { status: "pending" },
				headers: adminHeaders,
			});
			expect(pending.invitations.map((i) => i.email)).toEqual([
				"two@example.com",
			]);

			const accepted = await auth.api.listInvites({
				query: { status: "accepted" },
				headers: adminHeaders,
			});
			expect(accepted.invitations.map((i) => i.email)).toEqual([
				"three@example.com",
			]);
		});

		it("requires authentication", async () => {
			const { auth } = await createTestAuth();
			await expectAPIError(
				auth.api.listInvites({ query: {}, headers: new Headers() }),
				401,
			);
		});

		it("applies pending/expired filters in the database query so limit/offset paginate correctly", async () => {
			const { auth, db, adminHeaders } = await createTestAuth();
			const one = await auth.api.sendInvite({
				body: { email: "one@example.com" },
				headers: adminHeaders,
			});
			const two = await auth.api.sendInvite({
				body: { email: "two@example.com" },
				headers: adminHeaders,
			});
			await auth.api.sendInvite({
				body: { email: "three@example.com" },
				headers: adminHeaders,
			});
			expireInvite(db, one.id);
			expireInvite(db, two.id);

			// pending with a limit larger than the live-pending count must
			// still find the live invite even though the two most recent
			// pending-status rows are expired
			const pending = await auth.api.listInvites({
				query: { status: "pending", limit: 2 },
				headers: adminHeaders,
			});
			expect(pending.invitations.map((i) => i.email)).toEqual([
				"three@example.com",
			]);
			expect(pending.total).toBe(1);

			// expired pagination: limit applies to the expired set, total
			// reports the full filtered count
			const expiredPage = await auth.api.listInvites({
				query: { status: "expired", limit: 1 },
				headers: adminHeaders,
			});
			expect(expiredPage.invitations).toHaveLength(1);
			expect(expiredPage.invitations[0]!.status).toBe("expired");
			expect(expiredPage.total).toBe(2);

			const expiredRest = await auth.api.listInvites({
				query: { status: "expired", limit: 1, offset: 1 },
				headers: adminHeaders,
			});
			expect(expiredRest.invitations).toHaveLength(1);
			expect(
				new Set([
					expiredPage.invitations[0]!.email,
					expiredRest.invitations[0]!.email,
				]),
			).toEqual(new Set(["one@example.com", "two@example.com"]));
		});

		it("filters by email and returns the total count", async () => {
			const { auth, adminHeaders } = await createTestAuth();
			await auth.api.sendInvite({
				body: { email: "one@example.com" },
				headers: adminHeaders,
			});
			await auth.api.sendInvite({
				body: { email: "two@example.com" },
				headers: adminHeaders,
			});
			const all = await auth.api.listInvites({
				query: {},
				headers: adminHeaders,
			});
			expect(all.total).toBe(2);
			const filtered = await auth.api.listInvites({
				query: { email: "One@Example.com" },
				headers: adminHeaders,
			});
			expect(filtered.total).toBe(1);
			expect(filtered.invitations.map((i) => i.email)).toEqual([
				"one@example.com",
			]);
		});

		it("list items are assignable to the exported ListedInvitation type", async () => {
			const { auth, db, adminHeaders } = await createTestAuth();
			const sent = await auth.api.sendInvite({
				body: { email: "one@example.com" },
				headers: adminHeaders,
			});
			expireInvite(db, sent.id);
			const { invitations } = await auth.api.listInvites({
				query: {},
				headers: adminHeaders,
			});
			// type-level: the handler's return items carry the virtual status
			const item: ListedInvitation = invitations[0]!;
			expect(item.status).toBe("expired");
		});
	});

	describe("resend", () => {
		it("issues a fresh working token and invalidates the old one", async () => {
			const { auth, emails, adminHeaders } = await createTestAuth();
			const invitation = await auth.api.sendInvite({
				body: { email: "invitee@example.com" },
				headers: adminHeaders,
			});
			const refreshed = await auth.api.resendInvite({
				body: { invitationId: invitation.id },
				headers: adminHeaders,
			});
			expect(refreshed.id).toBe(invitation.id);
			expect((refreshed as any).tokenHash).toBeUndefined();
			expect(emails).toHaveLength(2);
			expect(emails[1]!.token).not.toBe(emails[0]!.token);

			// old token no longer resolves (hash was replaced)
			await expectAPIError(
				auth.api.getInvite({ query: { token: emails[0]!.token } }),
				404,
				"INVITATION_NOT_FOUND",
			);

			// new token accepts fine
			const accepted = await auth.api.acceptInvite({
				body: {
					token: emails[1]!.token,
					password: "invitee-password-123",
				},
			});
			expect(accepted.user.email).toBe("invitee@example.com");
		});

		it("allows resending an expired pending invitation", async () => {
			const { auth, db, emails, adminHeaders } = await createTestAuth();
			const invitation = await auth.api.sendInvite({
				body: { email: "invitee@example.com" },
				headers: adminHeaders,
			});
			expireInvite(db, invitation.id);
			await auth.api.resendInvite({
				body: { invitationId: invitation.id },
				headers: adminHeaders,
			});
			const result = await auth.api.getInvite({
				query: { token: emails[1]!.token },
			});
			expect(result.status).toBe("pending");
		});

		it("rejects resending a canceled invitation", async () => {
			const { auth, adminHeaders } = await createTestAuth();
			const invitation = await auth.api.sendInvite({
				body: { email: "invitee@example.com" },
				headers: adminHeaders,
			});
			await auth.api.cancelInvite({
				body: { invitationId: invitation.id },
				headers: adminHeaders,
			});
			await expectAPIError(
				auth.api.resendInvite({
					body: { invitationId: invitation.id },
					headers: adminHeaders,
				}),
				400,
				"INVITATION_CANCELED",
			);
		});

		it("rejects resending an accepted invitation", async () => {
			const { auth, emails, adminHeaders } = await createTestAuth();
			const invitation = await auth.api.sendInvite({
				body: { email: "invitee@example.com" },
				headers: adminHeaders,
			});
			await auth.api.acceptInvite({
				body: {
					token: emails[0]!.token,
					password: "invitee-password-123",
				},
			});
			await expectAPIError(
				auth.api.resendInvite({
					body: { invitationId: invitation.id },
					headers: adminHeaders,
				}),
				400,
				"INVITATION_ALREADY_ACCEPTED",
			);
		});
	});

	describe("claimOnSignUp", () => {
		it("claims a pending invitation when the invited email signs up directly", async () => {
			const accepted: any[] = [];
			const { auth, db, adminHeaders } = await createTestAuth({
				onInvitationAccepted: async (data) => {
					accepted.push(data);
				},
			});
			const invitation = await auth.api.sendInvite({
				body: {
					email: "walkin@example.com",
					role: "member",
					metadata: { plan: "pro" },
				},
				headers: adminHeaders,
			});

			await auth.api.signUpEmail({
				body: {
					email: "walkin@example.com",
					password: "direct-password-123",
					name: "Walk In",
				},
			});

			const row = db["invite"]!.find((i: any) => i.id === invitation.id);
			const user = db["user"]!.find(
				(u: any) => u.email === "walkin@example.com",
			);
			expect(row.status).toBe("accepted");
			expect(row.acceptedUserId).toBe(user.id);
			expect(user.role).toBe("member");
			expect(accepted).toHaveLength(1);
			expect(accepted[0].invitation.id).toBe(invitation.id);
			expect(accepted[0].invitation.status).toBe("accepted");
			expect(accepted[0].invitation.metadata).toEqual({ plan: "pro" });
			expect(accepted[0].user.email).toBe("walkin@example.com");
		});

		it("makes the invite link unusable after a direct sign-up claimed it", async () => {
			const { auth, emails, adminHeaders } = await createTestAuth();
			await auth.api.sendInvite({
				body: { email: "walkin@example.com" },
				headers: adminHeaders,
			});
			await auth.api.signUpEmail({
				body: {
					email: "walkin@example.com",
					password: "direct-password-123",
					name: "Walk In",
				},
			});
			await expectAPIError(
				auth.api.acceptInvite({
					body: {
						token: emails[0]!.token,
						password: "another-password-123",
					},
				}),
				400,
				"INVITATION_ALREADY_ACCEPTED",
			);
		});

		it("does not claim when claimOnSignUp is false", async () => {
			const { auth, db, adminHeaders } = await createTestAuth({
				claimOnSignUp: false,
			});
			const invitation = await auth.api.sendInvite({
				body: { email: "walkin@example.com", role: "member" },
				headers: adminHeaders,
			});
			await auth.api.signUpEmail({
				body: {
					email: "walkin@example.com",
					password: "direct-password-123",
					name: "Walk In",
				},
			});
			const row = db["invite"]!.find((i: any) => i.id === invitation.id);
			const user = db["user"]!.find(
				(u: any) => u.email === "walkin@example.com",
			);
			expect(row.status).toBe("pending");
			expect(user.role).toBeFalsy();
		});

		it("does not claim an expired invitation", async () => {
			const { auth, db, adminHeaders } = await createTestAuth();
			const invitation = await auth.api.sendInvite({
				body: { email: "walkin@example.com", role: "member" },
				headers: adminHeaders,
			});
			expireInvite(db, invitation.id);
			await auth.api.signUpEmail({
				body: {
					email: "walkin@example.com",
					password: "direct-password-123",
					name: "Walk In",
				},
			});
			const row = db["invite"]!.find((i: any) => i.id === invitation.id);
			expect(row.status).toBe("pending");
		});

		it("never fails the sign-up when onInvitationAccepted throws", async () => {
			const { auth, db, adminHeaders } = await createTestAuth({
				onInvitationAccepted: async () => {
					throw new Error("provisioning exploded");
				},
			});
			const invitation = await auth.api.sendInvite({
				body: { email: "walkin@example.com" },
				headers: adminHeaders,
			});
			const result = await auth.api.signUpEmail({
				body: {
					email: "walkin@example.com",
					password: "direct-password-123",
					name: "Walk In",
				},
			});
			expect(result.user.email).toBe("walkin@example.com");
			// the claim itself still went through; only the hook failed
			const row = db["invite"]!.find((i: any) => i.id === invitation.id);
			expect(row.status).toBe("accepted");
		});
	});

	describe("email delivery failures", () => {
		it("rolls the invitation back when sendInvitationEmail throws", async () => {
			const { auth, db, adminHeaders } = await createTestAuth({
				sendInvitationEmail: async () => {
					throw new Error("smtp is down");
				},
			});
			await expectAPIError(
				auth.api.sendInvite({
					body: { email: "invitee@example.com" },
					headers: adminHeaders,
				}),
				500,
				"FAILED_TO_SEND_INVITATION_EMAIL",
			);
			// no undeliverable invitation left behind
			expect(db["invite"]!).toHaveLength(0);
		});

		it("restores the invitation a failed re-invite superseded", async () => {
			let fail = false;
			const emails: SendInvitationEmailData[] = [];
			const { auth, db, adminHeaders } = await createTestAuth({
				sendInvitationEmail: async (data) => {
					if (fail) throw new Error("smtp is down");
					emails.push(data);
				},
			});
			const first = await auth.api.sendInvite({
				body: { email: "invitee@example.com" },
				headers: adminHeaders,
			});
			fail = true;
			await expectAPIError(
				auth.api.sendInvite({
					body: { email: "invitee@example.com" },
					headers: adminHeaders,
				}),
				500,
				"FAILED_TO_SEND_INVITATION_EMAIL",
			);
			// the original invitation is pending again and its emailed link
			// still works
			const row = db["invite"]!.find((i: any) => i.id === first.id);
			expect(row.status).toBe("pending");
			expect(db["invite"]!).toHaveLength(1);
			const invitation = await auth.api.getInvite({
				query: { token: emails[0]!.token },
			});
			expect(invitation.email).toBe("invitee@example.com");
		});

		it("restores the previous token when a resend cannot be delivered", async () => {
			let fail = false;
			const emails: SendInvitationEmailData[] = [];
			const { auth, adminHeaders } = await createTestAuth({
				sendInvitationEmail: async (data) => {
					if (fail) throw new Error("smtp is down");
					emails.push(data);
				},
			});
			const invitation = await auth.api.sendInvite({
				body: { email: "invitee@example.com" },
				headers: adminHeaders,
			});
			fail = true;
			await expectAPIError(
				auth.api.resendInvite({
					body: { invitationId: invitation.id },
					headers: adminHeaders,
				}),
				500,
				"FAILED_TO_SEND_INVITATION_EMAIL",
			);
			// the link the invitee already has keeps working
			const found = await auth.api.getInvite({
				query: { token: emails[0]!.token },
			});
			expect(found.email).toBe("invitee@example.com");
		});

		it("hands delivery to advanced.backgroundTasks.handler when one is configured", async () => {
			const dispatched: Promise<unknown>[] = [];
			const { auth, db, adminHeaders } = await createTestAuth(
				{
					sendInvitationEmail: async () => {
						throw new Error("smtp is down");
					},
				},
				{
					options: {
						advanced: {
							backgroundTasks: {
								handler: (promise: Promise<unknown>) => {
									dispatched.push(promise);
								},
							},
						},
					},
				},
			);
			// delivery is dispatched, so a failing provider no longer fails
			// the request or rolls the invitation back
			const invitation = await auth.api.sendInvite({
				body: { email: "invitee@example.com" },
				headers: adminHeaders,
			});
			expect(invitation.email).toBe("invitee@example.com");
			expect(dispatched).toHaveLength(1);
			const row = db["invite"]!.find((i: any) => i.id === invitation.id);
			expect(row.status).toBe("pending");
		});
	});

	describe("send-bulk", () => {
		it("reports per-invitation outcomes instead of failing the batch", async () => {
			const { auth, emails, db, adminHeaders } = await createTestAuth();
			// an address that is already a registered user must not sink the
			// rest of the batch
			await auth.api.signUpEmail({
				body: {
					email: "taken@example.com",
					password: "taken-password-123",
					name: "Taken",
				},
			});
			const result = await auth.api.sendBulkInvites({
				body: {
					invitations: [
						{ email: "one@example.com", role: "member" },
						{ email: "taken@example.com" },
						{ email: "two@example.com", name: "Two" },
					],
				},
				headers: adminHeaders,
			});
			expect(result.sent).toBe(2);
			expect(result.failed).toBe(1);
			expect(result.results[1]).toMatchObject({
				email: "taken@example.com",
				status: "failed",
				code: "USER_ALREADY_EXISTS",
			});
			expect(emails.map((e) => e.invitation.email)).toEqual([
				"one@example.com",
				"two@example.com",
			]);
			expect(db["invite"]!).toHaveLength(2);
			// and the tokens work
			const accepted = await auth.api.acceptInvite({
				body: { token: emails[0]!.token, password: "one-password-123" },
			});
			expect(accepted.user.email).toBe("one@example.com");
		});

		it("applies allowedRoles per item and caps the batch size", async () => {
			const { auth, adminHeaders } = await createTestAuth({
				allowedRoles: ["member"],
			});
			const result = await auth.api.sendBulkInvites({
				body: {
					invitations: [
						{ email: "ok@example.com", role: "member" },
						{ email: "nope@example.com", role: "admin" },
					],
				},
				headers: adminHeaders,
			});
			expect(result.results[1]).toMatchObject({
				status: "failed",
				code: "ROLE_NOT_ALLOWED",
			});
			// body-schema rejection, so it surfaces as a validation error
			await expect(
				auth.api.sendBulkInvites({
					body: {
						invitations: Array.from({ length: 101 }, (_, i) => ({
							email: `bulk${i}@example.com`,
						})),
					},
					headers: adminHeaders,
				}),
			).rejects.toMatchObject({ statusCode: 400 });
		});

		it("requires canInvite", async () => {
			const { auth } = await createTestAuth();
			await expectAPIError(
				auth.api.sendBulkInvites({
					body: { invitations: [{ email: "one@example.com" }] },
				}),
				401,
			);
		});
	});

	describe("reject", () => {
		it("lets the recipient decline: the token dies and the status sticks", async () => {
			const { auth, emails, adminHeaders } = await createTestAuth();
			const invitation = await auth.api.sendInvite({
				body: { email: "invitee@example.com" },
				headers: adminHeaders,
			});
			const rejected = await auth.api.rejectInvite({
				body: { token: emails[0]!.token },
			});
			expect(rejected.status).toBe("rejected");
			expect(rejected.id).toBe(invitation.id);

			await expectAPIError(
				auth.api.acceptInvite({
					body: { token: emails[0]!.token, password: "invitee-password-1" },
				}),
				400,
				"INVITATION_REJECTED",
			);
			await expectAPIError(
				auth.api.getInvite({ query: { token: emails[0]!.token } }),
				400,
				"INVITATION_REJECTED",
			);
			await expectAPIError(
				auth.api.resendInvite({
					body: { invitationId: invitation.id },
					headers: adminHeaders,
				}),
				400,
				"INVITATION_REJECTED",
			);
			const { invitations } = await auth.api.listInvites({
				query: { status: "rejected" },
				headers: adminHeaders,
			});
			expect(invitations).toHaveLength(1);
		});

		it("cannot reject an already accepted invitation", async () => {
			const { auth, emails, adminHeaders } = await createTestAuth();
			await auth.api.sendInvite({
				body: { email: "invitee@example.com" },
				headers: adminHeaders,
			});
			await auth.api.acceptInvite({
				body: { token: emails[0]!.token, password: "invitee-password-1" },
			});
			await expectAPIError(
				auth.api.rejectInvite({ body: { token: emails[0]!.token } }),
				400,
				"INVITATION_ALREADY_ACCEPTED",
			);
		});
	});

	describe("purge", () => {
		it("deletes finished invitations and leaves live ones alone", async () => {
			const { auth, db, emails, adminHeaders } = await createTestAuth();
			await auth.api.sendInvite({
				body: { email: "live@example.com" },
				headers: adminHeaders,
			});
			const expired = await auth.api.sendInvite({
				body: { email: "expired@example.com" },
				headers: adminHeaders,
			});
			expireInvite(db, expired.id);
			const canceled = await auth.api.sendInvite({
				body: { email: "canceled@example.com" },
				headers: adminHeaders,
			});
			await auth.api.cancelInvite({
				body: { invitationId: canceled.id },
				headers: adminHeaders,
			});
			await auth.api.sendInvite({
				body: { email: "accepted@example.com" },
				headers: adminHeaders,
			});
			await auth.api.acceptInvite({
				body: {
					token: emails.at(-1)!.token,
					password: "accepted-password-1",
				},
			});

			const { deleted } = await auth.api.purgeInvites({
				body: {},
				headers: adminHeaders,
			});
			expect(deleted).toBe(2); // expired + canceled
			const remaining = db["invite"]!.map((i: any) => i.email).toSorted();
			expect(remaining).toEqual(["accepted@example.com", "live@example.com"]);

			// accepted rows are only removed when explicitly asked for
			const second = await auth.api.purgeInvites({
				body: { statuses: ["accepted"] },
				headers: adminHeaders,
			});
			expect(second.deleted).toBe(1);
			expect(db["invite"]!.map((i: any) => i.email)).toEqual([
				"live@example.com",
			]);
			expect(
				await auth.api.getInvite({ query: { token: emails[0]!.token } }),
			).toMatchObject({ email: "live@example.com" });
		});

		it("honors olderThan and requires canInvite", async () => {
			const { auth, db, adminHeaders } = await createTestAuth();
			const canceled = await auth.api.sendInvite({
				body: { email: "canceled@example.com" },
				headers: adminHeaders,
			});
			await auth.api.cancelInvite({
				body: { invitationId: canceled.id },
				headers: adminHeaders,
			});
			// just-canceled rows stay visible while inside the window
			const untouched = await auth.api.purgeInvites({
				body: { olderThan: 3600 },
				headers: adminHeaders,
			});
			expect(untouched.deleted).toBe(0);
			expect(db["invite"]!).toHaveLength(1);

			await expectAPIError(auth.api.purgeInvites({ body: {} }), 401);
		});
	});

	describe("requireInvite", () => {
		it("blocks an uninvited sign-up and lets an invited one through", async () => {
			const { auth, emails, adminHeaders } = await createTestAuth({
				requireInvite: true,
			});
			await expectAPIError(
				auth.api.signUpEmail({
					body: {
						email: "stranger@example.com",
						password: "stranger-password-1",
						name: "Stranger",
					},
				}),
				403,
				"SIGN_UP_REQUIRES_INVITATION",
			);

			await auth.api.sendInvite({
				body: { email: "invitee@example.com" },
				headers: adminHeaders,
			});
			// signing up directly with an invitation pending is allowed, and
			// claimOnSignUp still claims it
			const signedUp = await auth.api.signUpEmail({
				body: {
					email: "invitee@example.com",
					password: "invitee-password-1",
					name: "Invitee",
				},
			});
			expect(signedUp.user.email).toBe("invitee@example.com");
			const { invitations } = await auth.api.listInvites({
				query: { status: "accepted" },
				headers: adminHeaders,
			});
			expect(invitations).toHaveLength(1);
			expect(emails).toHaveLength(1);
		});

		it("never blocks the plugin's own accept endpoint", async () => {
			// the invitation is already marked accepted by the time the user
			// row is created, so a naive check would lock out the happy path
			const { auth, emails, adminHeaders } = await createTestAuth({
				requireInvite: true,
			});
			await auth.api.sendInvite({
				body: { email: "invitee@example.com" },
				headers: adminHeaders,
			});
			const accepted = await auth.api.acceptInvite({
				body: { token: emails[0]!.token, password: "invitee-password-1" },
			});
			expect(accepted.user.email).toBe("invitee@example.com");
		});

		it("lets the first user bootstrap the app, then closes the door", async () => {
			const { auth } = await createTestAuth(
				{ requireInvite: true },
				{ withoutAdmin: true },
			);
			const first = await auth.api.signUpEmail({
				body: {
					email: "founder@example.com",
					password: "founder-password-1",
					name: "Founder",
				},
			});
			expect(first.user.email).toBe("founder@example.com");
			await expectAPIError(
				auth.api.signUpEmail({
					body: {
						email: "second@example.com",
						password: "second-password-1",
						name: "Second",
					},
				}),
				403,
				"SIGN_UP_REQUIRES_INVITATION",
			);
		});

		it("can refuse even the first user when allowFirstUser is false", async () => {
			const { auth } = await createTestAuth(
				{ requireInvite: { allowFirstUser: false } },
				{ withoutAdmin: true },
			);
			await expectAPIError(
				auth.api.signUpEmail({
					body: {
						email: "founder@example.com",
						password: "founder-password-1",
						name: "Founder",
					},
				}),
				403,
				"SIGN_UP_REQUIRES_INVITATION",
			);
		});

		it("waves through allowedEmailDomains and a custom allow()", async () => {
			const seen: string[] = [];
			const { auth } = await createTestAuth({
				requireInvite: {
					allowedEmailDomains: ["Acme.com"],
					allow: async ({ email }) => {
						seen.push(email);
						return email.startsWith("vip");
					},
				},
			});
			const staff = await auth.api.signUpEmail({
				body: {
					email: "someone@acme.com",
					password: "someone-password-1",
					name: "Staff",
				},
			});
			expect(staff.user.email).toBe("someone@acme.com");
			// domain match short-circuits before allow()
			expect(seen).toEqual([]);

			const vip = await auth.api.signUpEmail({
				body: {
					email: "vip@elsewhere.com",
					password: "vip-password-123",
					name: "VIP",
				},
			});
			expect(vip.user.email).toBe("vip@elsewhere.com");
			expect(seen).toEqual(["vip@elsewhere.com"]);

			await expectAPIError(
				auth.api.signUpEmail({
					body: {
						email: "nobody@elsewhere.com",
						password: "nobody-password-1",
						name: "Nobody",
					},
				}),
				403,
				"SIGN_UP_REQUIRES_INVITATION",
			);
		});

		it("is off by default", async () => {
			const { auth } = await createTestAuth();
			const signedUp = await auth.api.signUpEmail({
				body: {
					email: "stranger@example.com",
					password: "stranger-password-1",
					name: "Stranger",
				},
			});
			expect(signedUp.user.email).toBe("stranger@example.com");
		});
	});

	describe("claiming across sign-up flows", () => {
		it("claims through email OTP sign-in, which no route allowlist covered", async () => {
			const otps: string[] = [];
			const { auth, db, adminHeaders } = await createTestAuth(
				{},
				{
					plugins: [
						emailOTP({
							sendVerificationOTP: async ({ otp }) => {
								otps.push(otp);
							},
						}),
					],
				},
			);
			await auth.api.sendInvite({
				body: { email: "otp@example.com", role: "member" },
				headers: adminHeaders,
			});
			// the helper's plugins are passed dynamically, so the email-OTP
			// routes exist at runtime but not in `auth.api`'s inferred type
			const otpApi = auth.api as unknown as {
				sendVerificationOTP: (opts: {
					body: { email: string; type: string };
				}) => Promise<unknown>;
				signInEmailOTP: (opts: {
					body: { email: string; otp: string };
				}) => Promise<{ user: { email: string } }>;
			};
			await otpApi.sendVerificationOTP({
				body: { email: "otp@example.com", type: "sign-in" },
			});
			const signedIn = await otpApi.signInEmailOTP({
				body: { email: "otp@example.com", otp: otps.at(-1)! },
			});
			expect(signedIn.user.email).toBe("otp@example.com");

			const { invitations } = await auth.api.listInvites({
				query: { email: "otp@example.com" },
				headers: adminHeaders,
			});
			expect(invitations[0]!.status).toBe("accepted");
			const userRow = db["user"]!.find(
				(u: any) => u.email === "otp@example.com",
			);
			expect(userRow.role).toBe("member");
		});

		it("does not re-run the claim for a returning user", async () => {
			const { auth, emails, db, adminHeaders } = await createTestAuth();
			await auth.api.sendInvite({
				body: { email: "invitee@example.com", role: "member" },
				headers: adminHeaders,
			});
			await auth.api.acceptInvite({
				body: { token: emails[0]!.token, password: "invitee-password-1" },
			});
			const before = JSON.stringify(db["invite"]!);
			await auth.api.signInEmail({
				body: {
					email: "invitee@example.com",
					password: "invitee-password-1",
				},
			});
			expect(JSON.stringify(db["invite"]!)).toBe(before);
		});
	});

	describe("lifecycle hooks", () => {
		it("fires onInvitationSent on send and resend, and onInvitationCanceled on cancel and reject", async () => {
			const sent: { email: string; resent: boolean }[] = [];
			const closed: { email: string; rejected: boolean }[] = [];
			const { auth, emails, adminHeaders } = await createTestAuth({
				onInvitationSent: async ({ invitation, inviter, resent }) => {
					expect(inviter.email).toBe(ADMIN_EMAIL);
					sent.push({ email: invitation.email, resent });
				},
				onInvitationCanceled: async ({ invitation, rejected }) => {
					closed.push({ email: invitation.email, rejected });
				},
			});
			const invitation = await auth.api.sendInvite({
				body: { email: "invitee@example.com" },
				headers: adminHeaders,
			});
			await auth.api.resendInvite({
				body: { invitationId: invitation.id },
				headers: adminHeaders,
			});
			await auth.api.cancelInvite({
				body: { invitationId: invitation.id },
				headers: adminHeaders,
			});
			expect(sent).toEqual([
				{ email: "invitee@example.com", resent: false },
				{ email: "invitee@example.com", resent: true },
			]);
			expect(closed).toEqual([
				{ email: "invitee@example.com", rejected: false },
			]);

			await auth.api.sendInvite({
				body: { email: "second@example.com" },
				headers: adminHeaders,
			});
			await auth.api.rejectInvite({ body: { token: emails.at(-1)!.token } });
			expect(closed.at(-1)).toEqual({
				email: "second@example.com",
				rejected: true,
			});
		});

		it("keeps notification hooks best-effort", async () => {
			const { auth, adminHeaders } = await createTestAuth({
				onInvitationSent: async () => {
					throw new Error("notification exploded");
				},
			});
			const invitation = await auth.api.sendInvite({
				body: { email: "invitee@example.com" },
				headers: adminHeaders,
			});
			expect(invitation.email).toBe("invitee@example.com");
		});

		it("rolls the acceptance back when onInvitationAccepted throws", async () => {
			const { auth, db, emails, adminHeaders } = await createTestAuth({
				onInvitationAccepted: async () => {
					throw new Error("provisioning exploded");
				},
			});
			const invitation = await auth.api.sendInvite({
				body: { email: "invitee@example.com" },
				headers: adminHeaders,
			});
			await expect(
				auth.api.acceptInvite({
					body: { token: emails[0]!.token, password: "invitee-password-1" },
				}),
			).rejects.toThrow();
			// no half-provisioned user, and the link still works
			expect(
				db["user"]!.some((u: any) => u.email === "invitee@example.com"),
			).toBe(false);
			const row = db["invite"]!.find((i: any) => i.id === invitation.id);
			expect(row.status).toBe("pending");
			const retried = await auth.api.getInvite({
				query: { token: emails[0]!.token },
			});
			expect(retried.email).toBe("invitee@example.com");
		});
	});

	describe("invitation surface", () => {
		it("returns the inviter's display identity, but not their email", async () => {
			const { auth, emails, adminHeaders } = await createTestAuth();
			await auth.api.sendInvite({
				body: { email: "invitee@example.com" },
				headers: adminHeaders,
			});
			const invitation = await auth.api.getInvite({
				query: { token: emails[0]!.token },
			});
			expect(invitation.inviter).toEqual({ name: "Admin", image: null });
			expect(JSON.stringify(invitation)).not.toContain(ADMIN_EMAIL);
		});

		it("builds the invite URL per invitation when given a function", async () => {
			const { auth, emails, adminHeaders } = await createTestAuth({
				inviteRedirectURL: ({ invitation, inviter }) => {
					expect(inviter.email).toBe(ADMIN_EMAIL);
					const tenant = (invitation.metadata?.tenant as string) ?? "app";
					return `https://${tenant}.example.com/accept`;
				},
			});
			await auth.api.sendInvite({
				body: {
					email: "invitee@example.com",
					metadata: { tenant: "acme" },
				},
				headers: adminHeaders,
			});
			expect(emails[0]!.url).toBe(
				`https://acme.example.com/accept?token=${emails[0]!.token}`,
			);
		});

		it("rejects metadata over the size cap", async () => {
			const { auth, adminHeaders } = await createTestAuth({
				maxMetadataSize: 64,
			});
			await expectAPIError(
				auth.api.sendInvite({
					body: {
						email: "invitee@example.com",
						metadata: { note: "x".repeat(200) },
					},
					headers: adminHeaders,
				}),
				400,
				"METADATA_TOO_LARGE",
			);
			const ok = await auth.api.sendInvite({
				body: { email: "invitee@example.com", metadata: { note: "ok" } },
				headers: adminHeaders,
			});
			expect(ok.metadata).toEqual({ note: "ok" });
		});

		it("takes password bounds from emailAndPassword, like sign-up", async () => {
			const { auth, emails, adminHeaders } = await createTestAuth(
				{},
				{
					options: {
						emailAndPassword: { enabled: true, minPasswordLength: 6 },
					},
				},
			);
			await auth.api.sendInvite({
				body: { email: "invitee@example.com" },
				headers: adminHeaders,
			});
			// a 6-char password is valid for this app, so accept must take it
			const accepted = await auth.api.acceptInvite({
				body: { token: emails[0]!.token, password: "sixxxx" },
			});
			expect(accepted.user.email).toBe("invitee@example.com");

			await auth.api.sendInvite({
				body: { email: "second@example.com" },
				headers: adminHeaders,
			});
			await expectAPIError(
				auth.api.acceptInvite({
					body: { token: emails.at(-1)!.token, password: "five5" },
				}),
				400,
				"PASSWORD_TOO_SHORT",
			);
		});
	});
});
