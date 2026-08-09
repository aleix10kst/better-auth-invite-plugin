import type {
	BetterAuthPlugin,
	GenericEndpointContext,
	InferOptionSchema,
	User,
	Where,
} from "better-auth";
import { APIError, BetterAuthError, defineErrorCodes } from "better-auth";
import { createAuthEndpoint, createAuthMiddleware, getSessionFromCtx } from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import { generateRandomString } from "better-auth/crypto";
import { mergeSchema, parseUserInput, parseUserOutput } from "better-auth/db";
import { z } from "zod";

/**
 * Error codes exposed on the plugin's `$ERROR_CODES`.
 */
export const INVITE_ERROR_CODES = defineErrorCodes({
	USER_ALREADY_EXISTS: "A user with this email address has already been registered",
	INVITATION_NOT_FOUND: "Invitation not found",
	INVITATION_EXPIRED: "Invitation has expired",
	INVITATION_ALREADY_ACCEPTED: "Invitation has already been accepted",
	INVITATION_CANCELED: "Invitation has been canceled",
	INVITATION_ALREADY_SENT: "An invitation has already been sent to this email",
	NOT_AUTHORIZED_TO_INVITE: "You are not authorized to manage invitations",
	FAILED_TO_CREATE_USER: "Failed to create user",
	PASSWORD_TOO_SHORT: "Password is too short",
	PASSWORD_TOO_LONG: "Password is too long",
	PASSWORD_REQUIRED: "Password is required to accept this invitation",
	ROLE_NOT_ALLOWED: "This role cannot be assigned through an invitation",
});

/**
 * Naming convention: the database model and the routes use the short noun
 * (`invite`, `/invite/*`) — the `invitation` model name is already taken by
 * the organization plugin — while domain nouns (types, error codes, body
 * fields such as `invitationId`) use `invitation`, matching the organization
 * plugin's vocabulary.
 */
export type InvitationStatus = "pending" | "accepted" | "canceled";

/**
 * Status as reported by `listInvites`: pending invitations past their expiry
 * are reported with the virtual status `"expired"`.
 */
export type InvitationListStatus = InvitationStatus | "expired";

/**
 * An invitation row. `tokenHash` is stored in the database but is never
 * returned by any endpoint.
 */
export interface Invitation {
	id: string;
	email: string;
	name?: string | null;
	role?: string | null;
	/** Arbitrary JSON metadata attached when the invitation was sent. */
	metadata?: Record<string, unknown> | null;
	status: InvitationStatus;
	expiresAt: Date;
	inviterId: string;
	acceptedUserId?: string | null;
	createdAt: Date;
	updatedAt: Date;
}

/**
 * The shape of items returned by `listInvites` (its `status` may be the
 * virtual `"expired"`).
 */
export type ListedInvitation = Omit<Invitation, "status"> & {
	status: InvitationListStatus;
};

type InvitationRow = Omit<Invitation, "metadata"> & {
	tokenHash: string;
	/** Stored as a JSON string in the database. */
	metadata?: string | null;
};

export interface SendInvitationEmailData {
	/** The invitation record (without the token hash). */
	invitation: Invitation;
	/** The raw single-use invite token. Only ever exposed here. */
	token: string;
	/**
	 * Ready-to-use invite URL: `${inviteRedirectURL}?token=...`. Point
	 * `inviteRedirectURL` at a page in your app; that page should read the
	 * `token` query parameter and POST it to the `acceptInvite` endpoint
	 * (the accept endpoint itself is POST-only and cannot be opened in a
	 * browser).
	 */
	url: string;
	/** The user who sent the invitation. */
	inviter: User;
}

const schema = {
	invite: {
		fields: {
			email: {
				type: "string",
				required: true,
				sortable: true,
				index: true,
			},
			name: {
				type: "string",
				required: false,
			},
			role: {
				type: "string",
				required: false,
			},
			metadata: {
				type: "string",
				required: false,
			},
			status: {
				type: "string",
				required: true,
				sortable: true,
				defaultValue: "pending",
			},
			tokenHash: {
				type: "string",
				required: true,
				unique: true,
				input: false,
				returned: false,
			},
			expiresAt: {
				type: "date",
				required: true,
			},
			inviterId: {
				type: "string",
				required: true,
				references: {
					model: "user",
					field: "id",
					onDelete: "cascade",
				},
			},
			acceptedUserId: {
				type: "string",
				required: false,
			},
			createdAt: {
				type: "date",
				required: true,
				input: false,
				defaultValue: () => new Date(),
			},
			updatedAt: {
				type: "date",
				required: true,
				input: false,
				defaultValue: () => new Date(),
				onUpdate: () => new Date(),
			},
		},
	},
} satisfies BetterAuthPlugin["schema"];

export interface InviteOptions {
	/**
	 * Called to deliver the invitation email. REQUIRED.
	 *
	 * `data.token` is the raw single-use token and `data.url` a ready-to-use
	 * link. This is the only place the raw token is ever exposed.
	 */
	sendInvitationEmail: (
		data: SendInvitationEmailData,
		request?: Request,
	) => Promise<void>;
	/**
	 * The app page the emailed invite link points at. REQUIRED.
	 *
	 * The token is appended as a `token` query parameter; your page should
	 * read it and call the `acceptInvite` endpoint (a POST — the API endpoint
	 * cannot be opened directly in a browser).
	 */
	inviteRedirectURL: string;
	/**
	 * How long an invitation stays valid, in seconds. Must be a positive
	 * integer of at most one year (31536000).
	 * @default 86400 (24 hours)
	 */
	expiresIn?: number;
	/**
	 * Decides whether a user may send/cancel/list/resend invitations.
	 *
	 * NOTE: anyone who passes `canInvite` can also choose the invited user's
	 * `role`. If you loosen this beyond admins, set `allowedRoles` so invite
	 * managers cannot mint accounts with elevated roles.
	 * @default user.role contains "admin" (comma-separated roles supported)
	 */
	canInvite?: (
		user: User & { role?: string | null },
		ctx: GenericEndpointContext,
	) => boolean | Promise<boolean>;
	/**
	 * Roles that may be assigned via an invitation's `role` field. When set,
	 * `sendInvite` rejects any other role with `ROLE_NOT_ALLOWED`. When
	 * unset, any role string is accepted (safe only while `canInvite` is
	 * restricted to fully trusted principals).
	 */
	allowedRoles?: string[];
	/**
	 * Create a session and set the session cookie when an invitation is
	 * accepted.
	 * @default true
	 */
	autoSignIn?: boolean;
	/**
	 * When re-inviting an email that already has a pending invitation, cancel
	 * the old invitation (invalidating its token) and issue a fresh one. When
	 * `false`, re-inviting throws `INVITATION_ALREADY_SENT`.
	 * @default true
	 */
	allowReInvite?: boolean;
	/**
	 * Whether accepting an invitation requires choosing a password (which
	 * creates a credential account). Requires `emailAndPassword` to be
	 * enabled. Set to `false` to create the user without a credential
	 * account, so they complete sign-in through any other enabled method
	 * (social provider, magic link, passkey, ...).
	 * @default true
	 */
	requirePassword?: boolean;
	/**
	 * Automatically claim a pending invitation when the invited email signs
	 * up through another flow — an OAuth/social callback, email sign-up,
	 * magic link, email OTP... Without this, a user who ignores the invite
	 * link and signs up directly would leave the invitation `pending`
	 * forever (its `role`, `metadata`, and `onInvitationAccepted` never
	 * applied), and later clicking the invite link would fail with
	 * `USER_ALREADY_EXISTS`.
	 *
	 * Claiming marks the invitation accepted, applies its `role` to the
	 * user (subject to the same user-schema check as `acceptInvite`), and
	 * fires `onInvitationAccepted`. Unlike `acceptInvite`, claim errors are
	 * logged but never fail the sign-in that triggered them.
	 * @default true
	 */
	claimOnSignUp?: boolean;
	/**
	 * Called after an invitation has been accepted: the user is created and
	 * the invitation is marked accepted (and, when `autoSignIn` is enabled,
	 * just before the session is created). Use it to provision whatever the
	 * invitation was for (organization membership, seat, default project...).
	 *
	 * Errors thrown here propagate to the caller but do NOT roll back the
	 * accepted invitation or the created user. When invoked from the
	 * `claimOnSignUp` hook, errors are logged instead of propagated.
	 */
	onInvitationAccepted?: (
		data: { invitation: Invitation; user: User },
		ctx: GenericEndpointContext,
	) => void | Promise<void>;
	/**
	 * Customize the invite table name / field names.
	 */
	schema?: InferOptionSchema<typeof schema>;
}

const DEFAULT_EXPIRES_IN = 60 * 60 * 24; // 24 hours
const MAX_EXPIRES_IN = 60 * 60 * 24 * 365; // 1 year

/**
 * Paths after which a session may have been created for a user who signed
 * up/in outside the invite flow, used by the `claimOnSignUp` hook: social
 * OAuth callbacks, generic OAuth callbacks, email/social sign-up and
 * sign-in (id-token flows create the user directly), magic link, email
 * OTP, and phone number verification.
 */
const CLAIM_PATH_PREFIXES = [
	"/callback",
	"/oauth2/callback",
	"/sign-up",
	"/sign-in/social",
	"/sign-in/oauth2",
	"/magic-link/verify",
	"/email-otp/verify-email",
	"/phone-number/verify",
];

async function hashToken(token: string): Promise<string> {
	const digest = await crypto.subtle.digest(
		"SHA-256",
		new TextEncoder().encode(token),
	);
	return Array.from(new Uint8Array(digest))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

function parseMetadata(
	metadata: string | null | undefined,
): Record<string, unknown> | null {
	if (!metadata) return null;
	try {
		return JSON.parse(metadata) as Record<string, unknown>;
	} catch {
		return null;
	}
}

function sanitizeInvitation(invitation: InvitationRow): Invitation {
	const { tokenHash: _tokenHash, metadata, ...rest } = invitation;
	return { ...rest, metadata: parseMetadata(metadata) };
}

function isExpired(invitation: Pick<Invitation, "expiresAt">): boolean {
	return new Date(invitation.expiresAt) < new Date();
}

const defaultCanInvite = (user: User & { role?: string | null }) => {
	return (user.role ?? "")
		.split(",")
		.map((role) => role.trim())
		.includes("admin");
};

export const invite = (options: InviteOptions) => {
	const opts = {
		expiresIn: DEFAULT_EXPIRES_IN,
		autoSignIn: true,
		allowReInvite: true,
		requirePassword: true,
		claimOnSignUp: true,
		canInvite: defaultCanInvite,
		...options,
	};

	if (!opts.inviteRedirectURL) {
		throw new BetterAuthError(
			"[better-auth-invite] `inviteRedirectURL` is required: the emailed invite link must point at a page in your app (the `/invite/accept` API endpoint is POST-only and cannot be opened in a browser).",
		);
	}
	if (
		!Number.isInteger(opts.expiresIn) ||
		opts.expiresIn <= 0 ||
		opts.expiresIn > MAX_EXPIRES_IN
	) {
		throw new BetterAuthError(
			`[better-auth-invite] \`expiresIn\` must be a positive integer number of seconds of at most ${MAX_EXPIRES_IN} (1 year).`,
		);
	}

	/**
	 * Requires an authenticated session AND `canInvite` approval.
	 */
	const inviteManagerMiddleware = createAuthMiddleware(async (ctx) => {
		const session = await getSessionFromCtx(ctx);
		if (!session?.session) {
			throw APIError.from("UNAUTHORIZED", {
				code: "UNAUTHORIZED",
				message: "Unauthorized",
			});
		}
		const allowed = await opts.canInvite(
			session.user as User & { role?: string | null },
			ctx,
		);
		if (!allowed) {
			throw APIError.from(
				"FORBIDDEN",
				INVITE_ERROR_CODES.NOT_AUTHORIZED_TO_INVITE,
			);
		}
		return { session };
	});

	function buildInviteURL(token: string) {
		const separator = opts.inviteRedirectURL.includes("?") ? "&" : "?";
		return `${opts.inviteRedirectURL}${separator}token=${encodeURIComponent(token)}`;
	}

	async function issueAndSend(
		ctx: GenericEndpointContext,
		invitation: InvitationRow,
		token: string,
		inviter: User,
	) {
		await opts.sendInvitationEmail(
			{
				invitation: sanitizeInvitation(invitation),
				token,
				url: buildInviteURL(token),
				inviter,
			},
			ctx.request,
		);
	}

	/**
	 * Claim the freshest pending, unexpired invitation matching `user.email`
	 * after the user signed up/in through a non-invite flow: mark it
	 * accepted, apply its `role`, and fire `onInvitationAccepted`. No-op
	 * when there is nothing to claim or a concurrent request claimed first.
	 */
	async function claimPendingInvitation(
		ctx: GenericEndpointContext,
		user: User,
	) {
		const pending = await ctx.context.adapter.findMany<InvitationRow>({
			model: "invite",
			where: [
				{ field: "email", value: user.email.toLowerCase() },
				{ field: "status", value: "pending" },
			],
			sortBy: { field: "createdAt", direction: "desc" },
		});
		const invitation = pending.find((row) => !isExpired(row));
		if (!invitation) return;

		// same atomic claim as acceptInvite: lose gracefully to a concurrent
		// accept, and to a resend that rotated the token after our read
		const claimed = await ctx.context.adapter.incrementOne<InvitationRow>({
			model: "invite",
			where: [
				{ field: "id", value: invitation.id },
				{ field: "status", value: "pending" },
				{ field: "tokenHash", value: invitation.tokenHash },
			],
			increment: {},
			set: {
				status: "accepted",
				acceptedUserId: user.id,
				updatedAt: new Date(),
			},
		});
		if (!claimed) return;

		let acceptedUser = user;
		const hasRoleField = !!ctx.context.tables?.user?.fields?.role;
		if (invitation.role && hasRoleField) {
			const updated = await ctx.context.adapter.update<User>({
				model: "user",
				where: [{ field: "id", value: user.id }],
				update: { role: invitation.role, updatedAt: new Date() },
			});
			if (updated) acceptedUser = updated;
		}

		if (opts.onInvitationAccepted) {
			await opts.onInvitationAccepted(
				{
					invitation: {
						...sanitizeInvitation(invitation),
						status: "accepted",
						acceptedUserId: user.id,
					},
					user: acceptedUser,
				},
				ctx,
			);
		}
	}

	/**
	 * Look up an invitation by raw token and assert it is pending and not
	 * expired. Throws the appropriate APIError otherwise.
	 */
	async function getValidInvitationByToken(
		ctx: GenericEndpointContext,
		token: string,
	): Promise<InvitationRow> {
		const tokenHash = await hashToken(token);
		const invitation = await ctx.context.adapter.findOne<InvitationRow>({
			model: "invite",
			where: [{ field: "tokenHash", value: tokenHash }],
		});
		if (!invitation) {
			throw APIError.from(
				"NOT_FOUND",
				INVITE_ERROR_CODES.INVITATION_NOT_FOUND,
			);
		}
		if (invitation.status === "accepted") {
			throw APIError.from(
				"BAD_REQUEST",
				INVITE_ERROR_CODES.INVITATION_ALREADY_ACCEPTED,
			);
		}
		if (invitation.status === "canceled") {
			throw APIError.from(
				"BAD_REQUEST",
				INVITE_ERROR_CODES.INVITATION_CANCELED,
			);
		}
		if (isExpired(invitation)) {
			throw APIError.from("GONE", INVITE_ERROR_CODES.INVITATION_EXPIRED);
		}
		return invitation;
	}

	return {
		id: "invite",
		init: (context) => {
			if (
				opts.requirePassword &&
				!context.options.emailAndPassword?.enabled
			) {
				throw new BetterAuthError(
					"[better-auth-invite] accepting an invitation sets a password (credential account), which requires `emailAndPassword` to be enabled. Enable `emailAndPassword` or set `requirePassword: false` on the invite plugin.",
				);
			}
		},
		endpoints: {
			/**
			 * ### Endpoint
			 *
			 * POST `/invite/send`
			 *
			 * Invite a user by email. Requires an authenticated session that
			 * passes `canInvite`. Inviting an email that already belongs to a
			 * user fails; a pending invite is (by default) canceled and
			 * re-issued.
			 */
			sendInvite: createAuthEndpoint(
				"/invite/send",
				{
					method: "POST",
					body: z.object({
						email: z.string().email(),
						name: z.string().min(1).max(255).optional(),
						role: z.string().min(1).max(255).optional(),
						metadata: z.record(z.string(), z.any()).optional(),
						expiresIn: z
							.number()
							.int()
							.positive()
							.max(MAX_EXPIRES_IN)
							.optional(),
					}),
					use: [inviteManagerMiddleware],
					metadata: {
						openapi: {
							description: "Invite a user by email",
							responses: {
								"200": {
									description: "The created invitation",
								},
							},
						},
					},
				},
				async (ctx) => {
					const email = ctx.body.email.toLowerCase();
					const inviter = ctx.context.session!.user;

					if (
						ctx.body.role &&
						opts.allowedRoles &&
						!opts.allowedRoles.includes(ctx.body.role)
					) {
						throw APIError.from(
							"BAD_REQUEST",
							INVITE_ERROR_CODES.ROLE_NOT_ALLOWED,
						);
					}

					const existingUser =
						await ctx.context.internalAdapter.findUserByEmail(email);
					if (existingUser) {
						throw APIError.from(
							"BAD_REQUEST",
							INVITE_ERROR_CODES.USER_ALREADY_EXISTS,
						);
					}

					const pendingInvites =
						await ctx.context.adapter.findMany<InvitationRow>({
							model: "invite",
							where: [
								{ field: "email", value: email },
								{ field: "status", value: "pending" },
							],
						});
					const livePending = pendingInvites.filter(
						(invitation) => !isExpired(invitation),
					);
					if (livePending.length > 0) {
						if (!opts.allowReInvite) {
							throw APIError.from(
								"BAD_REQUEST",
								INVITE_ERROR_CODES.INVITATION_ALREADY_SENT,
							);
						}
					}
					// cancel every previous pending invite (expired ones too)
					// so only the freshly issued token is usable
					if (pendingInvites.length > 0) {
						await ctx.context.adapter.updateMany({
							model: "invite",
							where: [
								{ field: "email", value: email },
								{ field: "status", value: "pending" },
							],
							update: { status: "canceled", updatedAt: new Date() },
						});
					}

					const token = generateRandomString(32, "a-z", "A-Z", "0-9");
					const tokenHash = await hashToken(token);
					const expiresIn = ctx.body.expiresIn ?? opts.expiresIn;
					const invitation =
						await ctx.context.adapter.create<Omit<InvitationRow, "id">, InvitationRow>({
							model: "invite",
							data: {
								email,
								name: ctx.body.name ?? null,
								role: ctx.body.role ?? null,
								metadata: ctx.body.metadata
									? JSON.stringify(ctx.body.metadata)
									: null,
								status: "pending",
								tokenHash,
								expiresAt: new Date(Date.now() + expiresIn * 1000),
								inviterId: inviter.id,
								acceptedUserId: null,
								createdAt: new Date(),
								updatedAt: new Date(),
							},
						});

					await issueAndSend(ctx, invitation, token, inviter);

					return ctx.json(sanitizeInvitation(invitation));
				},
			),
			/**
			 * ### Endpoint
			 *
			 * GET `/invite/get?token=...`
			 *
			 * Public. Look up an invitation by its raw token, e.g. from the
			 * accept page, to display who is being invited before asking for
			 * a password.
			 */
			getInvite: createAuthEndpoint(
				"/invite/get",
				{
					method: "GET",
					query: z.object({
						token: z.string().min(1),
					}),
					metadata: {
						openapi: {
							description: "Get an invitation by token",
							responses: {
								"200": {
									description: "The invitation details",
								},
							},
						},
					},
				},
				async (ctx) => {
					const invitation = await getValidInvitationByToken(
						ctx,
						ctx.query.token,
					);
					return ctx.json({
						email: invitation.email,
						name: invitation.name ?? null,
						role: invitation.role ?? null,
						metadata: parseMetadata(invitation.metadata),
						status: invitation.status,
						expiresAt: invitation.expiresAt,
					});
				},
			),
			/**
			 * ### Endpoint
			 *
			 * POST `/invite/accept`
			 *
			 * Public. Accept an invitation: creates the user (email verified),
			 * sets their password (unless `requirePassword: false`), and (by
			 * default) signs them in. Additional `user.additionalFields` may
			 * be passed in the body, like sign-up.
			 */
			acceptInvite: createAuthEndpoint(
				"/invite/accept",
				{
					method: "POST",
					body: z
						.object({
							token: z.string().min(1),
							password: z.string().min(8).max(512).optional(),
							name: z.string().min(1).max(255).optional(),
						})
						.and(z.record(z.string(), z.any())),
					metadata: {
						openapi: {
							description:
								"Accept an invitation and create the invited user",
							responses: {
								"200": {
									description:
										"The created user and session token",
								},
							},
						},
					},
				},
				async (ctx) => {
					const invitation = await getValidInvitationByToken(
						ctx,
						ctx.body.token,
					);

					const {
						token: _token,
						password,
						name: _name,
						...rest
					} = ctx.body;
					if (!password) {
						if (opts.requirePassword) {
							throw APIError.from(
								"BAD_REQUEST",
								INVITE_ERROR_CODES.PASSWORD_REQUIRED,
							);
						}
					} else {
						const passwordConfig = ctx.context.password.config;
						if (password.length < passwordConfig.minPasswordLength) {
							throw APIError.from(
								"BAD_REQUEST",
								INVITE_ERROR_CODES.PASSWORD_TOO_SHORT,
							);
						}
						if (password.length > passwordConfig.maxPasswordLength) {
							throw APIError.from(
								"BAD_REQUEST",
								INVITE_ERROR_CODES.PASSWORD_TOO_LONG,
							);
						}
					}

					// Validate `user.additionalFields` passed in the body, the
					// same way sign-up does (required fields, input flags,
					// validators). Runs before the claim so validation errors
					// don't churn the invitation status.
					const additionalFields = parseUserInput(
						ctx.context.options,
						rest,
						"create",
					);

					const existingUser =
						await ctx.context.internalAdapter.findUserByEmail(
							invitation.email,
						);
					if (existingUser) {
						throw APIError.from(
							"BAD_REQUEST",
							INVITE_ERROR_CODES.USER_ALREADY_EXISTS,
						);
					}

					// Atomically claim the invitation (pending -> accepted) so a
					// concurrent accept with the same token loses the race. The
					// claim is also conditioned on the token hash so a token
					// rotated by a concurrent resend cannot be accepted.
					const claimed =
						await ctx.context.adapter.incrementOne<InvitationRow>({
							model: "invite",
							where: [
								{ field: "id", value: invitation.id },
								{ field: "status", value: "pending" },
								{ field: "tokenHash", value: invitation.tokenHash },
							],
							increment: {},
							set: { status: "accepted", updatedAt: new Date() },
						});
					if (!claimed) {
						const current =
							await ctx.context.adapter.findOne<InvitationRow>({
								model: "invite",
								where: [{ field: "id", value: invitation.id }],
							});
						if (!current || current.tokenHash !== invitation.tokenHash) {
							// the token was rotated by a concurrent resend —
							// this token no longer identifies the invitation
							throw APIError.from(
								"NOT_FOUND",
								INVITE_ERROR_CODES.INVITATION_NOT_FOUND,
							);
						}
						if (current.status === "canceled") {
							throw APIError.from(
								"BAD_REQUEST",
								INVITE_ERROR_CODES.INVITATION_CANCELED,
							);
						}
						throw APIError.from(
							"BAD_REQUEST",
							INVITE_ERROR_CODES.INVITATION_ALREADY_ACCEPTED,
						);
					}

					let user: User | undefined;
					try {
						// Re-check inside the claim: an independent sign-up may
						// have created this email between the check above and
						// the claim. On adapters without an enforced unique
						// email index this is the last line of defense against
						// a duplicate user.
						const racedUser =
							await ctx.context.internalAdapter.findUserByEmail(
								invitation.email,
							);
						if (racedUser) {
							throw APIError.from(
								"BAD_REQUEST",
								INVITE_ERROR_CODES.USER_ALREADY_EXISTS,
							);
						}
						const hasRoleField =
							!!ctx.context.tables?.user?.fields?.role;
						user = await ctx.context.internalAdapter.createUser({
							email: invitation.email,
							name: ctx.body.name || invitation.name || "",
							emailVerified: true,
							...additionalFields,
							...(invitation.role && hasRoleField
								? { role: invitation.role }
								: {}),
						});
						if (password) {
							const hash = await ctx.context.password.hash(password);
							await ctx.context.internalAdapter.linkAccount({
								userId: user.id,
								providerId: "credential",
								accountId: user.id,
								password: hash,
							});
						}
					} catch (error) {
						// roll back the partially created user first — an
						// orphaned verified user without a credential account
						// would make every retry fail with USER_ALREADY_EXISTS
						// and permanently brick the invitation
						if (user) {
							try {
								await ctx.context.internalAdapter.deleteUser(
									user.id,
								);
							} catch {
								// best effort: if the delete fails the invite
								// stays pending, matching the previous state
							}
						}
						// release the claim so the invite can be retried
						await ctx.context.adapter.update({
							model: "invite",
							where: [{ field: "id", value: invitation.id }],
							update: { status: "pending", updatedAt: new Date() },
						});
						if (error instanceof APIError) {
							throw error;
						}
						throw APIError.from(
							"INTERNAL_SERVER_ERROR",
							INVITE_ERROR_CODES.FAILED_TO_CREATE_USER,
						);
					}
					const createdUser = user;

					await ctx.context.adapter.update({
						model: "invite",
						where: [{ field: "id", value: invitation.id }],
						update: {
							acceptedUserId: createdUser.id,
							updatedAt: new Date(),
						},
					});

					if (opts.onInvitationAccepted) {
						await opts.onInvitationAccepted(
							{
								invitation: {
									...sanitizeInvitation(invitation),
									status: "accepted",
									acceptedUserId: createdUser.id,
								},
								user: createdUser,
							},
							ctx,
						);
					}

					if (!opts.autoSignIn) {
						return ctx.json({
							token: null,
							user: parseUserOutput(ctx.context.options, createdUser),
						});
					}

					const session =
						await ctx.context.internalAdapter.createSession(
							createdUser.id,
						);
					await setSessionCookie(ctx, { session, user: createdUser });
					return ctx.json({
						token: session.token,
						user: parseUserOutput(ctx.context.options, createdUser),
					});
				},
			),
			/**
			 * ### Endpoint
			 *
			 * POST `/invite/cancel`
			 *
			 * Cancel a pending invitation, invalidating its token. Requires an
			 * authenticated session that passes `canInvite`.
			 */
			cancelInvite: createAuthEndpoint(
				"/invite/cancel",
				{
					method: "POST",
					body: z.object({
						invitationId: z.string().min(1),
					}),
					use: [inviteManagerMiddleware],
					metadata: {
						openapi: {
							description: "Cancel a pending invitation",
							responses: {
								"200": {
									description: "The canceled invitation",
								},
							},
						},
					},
				},
				async (ctx) => {
					const invitation =
						await ctx.context.adapter.findOne<InvitationRow>({
							model: "invite",
							where: [
								{ field: "id", value: ctx.body.invitationId },
							],
						});
					if (!invitation) {
						throw APIError.from(
							"NOT_FOUND",
							INVITE_ERROR_CODES.INVITATION_NOT_FOUND,
						);
					}
					if (invitation.status === "accepted") {
						throw APIError.from(
							"BAD_REQUEST",
							INVITE_ERROR_CODES.INVITATION_ALREADY_ACCEPTED,
						);
					}
					if (invitation.status === "canceled") {
						throw APIError.from(
							"BAD_REQUEST",
							INVITE_ERROR_CODES.INVITATION_CANCELED,
						);
					}
					const canceled =
						await ctx.context.adapter.incrementOne<InvitationRow>({
							model: "invite",
							where: [
								{ field: "id", value: invitation.id },
								{ field: "status", value: "pending" },
							],
							increment: {},
							set: { status: "canceled", updatedAt: new Date() },
						});
					if (!canceled) {
						throw APIError.from(
							"BAD_REQUEST",
							INVITE_ERROR_CODES.INVITATION_ALREADY_ACCEPTED,
						);
					}
					return ctx.json(sanitizeInvitation(canceled));
				},
			),
			/**
			 * ### Endpoint
			 *
			 * GET `/invite/list`
			 *
			 * List invitations. Requires an authenticated session that passes
			 * `canInvite`. Pending invitations past their expiry are reported
			 * with the virtual status `"expired"`; the `pending`/`expired`
			 * status filters are applied in the database query, so
			 * `limit`/`offset` paginate the filtered set. Returns the `total`
			 * count for the active filter alongside the page.
			 */
			listInvites: createAuthEndpoint(
				"/invite/list",
				{
					method: "GET",
					query: z
						.object({
							status: z
								.enum(["pending", "accepted", "canceled", "expired"])
								.optional(),
							email: z.string().optional(),
							limit: z.coerce.number().int().positive().max(1000).optional(),
							offset: z.coerce.number().int().min(0).optional(),
						})
						.optional(),
					use: [inviteManagerMiddleware],
					metadata: {
						openapi: {
							description: "List invitations",
							responses: {
								"200": {
									description: "The list of invitations",
								},
							},
						},
					},
				},
				async (ctx) => {
					const status = ctx.query?.status;
					const email = ctx.query?.email?.toLowerCase();
					const now = new Date();
					const where: Where[] = [];
					if (email) {
						where.push({ field: "email", value: email });
					}
					if (status === "expired") {
						where.push({ field: "status", value: "pending" });
						where.push({
							field: "expiresAt",
							value: now,
							operator: "lt",
						});
					} else if (status === "pending") {
						where.push({ field: "status", value: "pending" });
						where.push({
							field: "expiresAt",
							value: now,
							operator: "gte",
						});
					} else if (status) {
						where.push({ field: "status", value: status });
					}
					const [invitations, total] = await Promise.all([
						ctx.context.adapter.findMany<InvitationRow>({
							model: "invite",
							where: where.length > 0 ? where : undefined,
							sortBy: { field: "createdAt", direction: "desc" },
							limit: ctx.query?.limit,
							offset: ctx.query?.offset,
						}),
						ctx.context.adapter.count({
							model: "invite",
							where: where.length > 0 ? where : undefined,
						}),
					]);
					const withVirtualStatus: ListedInvitation[] =
						invitations.map((invitation) => {
							const sanitized = sanitizeInvitation(invitation);
							const effectiveStatus: InvitationListStatus =
								invitation.status === "pending" &&
								new Date(invitation.expiresAt) < now
									? "expired"
									: invitation.status;
							return { ...sanitized, status: effectiveStatus };
						});
					return ctx.json({
						invitations: withVirtualStatus,
						total,
					});
				},
			),
			/**
			 * ### Endpoint
			 *
			 * POST `/invite/resend`
			 *
			 * Re-send a pending invitation (including expired ones) with a
			 * fresh token and expiry. The previous token stops working.
			 * Requires an authenticated session that passes `canInvite`.
			 */
			resendInvite: createAuthEndpoint(
				"/invite/resend",
				{
					method: "POST",
					body: z.object({
						invitationId: z.string().min(1),
						expiresIn: z
							.number()
							.int()
							.positive()
							.max(MAX_EXPIRES_IN)
							.optional(),
					}),
					use: [inviteManagerMiddleware],
					metadata: {
						openapi: {
							description:
								"Re-send a pending invitation with a fresh token",
							responses: {
								"200": {
									description: "The refreshed invitation",
								},
							},
						},
					},
				},
				async (ctx) => {
					const invitation =
						await ctx.context.adapter.findOne<InvitationRow>({
							model: "invite",
							where: [
								{ field: "id", value: ctx.body.invitationId },
							],
						});
					if (!invitation) {
						throw APIError.from(
							"NOT_FOUND",
							INVITE_ERROR_CODES.INVITATION_NOT_FOUND,
						);
					}
					if (invitation.status === "accepted") {
						throw APIError.from(
							"BAD_REQUEST",
							INVITE_ERROR_CODES.INVITATION_ALREADY_ACCEPTED,
						);
					}
					if (invitation.status === "canceled") {
						throw APIError.from(
							"BAD_REQUEST",
							INVITE_ERROR_CODES.INVITATION_CANCELED,
						);
					}

					const token = generateRandomString(32, "a-z", "A-Z", "0-9");
					const tokenHash = await hashToken(token);
					const expiresIn = ctx.body.expiresIn ?? opts.expiresIn;
					const updated =
						await ctx.context.adapter.update<InvitationRow>({
							model: "invite",
							where: [{ field: "id", value: invitation.id }],
							update: {
								tokenHash,
								expiresAt: new Date(Date.now() + expiresIn * 1000),
								updatedAt: new Date(),
							},
						});
					const refreshed = updated ?? {
						...invitation,
						tokenHash,
						expiresAt: new Date(Date.now() + expiresIn * 1000),
					};

					await issueAndSend(
						ctx,
						refreshed,
						token,
						ctx.context.session!.user,
					);

					return ctx.json(sanitizeInvitation(refreshed));
				},
			),
		},
		hooks: {
			after: opts.claimOnSignUp
				? [
						{
							matcher: (context) =>
								CLAIM_PATH_PREFIXES.some((prefix) =>
									context.path?.startsWith(prefix),
								),
							handler: createAuthMiddleware(async (ctx) => {
								const context = ctx.context as typeof ctx.context & {
									newSession?: { user: User } | null;
									returned?: unknown;
								};
								// user freshly signed in (OAuth callback, magic
								// link, ...) or was returned by sign-up without a
								// session (e.g. requireEmailVerification)
								const user =
									context.newSession?.user ??
									(context.returned as { user?: User } | undefined)
										?.user;
								if (!user?.id || !user.email) return;
								try {
									await claimPendingInvitation(ctx, user);
								} catch (error) {
									// never fail the sign-in that triggered the claim
									ctx.context.logger.error(
										"[better-auth-invite] failed to claim pending invitation after sign-up",
										error,
									);
								}
							}),
						},
					]
				: [],
		},
		schema: mergeSchema(schema, options?.schema),
		rateLimit: [
			{
				pathMatcher(path: string) {
					return path === "/invite/accept" || path === "/invite/get";
				},
				window: 60,
				max: 10,
			},
			{
				pathMatcher(path: string) {
					return path === "/invite/send" || path === "/invite/resend";
				},
				window: 60,
				max: 20,
			},
		],
		options: opts,
		$ERROR_CODES: INVITE_ERROR_CODES,
	} satisfies BetterAuthPlugin;
};

export type InvitePlugin = ReturnType<typeof invite>;
