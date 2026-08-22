import type {
	BetterAuthPlugin,
	GenericEndpointContext,
	InferOptionSchema,
	User,
	Where,
} from "better-auth";
import {
	getCurrentAdapter,
	runWithTransaction,
} from "@better-auth/core/context";
import { createLocalAccountIssuer } from "@better-auth/core/db";
import { BetterAuthError } from "@better-auth/core/error";
import { defineErrorCodes } from "@better-auth/core/utils/error-codes";
import { APIError } from "better-auth";
import {
	createAuthEndpoint,
	createAuthMiddleware,
	getSessionFromCtx,
} from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import { generateRandomString } from "better-auth/crypto";
import { mergeSchema, parseUserInput, parseUserOutput } from "better-auth/db";
import { z } from "zod";

/**
 * Error codes exposed on the plugin's `$ERROR_CODES`.
 */
export const INVITE_ERROR_CODES = defineErrorCodes({
	USER_ALREADY_EXISTS:
		"A user with this email address has already been registered",
	INVITATION_NOT_FOUND: "Invitation not found",
	INVITATION_EXPIRED: "Invitation has expired",
	INVITATION_ALREADY_ACCEPTED: "Invitation has already been accepted",
	INVITATION_CANCELED: "Invitation has been canceled",
	INVITATION_REJECTED: "Invitation has been rejected",
	INVITATION_ALREADY_SENT: "An invitation has already been sent to this email",
	NOT_AUTHORIZED_TO_INVITE: "You are not authorized to manage invitations",
	FAILED_TO_CREATE_USER: "Failed to create user",
	FAILED_TO_SEND_INVITATION_EMAIL: "Failed to send the invitation email",
	PASSWORD_TOO_SHORT: "Password is too short",
	PASSWORD_TOO_LONG: "Password is too long",
	PASSWORD_REQUIRED: "Password is required to accept this invitation",
	ROLE_NOT_ALLOWED: "This role cannot be assigned through an invitation",
	METADATA_TOO_LARGE: "Invitation metadata is too large",
	SIGN_UP_REQUIRES_INVITATION: "Sign up is invite-only",
});

/**
 * Naming convention: the database model and the routes use the short noun
 * (`invite`, `/invite/*`) — the `invitation` model name is already taken by
 * the organization plugin — while domain nouns (types, error codes, body
 * fields such as `invitationId`) use `invitation`, matching the organization
 * plugin's vocabulary.
 */
export type InvitationStatus = "pending" | "accepted" | "canceled" | "rejected";

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

/**
 * One entry of a `/invite/send-bulk` response: a batch never fails as a
 * whole, so each address reports its own outcome.
 */
export type BulkInviteResult =
	| { email: string; status: "sent"; invitation: Invitation }
	| {
			email: string;
			status: "failed";
			/** Human-readable reason. */
			error: string;
			/** The `$ERROR_CODES` key, when the failure maps to one. */
			code?: string | undefined;
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
				// an unfiltered `listInvites` sorts on this column alone
				index: true,
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
		indexes: [
			// `listInvites` filters on status and orders by createdAt; the
			// leading column also serves a status filter on its own
			{ fields: ["status", "createdAt"] },
			// the pending/expired split in `listInvites`, and the expired
			// sweep in `purgeInvites`, are a status/expiry pair
			{ fields: ["status", "expiresAt"] },
		],
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
	 *
	 * Pass a function to build the URL per invitation — multi-tenant apps can
	 * route each invite at the tenant that issued it, e.g. from the
	 * invitation's `metadata`. The URL is always computed server-side (there
	 * is deliberately no caller-supplied redirect, which would be an open
	 * redirect).
	 */
	inviteRedirectURL:
		| string
		| ((
				data: { invitation: Invitation; inviter: User },
				ctx: GenericEndpointContext,
		  ) => string | Promise<string>);
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
	 * Restrict sign-up to invited emails. When enabled, any user creation for
	 * an email without a live pending invitation is rejected with
	 * `SIGN_UP_REQUIRES_INVITATION` — across every flow (email sign-up, OAuth
	 * callbacks, magic link, email OTP, ...), because the check runs as a
	 * `user.create` database hook rather than per-route.
	 *
	 * Always exempt: this plugin's own `/invite/accept` (its invitation is
	 * already claimed by the time the user row is created) and the admin
	 * plugin's `/admin/create-user` (an authorized admin creating a user
	 * directly).
	 *
	 * With Better Auth's organization plugin mounted, a pending organization
	 * invitation counts as an invitation too — see
	 * `allowOrganizationInvitations`.
	 * @default false
	 */
	requireInvite?:
		| boolean
		| {
				/**
				 * Let the very first user of an empty `user` table sign up
				 * without an invitation, so an app can be bootstrapped.
				 * @default true
				 */
				allowFirstUser?: boolean;
				/** Email domains that may always sign up, e.g. `["acme.com"]`. */
				allowedEmailDomains?: string[];
				/**
				 * Let the recipient of a pending, unexpired invitation from
				 * Better Auth's organization plugin sign up, so they can then
				 * accept it (`organization.acceptInvitation` needs a session
				 * whose email matches the invitation). Detected automatically:
				 * on whenever the organization plugin is mounted, i.e. its
				 * `invitation` table is part of the schema. Set `false` to
				 * ignore organization invitations, or `true` to fail at
				 * startup if the organization plugin is missing.
				 * @default true when the organization plugin is mounted
				 */
				allowOrganizationInvitations?: boolean;
				/**
				 * Last word on an uninvited sign-up: return `true` to allow it
				 * through. Runs after the invitation, first-user and domain
				 * checks have all declined.
				 */
				allow?: (
					data: { user: User; email: string },
					ctx: GenericEndpointContext | null,
				) => boolean | Promise<boolean>;
		  };
	/**
	 * Maximum size, in characters of the serialized JSON, of an invitation's
	 * `metadata`. Larger payloads are rejected with `METADATA_TOO_LARGE`.
	 * @default 4096
	 */
	maxMetadataSize?: number;
	/**
	 * Called after an invitation has been accepted: the user is created and
	 * the invitation is marked accepted (and, when `autoSignIn` is enabled,
	 * just before the session is created). Use it to provision whatever the
	 * invitation was for (organization membership, seat, default project...).
	 *
	 * Runs inside the acceptance transaction: on an adapter with transaction
	 * support, throwing here rolls back the created user AND the acceptance,
	 * so provisioning either fully happens or the invite stays usable. Keep
	 * the work database-local — an external API call would hold the
	 * transaction open across the network; queue that instead. When invoked
	 * from the `claimOnSignUp` hook, errors are logged instead of propagated.
	 */
	onInvitationAccepted?: (
		data: { invitation: Invitation; user: User },
		ctx: GenericEndpointContext,
	) => void | Promise<void>;
	/**
	 * Called after an invitation email has been handed to
	 * `sendInvitationEmail` — on the initial send and on every resend
	 * (`resent: true`). Best-effort: errors are logged, never surfaced to the
	 * caller.
	 */
	onInvitationSent?: (
		data: { invitation: Invitation; inviter: User; resent: boolean },
		ctx: GenericEndpointContext,
	) => void | Promise<void>;
	/**
	 * Called after an invitation is canceled by an invite manager, rejected by
	 * its recipient (`rejected: true`), or superseded by a re-invite.
	 * Best-effort: errors are logged, never surfaced to the caller.
	 */
	onInvitationCanceled?: (
		data: { invitation: Invitation; rejected: boolean },
		ctx: GenericEndpointContext,
	) => void | Promise<void>;
	/**
	 * Customize the invite table name / field names.
	 */
	schema?: InferOptionSchema<typeof schema>;
}

const DEFAULT_EXPIRES_IN = 60 * 60 * 24; // 24 hours
const MAX_EXPIRES_IN = 60 * 60 * 24 * 365; // 1 year
const DEFAULT_MAX_METADATA_SIZE = 4096;
/** Upper bound on one `/invite/send-bulk` batch. */
const MAX_BULK_INVITATIONS = 100;
/** Endpoints whose user creation is never subject to `requireInvite`. */
const REQUIRE_INVITE_EXEMPT_PATHS = ["/invite/accept", "/admin/create-user"];

/**
 * Whether Better Auth's organization plugin is mounted, judged by its
 * `invitation` table being part of the schema with the columns the
 * `requireInvite` check reads. The plugin is never imported: composing with
 * it must not make it a dependency.
 */
function hasOrganizationInvitationTable(
	tables: Record<string, { fields?: Record<string, unknown> }> | undefined,
) {
	const fields = tables?.["invitation"]?.fields;
	return (
		!!fields?.["organizationId"] &&
		!!fields?.["status"] &&
		!!fields?.["expiresAt"]
	);
}

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
		requireInvite: false as NonNullable<InviteOptions["requireInvite"]>,
		maxMetadataSize: DEFAULT_MAX_METADATA_SIZE,
		canInvite: defaultCanInvite,
		...options,
	};
	const requireInvite =
		opts.requireInvite === true ? {} : opts.requireInvite || null;

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
	if (!Number.isInteger(opts.maxMetadataSize) || opts.maxMetadataSize <= 0) {
		throw new BetterAuthError(
			"[better-auth-invite] `maxMetadataSize` must be a positive integer number of characters.",
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

	async function buildInviteURL(
		ctx: GenericEndpointContext,
		invitation: Invitation,
		token: string,
		inviter: User,
	) {
		const base =
			typeof opts.inviteRedirectURL === "string"
				? opts.inviteRedirectURL
				: await opts.inviteRedirectURL({ invitation, inviter }, ctx);
		const separator = base.includes("?") ? "&" : "?";
		return `${base}${separator}token=${encodeURIComponent(token)}`;
	}

	/**
	 * Run a best-effort notification hook: it must never turn a completed
	 * operation into a failed request.
	 */
	async function notify(
		ctx: GenericEndpointContext,
		name: "onInvitationSent" | "onInvitationCanceled",
		run: () => void | Promise<void>,
	) {
		try {
			await run();
		} catch (error) {
			ctx.context.logger.error(
				`[better-auth-invite] ${name} threw; the invitation operation itself succeeded`,
				error,
			);
		}
	}

	/**
	 * Hand the invitation email to `sendInvitationEmail`.
	 *
	 * When the app configured `advanced.backgroundTasks.handler` (Vercel /
	 * Cloudflare `waitUntil`, a queue, ...), delivery is dispatched through it
	 * and the response is not held open — matching how Better Auth core sends
	 * its own verification emails. Without a handler the send is awaited and a
	 * failure is propagated, so the caller can roll the invitation back rather
	 * than leaving a live-but-undelivered token behind.
	 */
	async function issueAndSend(
		ctx: GenericEndpointContext,
		invitation: InvitationRow,
		token: string,
		inviter: User,
		resent: boolean,
	) {
		const sanitized = sanitizeInvitation(invitation);
		const data: SendInvitationEmailData = {
			invitation: sanitized,
			token,
			url: await buildInviteURL(ctx, sanitized, token, inviter),
			inviter,
		};
		if (ctx.context.options.advanced?.backgroundTasks?.handler) {
			await ctx.context.runInBackgroundOrAwait(
				opts.sendInvitationEmail(data, ctx.request),
			);
		} else {
			await opts.sendInvitationEmail(data, ctx.request);
		}
		if (opts.onInvitationSent) {
			await notify(ctx, "onInvitationSent", () =>
				opts.onInvitationSent?.(
					{ invitation: sanitized, inviter, resent },
					ctx,
				),
			);
		}
	}

	function serializeMetadata(metadata: Record<string, unknown> | undefined) {
		if (!metadata) return null;
		const serialized = JSON.stringify(metadata);
		if (serialized.length > opts.maxMetadataSize) {
			throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.METADATA_TOO_LARGE);
		}
		return serialized;
	}

	/**
	 * Create one invitation row: validates the role, refuses emails that
	 * already belong to a user, and revokes every previous pending invitation
	 * for the address so only the freshly issued token is usable.
	 *
	 * Returns the row, its raw token, and a `rollback` that undoes both — used
	 * when the email cannot be delivered, so a failed send never revokes a
	 * working invitation nor leaves an undeliverable one behind.
	 */
	async function createInvitation(
		ctx: GenericEndpointContext,
		input: {
			email: string;
			name?: string | undefined;
			role?: string | undefined;
			metadata?: Record<string, unknown> | undefined;
			expiresIn?: number | undefined;
		},
	) {
		const email = input.email.toLowerCase();

		if (
			input.role &&
			opts.allowedRoles &&
			!opts.allowedRoles.includes(input.role)
		) {
			throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.ROLE_NOT_ALLOWED);
		}
		const metadata = serializeMetadata(input.metadata);

		const existingUser =
			await ctx.context.internalAdapter.findUserByEmail(email);
		if (existingUser) {
			throw APIError.from(
				"BAD_REQUEST",
				INVITE_ERROR_CODES.USER_ALREADY_EXISTS,
			);
		}

		const pendingInvites = await ctx.context.adapter.findMany<InvitationRow>({
			model: "invite",
			where: [
				{ field: "email", value: email },
				{ field: "status", value: "pending" },
			],
		});
		const livePending = pendingInvites.filter(
			(invitation) => !isExpired(invitation),
		);
		if (livePending.length > 0 && !opts.allowReInvite) {
			throw APIError.from(
				"BAD_REQUEST",
				INVITE_ERROR_CODES.INVITATION_ALREADY_SENT,
			);
		}
		// cancel every previous pending invite (expired ones too) so only the
		// freshly issued token is usable
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
		const expiresIn = input.expiresIn ?? opts.expiresIn;
		const invitation = await ctx.context.adapter.create<
			Omit<InvitationRow, "id">,
			InvitationRow
		>({
			model: "invite",
			data: {
				email,
				name: input.name ?? null,
				role: input.role ?? null,
				metadata,
				status: "pending",
				tokenHash,
				expiresAt: new Date(Date.now() + expiresIn * 1000),
				inviterId: ctx.context.session!.user.id,
				acceptedUserId: null,
				createdAt: new Date(),
				updatedAt: new Date(),
			},
		});

		const rollback = async () => {
			try {
				await ctx.context.adapter.delete({
					model: "invite",
					where: [{ field: "id", value: invitation.id }],
				});
				// put the invitations this send superseded back the way they
				// were, so a failed delivery costs the recipient nothing
				const supersededIds = pendingInvites.map((row) => row.id);
				if (supersededIds.length > 0) {
					await ctx.context.adapter.updateMany({
						model: "invite",
						where: [
							{ field: "id", operator: "in", value: supersededIds },
							{ field: "status", value: "canceled" },
						],
						update: { status: "pending", updatedAt: new Date() },
					});
				}
			} catch (error) {
				ctx.context.logger.error(
					"[better-auth-invite] failed to roll back an invitation after an email delivery failure",
					error,
				);
			}
		};

		return { invitation, token, rollback };
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
			throw APIError.from("NOT_FOUND", INVITE_ERROR_CODES.INVITATION_NOT_FOUND);
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
		if (invitation.status === "rejected") {
			throw APIError.from(
				"BAD_REQUEST",
				INVITE_ERROR_CODES.INVITATION_REJECTED,
			);
		}
		if (isExpired(invitation)) {
			throw APIError.from("GONE", INVITE_ERROR_CODES.INVITATION_EXPIRED);
		}
		return invitation;
	}

	/**
	 * The inviter's display identity, for the accept page ("Alice invited you
	 * to Acme"). Deliberately name/image only: whoever holds the token should
	 * not learn the inviter's email address from it.
	 */
	async function findInviterProfile(
		ctx: GenericEndpointContext,
		inviterId: string,
	) {
		const inviter = await ctx.context.adapter.findOne<{
			name?: string | null;
			image?: string | null;
		}>({
			model: "user",
			where: [{ field: "id", value: inviterId }],
			select: ["name", "image"],
		});
		if (!inviter) return null;
		return { name: inviter.name ?? null, image: inviter.image ?? null };
	}

	return {
		id: "invite",
		init: (context) => {
			if (opts.requirePassword && !context.options.emailAndPassword?.enabled) {
				throw new BetterAuthError(
					"[better-auth-invite] accepting an invitation sets a password (credential account), which requires `emailAndPassword` to be enabled. Enable `emailAndPassword` or set `requirePassword: false` on the invite plugin.",
				);
			}
			const organizationPluginMounted = hasOrganizationInvitationTable(
				context.tables,
			);
			if (
				requireInvite?.allowOrganizationInvitations === true &&
				!organizationPluginMounted
			) {
				throw new BetterAuthError(
					"[better-auth-invite] `requireInvite.allowOrganizationInvitations` is `true`, but the organization plugin is not mounted (no `invitation` table with an `organizationId` column). Mount `organization()` from `better-auth/plugins`, or drop the option.",
				);
			}
			const allowOrganizationInvitations =
				organizationPluginMounted &&
				requireInvite?.allowOrganizationInvitations !== false;

			if (!requireInvite && !opts.claimOnSignUp) return;

			/**
			 * Database hooks receive `null` for programmatic user creation
			 * that did not come through an endpoint. Everything the invite
			 * hooks need lives on the auth context, so stand in with that.
			 */
			const asEndpointContext = (ctx: GenericEndpointContext | null) =>
				ctx ?? ({ context } as unknown as GenericEndpointContext);

			return {
				options: {
					databaseHooks: {
						user: {
							create: {
								...(requireInvite
									? {
											before: async (
												user: User & Record<string, unknown>,
												endpointCtx: GenericEndpointContext | null,
											) => {
												if (
													endpointCtx?.path &&
													REQUIRE_INVITE_EXEMPT_PATHS.includes(endpointCtx.path)
												) {
													return;
												}
												const email = user.email?.toLowerCase();
												if (!email) return;
												const ctx = asEndpointContext(endpointCtx);
												const pending =
													await ctx.context.adapter.findMany<InvitationRow>({
														model: "invite",
														where: [
															{ field: "email", value: email },
															{ field: "status", value: "pending" },
														],
													});
												if (pending.some((row) => !isExpired(row))) {
													return;
												}
												if (allowOrganizationInvitations) {
													// the organization plugin's `invitation`
													// table: whoever was invited to an
													// organization must be able to sign up
													// in order to accept it
													const organizationPending =
														await ctx.context.adapter.findMany<{
															expiresAt: Date | string;
														}>({
															model: "invitation",
															where: [
																{ field: "email", value: email },
																{ field: "status", value: "pending" },
															],
														});
													const now = Date.now();
													if (
														organizationPending.some(
															(row) => new Date(row.expiresAt).getTime() > now,
														)
													) {
														return;
													}
												}
												const domain = email.split("@")[1];
												if (
													domain &&
													requireInvite.allowedEmailDomains?.some(
														(allowed) => allowed.toLowerCase() === domain,
													)
												) {
													return;
												}
												if (requireInvite.allowFirstUser !== false) {
													const users = await ctx.context.adapter.count({
														model: "user",
													});
													if (users === 0) return;
												}
												if (
													requireInvite.allow &&
													(await requireInvite.allow(
														{ user, email },
														endpointCtx,
													))
												) {
													return;
												}
												throw APIError.from(
													"FORBIDDEN",
													INVITE_ERROR_CODES.SIGN_UP_REQUIRES_INVITATION,
												);
											},
										}
									: {}),
								...(opts.claimOnSignUp
									? {
											after: async (
												user: User & Record<string, unknown>,
												endpointCtx: GenericEndpointContext | null,
											) => {
												// `/invite/accept` claimed its own
												// invitation before creating this user
												if (endpointCtx?.path === "/invite/accept") {
													return;
												}
												if (!user?.id || !user.email) return;
												try {
													await claimPendingInvitation(
														asEndpointContext(endpointCtx),
														user,
													);
												} catch (error) {
													// never fail the sign-up that
													// triggered the claim
													context.logger.error(
														"[better-auth-invite] failed to claim pending invitation after user creation",
														error,
													);
												}
											},
										}
									: {}),
							},
						},
					},
				},
			};
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
					const inviter = ctx.context.session!.user;
					const { invitation, token, rollback } = await createInvitation(
						ctx,
						ctx.body,
					);
					try {
						await issueAndSend(ctx, invitation, token, inviter, false);
					} catch (error) {
						await rollback();
						ctx.context.logger.error(
							"[better-auth-invite] sendInvitationEmail failed; the invitation was rolled back",
							error,
						);
						throw APIError.from(
							"INTERNAL_SERVER_ERROR",
							INVITE_ERROR_CODES.FAILED_TO_SEND_INVITATION_EMAIL,
						);
					}

					return ctx.json(sanitizeInvitation(invitation));
				},
			),
			/**
			 * ### Endpoint
			 *
			 * POST `/invite/send-bulk`
			 *
			 * Invite up to 100 emails in one call. Requires an authenticated
			 * session that passes `canInvite`. Per-invitation failures are
			 * reported in the response instead of failing the batch, so one
			 * already-registered address does not sink the other 99.
			 */
			sendBulkInvites: createAuthEndpoint(
				"/invite/send-bulk",
				{
					method: "POST",
					body: z.object({
						invitations: z
							.array(
								z.object({
									email: z.string().email(),
									name: z.string().min(1).max(255).optional(),
									role: z.string().min(1).max(255).optional(),
									metadata: z.record(z.string(), z.any()).optional(),
								}),
							)
							.min(1)
							.max(MAX_BULK_INVITATIONS),
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
							description: "Invite many users by email in one call",
							responses: {
								"200": {
									description: "Per-invitation results, in request order",
								},
							},
						},
					},
				},
				async (ctx) => {
					const inviter = ctx.context.session!.user;
					const results: BulkInviteResult[] = [];
					// deliberately sequential: each invitation revokes the
					// previous pending one for its address, and a batch that
					// repeats an address must not race itself
					for (const input of ctx.body.invitations) {
						const email = input.email.toLowerCase();
						try {
							const { invitation, token, rollback } = await createInvitation(
								ctx,
								{
									...input,
									expiresIn: ctx.body.expiresIn,
								},
							);
							try {
								await issueAndSend(ctx, invitation, token, inviter, false);
							} catch (error) {
								await rollback();
								ctx.context.logger.error(
									"[better-auth-invite] sendInvitationEmail failed during a bulk send; that invitation was rolled back",
									error,
								);
								results.push({
									email,
									status: "failed",
									error:
										INVITE_ERROR_CODES.FAILED_TO_SEND_INVITATION_EMAIL.message,
									code: INVITE_ERROR_CODES.FAILED_TO_SEND_INVITATION_EMAIL.code,
								});
								continue;
							}
							results.push({
								email,
								status: "sent",
								invitation: sanitizeInvitation(invitation),
							});
						} catch (error) {
							if (!(error instanceof APIError)) throw error;
							results.push({
								email,
								status: "failed",
								error:
									(error.body?.message as string | undefined) ?? error.message,
								code: error.body?.code as string | undefined,
							});
						}
					}
					return ctx.json({
						results,
						sent: results.filter((r) => r.status === "sent").length,
						failed: results.filter((r) => r.status === "failed").length,
					});
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
						inviter: await findInviterProfile(ctx, invitation.inviterId),
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
							// bounds come from `emailAndPassword`'s own
							// min/maxPasswordLength, checked below, so this
							// endpoint accepts exactly what sign-up accepts
							password: z.string().min(1).optional(),
							name: z.string().min(1).max(255).optional(),
						})
						.and(z.record(z.string(), z.any())),
					metadata: {
						openapi: {
							description: "Accept an invitation and create the invited user",
							responses: {
								"200": {
									description: "The created user and session token",
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
						// the role is the invitation's to grant, never the
						// accepting user's to pick — drop it even when the app
						// declares `role` as an input-able additional field
						role: _role,
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
						await ctx.context.internalAdapter.findUserByEmail(invitation.email);
					if (existingUser) {
						throw APIError.from(
							"BAD_REQUEST",
							INVITE_ERROR_CODES.USER_ALREADY_EXISTS,
						);
					}

					// Everything that constitutes accepting — the claim, the
					// user, their credential account, the acceptedUserId
					// backfill and `onInvitationAccepted` — runs as one
					// transaction, so provisioning that fails leaves the
					// invitation usable rather than half-applied.
					// `runWithTransaction` publishes the transaction adapter on
					// async-local storage, which is how the `internalAdapter`
					// calls below join it. Adapters without transaction support
					// run this sequentially; the compensating rollback in the
					// catch is what covers them.
					const createdUser = await runWithTransaction(
						ctx.context.adapter,
						async () => {
							// Inside the transaction the scoped adapter lives on
							// async-local storage; `ctx.context.adapter` is still
							// the OUTER one. Using it here would run these writes
							// outside the transaction we just opened — and on a
							// single-connection driver (kysely's SQLite dialect,
							// D1, ...) it deadlocks against the connection the
							// transaction holds. This is how better-auth's own
							// internals reach the right adapter.
							const adapter = await getCurrentAdapter(ctx.context.adapter);

							// Atomically claim the invitation (pending ->
							// accepted) so a concurrent accept with the same
							// token loses the race. The claim is also
							// conditioned on the token hash so a token rotated
							// by a concurrent resend cannot be accepted.
							const claimed = await adapter.incrementOne<InvitationRow>({
								model: "invite",
								where: [
									{ field: "id", value: invitation.id },
									{ field: "status", value: "pending" },
									{
										field: "tokenHash",
										value: invitation.tokenHash,
									},
								],
								increment: {},
								set: { status: "accepted", updatedAt: new Date() },
							});
							if (!claimed) {
								const current = await adapter.findOne<InvitationRow>({
									model: "invite",
									where: [{ field: "id", value: invitation.id }],
								});
								if (!current || current.tokenHash !== invitation.tokenHash) {
									// the token was rotated by a concurrent
									// resend — it no longer identifies the
									// invitation
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
								if (current.status === "rejected") {
									throw APIError.from(
										"BAD_REQUEST",
										INVITE_ERROR_CODES.INVITATION_REJECTED,
									);
								}
								throw APIError.from(
									"BAD_REQUEST",
									INVITE_ERROR_CODES.INVITATION_ALREADY_ACCEPTED,
								);
							}

							let user: User | undefined;
							try {
								// Re-check inside the claim: an independent
								// sign-up may have created this email between
								// the check above and the claim. On adapters
								// without an enforced unique email index this is
								// the last line of defense against a duplicate
								// user.
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
								const hasRoleField = !!ctx.context.tables?.user?.fields?.role;
								user = await ctx.context.internalAdapter.createUser(
									{
										email: invitation.email,
										name: ctx.body.name || invitation.name || "",
										emailVerified: true,
										...additionalFields,
										...(invitation.role && hasRoleField
											? { role: invitation.role }
											: {}),
									},
									// the provisioning source Better Auth passes to
									// `user.validateUserInfo`. Reported as its own
									// method rather than borrowing
									// "email-password", both because acceptance
									// need not set a password at all
									// (`requirePassword: false`) and so a
									// validateUserInfo gate can single out
									// invite-provisioned users.
									{ method: "invite" },
								);
								if (password) {
									const hash = await ctx.context.password.hash(password);
									await ctx.context.internalAdapter.linkAccount({
										userId: user.id,
										providerId: "credential",
										issuer: createLocalAccountIssuer("credential"),
										accountId: user.id,
										password: hash,
									});
								}
								await adapter.update({
									model: "invite",
									where: [{ field: "id", value: invitation.id }],
									update: {
										acceptedUserId: user.id,
										updatedAt: new Date(),
									},
								});
								if (opts.onInvitationAccepted) {
									await opts.onInvitationAccepted(
										{
											invitation: {
												...sanitizeInvitation(invitation),
												status: "accepted",
												acceptedUserId: user.id,
											},
											user,
										},
										ctx,
									);
								}
							} catch (error) {
								// Compensation for adapters that ran the above
								// sequentially rather than transactionally: an
								// orphaned verified user without a credential
								// account would make every retry fail with
								// USER_ALREADY_EXISTS and permanently brick the
								// invitation. Inside a real transaction these
								// writes are rolled back along with everything
								// else — and on a driver that aborts the
								// transaction at the first error they fail
								// outright — so each one is best-effort and must
								// never replace the error that got us here.
								if (user) {
									try {
										await ctx.context.internalAdapter.deleteUser(user.id);
									} catch {
										// best effort; see above
									}
								}
								try {
									await adapter.update({
										model: "invite",
										where: [{ field: "id", value: invitation.id }],
										update: {
											status: "pending",
											// the user this pointed at was just
											// deleted; leaving the id behind
											// would surface a dangling
											// acceptedUserId through listInvites
											acceptedUserId: null,
											updatedAt: new Date(),
										},
									});
								} catch {
									// best effort; see above
								}
								if (error instanceof APIError) {
									throw error;
								}
								throw APIError.from(
									"INTERNAL_SERVER_ERROR",
									INVITE_ERROR_CODES.FAILED_TO_CREATE_USER,
								);
							}
							return user;
						},
					);

					if (!opts.autoSignIn) {
						return ctx.json({
							token: null,
							user: parseUserOutput(ctx.context.options, createdUser),
						});
					}

					const session = await ctx.context.internalAdapter.createSession(
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
					const invitation = await ctx.context.adapter.findOne<InvitationRow>({
						model: "invite",
						where: [{ field: "id", value: ctx.body.invitationId }],
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
					if (invitation.status === "rejected") {
						throw APIError.from(
							"BAD_REQUEST",
							INVITE_ERROR_CODES.INVITATION_REJECTED,
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
					const sanitized = sanitizeInvitation(canceled);
					if (opts.onInvitationCanceled) {
						await notify(ctx, "onInvitationCanceled", () =>
							opts.onInvitationCanceled?.(
								{ invitation: sanitized, rejected: false },
								ctx,
							),
						);
					}
					return ctx.json(sanitized);
				},
			),
			/**
			 * ### Endpoint
			 *
			 * POST `/invite/reject`
			 *
			 * Public. Decline an invitation using its raw token: the
			 * invitation is marked `rejected` and its token stops working.
			 * Named for the organization plugin's `rejectInvitation`.
			 */
			rejectInvite: createAuthEndpoint(
				"/invite/reject",
				{
					method: "POST",
					body: z.object({
						token: z.string().min(1),
					}),
					metadata: {
						openapi: {
							description: "Reject an invitation by token",
							responses: {
								"200": {
									description: "The rejected invitation",
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
					// same guarded transition as accept: a concurrent accept or
					// a resend that rotated the token wins cleanly
					const rejected =
						await ctx.context.adapter.incrementOne<InvitationRow>({
							model: "invite",
							where: [
								{ field: "id", value: invitation.id },
								{ field: "status", value: "pending" },
								{ field: "tokenHash", value: invitation.tokenHash },
							],
							increment: {},
							set: { status: "rejected", updatedAt: new Date() },
						});
					if (!rejected) {
						throw APIError.from(
							"BAD_REQUEST",
							INVITE_ERROR_CODES.INVITATION_ALREADY_ACCEPTED,
						);
					}
					const sanitized = sanitizeInvitation(rejected);
					if (opts.onInvitationCanceled) {
						await notify(ctx, "onInvitationCanceled", () =>
							opts.onInvitationCanceled?.(
								{ invitation: sanitized, rejected: true },
								ctx,
							),
						);
					}
					return ctx.json(sanitized);
				},
			),
			/**
			 * ### Endpoint
			 *
			 * POST `/invite/purge`
			 *
			 * Delete invitations that are finished with — expired, canceled,
			 * rejected, and optionally accepted — so the table does not grow
			 * without bound. Requires an authenticated session that passes
			 * `canInvite`; meant to be called from a scheduled job.
			 */
			purgeInvites: createAuthEndpoint(
				"/invite/purge",
				{
					method: "POST",
					// every field is optional, but the body object itself is
					// not: an entirely optional body erases the client's
					// inferred argument type
					body: z.object({
						statuses: z
							.array(z.enum(["expired", "canceled", "rejected", "accepted"]))
							.min(1)
							.optional(),
						/**
						 * Only delete rows untouched for at least this many
						 * seconds, so a just-canceled invitation stays visible
						 * in the UI for a while.
						 */
						olderThan: z.number().int().positive().optional(),
					}),
					use: [inviteManagerMiddleware],
					metadata: {
						openapi: {
							description: "Delete finished invitations",
							responses: {
								"200": {
									description: "How many rows were deleted",
								},
							},
						},
					},
				},
				async (ctx) => {
					const statuses = ctx.body.statuses ?? [
						"expired",
						"canceled",
						"rejected",
					];
					const now = new Date();
					const cutoff = ctx.body.olderThan
						? new Date(now.getTime() - ctx.body.olderThan * 1000)
						: null;
					let deleted = 0;
					// one delete per status: a `where` is a conjunction, and
					// "expired" is a status/expiry pair rather than a stored
					// value
					for (const status of new Set(statuses)) {
						const where: Where[] = [];
						if (status === "expired") {
							where.push({ field: "status", value: "pending" });
							where.push({
								field: "expiresAt",
								value: now,
								operator: "lt",
							});
						} else {
							where.push({ field: "status", value: status });
						}
						if (cutoff) {
							where.push({
								field: "updatedAt",
								value: cutoff,
								operator: "lt",
							});
						}
						deleted += await ctx.context.adapter.deleteMany({
							model: "invite",
							where,
						});
					}
					return ctx.json({ deleted });
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
								.enum([
									"pending",
									"accepted",
									"canceled",
									"rejected",
									"expired",
								])
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
					const withVirtualStatus: ListedInvitation[] = invitations.map(
						(invitation) => {
							const sanitized = sanitizeInvitation(invitation);
							const effectiveStatus: InvitationListStatus =
								invitation.status === "pending" &&
								new Date(invitation.expiresAt) < now
									? "expired"
									: invitation.status;
							return { ...sanitized, status: effectiveStatus };
						},
					);
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
							description: "Re-send a pending invitation with a fresh token",
							responses: {
								"200": {
									description: "The refreshed invitation",
								},
							},
						},
					},
				},
				async (ctx) => {
					const invitation = await ctx.context.adapter.findOne<InvitationRow>({
						model: "invite",
						where: [{ field: "id", value: ctx.body.invitationId }],
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
					if (invitation.status === "rejected") {
						throw APIError.from(
							"BAD_REQUEST",
							INVITE_ERROR_CODES.INVITATION_REJECTED,
						);
					}

					const token = generateRandomString(32, "a-z", "A-Z", "0-9");
					const tokenHash = await hashToken(token);
					const expiresIn = ctx.body.expiresIn ?? opts.expiresIn;
					const updated = await ctx.context.adapter.update<InvitationRow>({
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

					try {
						await issueAndSend(
							ctx,
							refreshed,
							token,
							ctx.context.session!.user,
							true,
						);
					} catch (error) {
						// the rotation already killed the previous token; put
						// it back so a failed delivery does not brick a link
						// that was working a moment ago
						try {
							await ctx.context.adapter.update({
								model: "invite",
								where: [{ field: "id", value: invitation.id }],
								update: {
									tokenHash: invitation.tokenHash,
									expiresAt: invitation.expiresAt,
									updatedAt: new Date(),
								},
							});
						} catch (rollbackError) {
							ctx.context.logger.error(
								"[better-auth-invite] failed to restore the previous invite token after an email delivery failure",
								rollbackError,
							);
						}
						ctx.context.logger.error(
							"[better-auth-invite] sendInvitationEmail failed on resend; the previous token was restored",
							error,
						);
						throw APIError.from(
							"INTERNAL_SERVER_ERROR",
							INVITE_ERROR_CODES.FAILED_TO_SEND_INVITATION_EMAIL,
						);
					}

					return ctx.json(sanitizeInvitation(refreshed));
				},
			),
		},
		schema: mergeSchema(schema, options?.schema),
		rateLimit: [
			{
				pathMatcher(path: string) {
					return (
						path === "/invite/accept" ||
						path === "/invite/get" ||
						path === "/invite/reject"
					);
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
			{
				// a bulk send is up to 100 emails and a purge is a table-wide
				// delete: both are cheap to call and expensive to serve
				pathMatcher(path: string) {
					return path === "/invite/send-bulk" || path === "/invite/purge";
				},
				window: 60,
				max: 5,
			},
		],
		options: opts,
		$ERROR_CODES: INVITE_ERROR_CODES,
	} satisfies BetterAuthPlugin;
};

export type InvitePlugin = ReturnType<typeof invite>;
