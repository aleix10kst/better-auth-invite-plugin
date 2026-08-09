# @aleix10kst/better-auth-invite

A [Better Auth](https://better-auth.com) plugin that implements an invite system for your app — invite users by email with expiring single-use tokens:

- Admins invite an email address; the invited person receives a single-use link.
- Inviting an email that already belongs to a registered user fails with `USER_ALREADY_EXISTS`.
- Re-inviting a pending email rotates the token: the old link dies, a fresh email goes out.
- Accepting the invitation creates the user with `emailVerified: true`, sets their password, and signs them in.
- Tokens are stored only as SHA-256 hashes, are single-use, and expire (24h by default).

## Installation

```bash
npm install @aleix10kst/better-auth-invite
# or
bun add @aleix10kst/better-auth-invite
```

`better-auth` (>= 1.6.17) and `zod` are peer dependencies. The plugin uses adapter and error APIs introduced in better-auth 1.6.17; it does not load on older versions.

## Server setup

```ts
import { betterAuth } from "better-auth";
import { invite } from "@aleix10kst/better-auth-invite";

export const auth = betterAuth({
  // ...your config
  // required unless you set `requirePassword: false` — accepting an
  // invitation creates a credential (email + password) account
  emailAndPassword: { enabled: true },
  plugins: [
    invite({
      // REQUIRED: deliver the invitation email however you like
      sendInvitationEmail: async ({ invitation, token, url, inviter }) => {
        await sendEmail({
          to: invitation.email,
          subject: `${inviter.name} invited you`,
          text: `Accept your invitation: ${url}`,
        });
      },
      // REQUIRED: where the emailed link points (your app's accept page).
      // The `/invite/accept` API endpoint is POST-only, so the link must
      // land on a page that reads the token and calls it.
      inviteRedirectURL: "https://app.example.com/accept-invite",
      expiresIn: 60 * 60 * 24, // 24h (default)
    }),
  ],
});
```

Run your usual migration flow (`npx @better-auth/cli migrate` / `generate`) — the plugin adds one table, `invite`. The plugin also relies on the `user.email` unique index that Better Auth's schema declares — keep it in place (it is the backstop against a concurrent sign-up racing an invite acceptance).

### Who may invite?

By default, invitation management endpoints (`send`, `cancel`, `list`, `resend`) require a signed-in user whose `role` contains `admin` (comma-separated roles supported, matching the admin plugin's convention — so it composes cleanly with `better-auth/plugins`' `admin()`). Override with `canInvite`:

```ts
invite({
  sendInvitationEmail,
  inviteRedirectURL,
  canInvite: async (user, ctx) => user.email.endsWith("@yourcompany.com"),
  // whoever passes canInvite chooses the invited user's role — when
  // canInvite is broader than "admins only", restrict assignable roles:
  allowedRoles: ["member", "viewer"],
});
```

**`canInvite` gates role assignment too.** The invitation's `role` is written verbatim onto the created (email-verified) user, so anyone who passes `canInvite` can mint users with any role — including `"admin"` or composite values like `"user,admin"` — unless you set `allowedRoles`. If you loosen `canInvite` beyond fully trusted admins, always set `allowedRoles`. Note also that `/invite/send` reveals whether an email is already registered (`USER_ALREADY_EXISTS`); with a permissive `canInvite`, that becomes an account-enumeration oracle for everyone you grant invite rights to (bounded by the 20 req/min rate limit).

Note: the base Better Auth user model has no `role` field. Add one via the admin plugin or `user.additionalFields` if you rely on the default check, or supply your own `canInvite`. The same applies to the invitation's `role`: it is copied onto the created user at accept time only if the user table actually has a `role` field.

## Client setup

```ts
import { createAuthClient } from "better-auth/client";
import { inviteClient } from "@aleix10kst/better-auth-invite/client";

export const authClient = createAuthClient({
  plugins: [inviteClient()],
});

// fully typed:
await authClient.invite.send({ email: "new@user.com", role: "member" });
await authClient.invite.get({ query: { token } });
await authClient.invite.accept({ token, password: "chosen-password" });
await authClient.invite.list({ query: { status: "pending" } });
await authClient.invite.cancel({ invitationId });
await authClient.invite.resend({ invitationId });
```

## Endpoints

| Endpoint | Method | Auth | Description |
| --- | --- | --- | --- |
| `/invite/send` | POST | session + `canInvite` | Invite an email. Body: `{ email, name?, role?, metadata?, expiresIn? }`. Fails with `USER_ALREADY_EXISTS` if the email is registered, and with `ROLE_NOT_ALLOWED` if `allowedRoles` is set and `role` is not in it. Re-inviting a pending email cancels the old invite and issues a fresh token (unless `allowReInvite: false`, then `INVITATION_ALREADY_SENT`). Returns the invitation (never the token). |
| `/invite/get` | GET | public | Query: `{ token }`. Returns `{ email, name, role, metadata, status, expiresAt }` for a valid pending token; `404 INVITATION_NOT_FOUND`, `410 INVITATION_EXPIRED`, `400 INVITATION_CANCELED` / `INVITATION_ALREADY_ACCEPTED` otherwise. |
| `/invite/accept` | POST | public | Body: `{ token, password?, name?, ...additionalFields }`. Creates the user (`emailVerified: true`, role from the invitation, plus any `user.additionalFields` passed in the body — validated exactly like sign-up), sets the password (credential account; required unless `requirePassword: false`), marks the invite accepted, calls `onInvitationAccepted`, and — with `autoSignIn` (default) — creates a session and sets the cookie. Returns `{ token, user }`. |
| `/invite/cancel` | POST | session + `canInvite` | Body: `{ invitationId }`. Cancels a pending invitation, invalidating its token. |
| `/invite/list` | GET | session + `canInvite` | Query: `{ status?, email?, limit?, offset? }`. Lists invitations (never token hashes) and returns `{ invitations, total }`. Pending invitations past expiry are reported with the virtual status `"expired"`; the `pending`/`expired` filters are applied in the database query, so `limit`/`offset` paginate the filtered set and `total` counts it. |
| `/invite/resend` | POST | session + `canInvite` | Body: `{ invitationId, expiresIn? }`. Re-sends a pending invitation (expired ones included) with a fresh token and expiry; the old token stops working (acceptance is guarded on the token hash, so an in-flight accept with the old token loses). |

Server-side, the endpoints are available as `auth.api.sendInvite`, `auth.api.getInvite`, `auth.api.acceptInvite`, `auth.api.cancelInvite`, `auth.api.listInvites`, and `auth.api.resendInvite`.

## Options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `sendInvitationEmail` | `(data, request?) => Promise<void>` | — (required) | Called with `{ invitation, token, url, inviter }`. The only place the raw token is exposed. |
| `inviteRedirectURL` | `string` | — (required) | App page the emailed `url` points at (token appended as `?token=`). The `/invite/accept` API endpoint is POST-only, so the link must land on a page. |
| `expiresIn` | `number` (seconds) | `86400` (24h) | Invitation lifetime. Positive integer, at most `31536000` (1 year). Can be overridden per call via the `expiresIn` body field of `send`/`resend` (same bounds). |
| `canInvite` | `(user, ctx) => boolean \| Promise<boolean>` | `user.role` contains `"admin"` | Gate for `send`/`cancel`/`list`/`resend`. Also gates role assignment — see `allowedRoles`. |
| `allowedRoles` | `string[]` | — (any role) | When set, `sendInvite` rejects any `role` not in the list with `ROLE_NOT_ALLOWED`. Set this whenever `canInvite` is looser than "admins only". |
| `autoSignIn` | `boolean` | `true` | Create a session + set the cookie when an invitation is accepted. |
| `allowReInvite` | `boolean` | `true` | Re-inviting a pending email cancels the old invitation and issues a fresh token. When `false`, it throws `INVITATION_ALREADY_SENT`. |
| `requirePassword` | `boolean` | `true` | Accepting requires choosing a password (credential account; needs `emailAndPassword` enabled — the plugin fails fast at startup otherwise). Set to `false` to create the user without a credential account so they finish sign-in via any other enabled method (social provider, magic link, passkey, ...). |
| `claimOnSignUp` | `boolean` | `true` | When the invited email signs up through another flow (OAuth/social callback, email sign-up, magic link, email OTP, ...), automatically claim the pending invitation: mark it accepted, apply its `role` and fire `onInvitationAccepted`. See [Invites and OAuth](#invites-and-oauth-sign-up). |
| `onInvitationAccepted` | `({ invitation, user }, ctx) => void \| Promise<void>` | — | Called after the user is created and the invitation marked accepted (before the session response). Use it to provision what the invite was for (org membership, seat, ...). Errors propagate but do not roll back the acceptance. |
| `schema` | Better Auth schema override | — | Rename the `invite` table / columns (standard `modelName` / `fields` passthrough). |

### Invitation metadata

Attach arbitrary JSON context to an invitation (team id, locale, plan, a personal message, ...) via the `metadata` body field of `send`. It is stored as a JSON string in the `metadata` column and returned parsed on the invitation everywhere it appears: `sendInvitationEmail`'s `data.invitation.metadata`, `/invite/get`, `/invite/list`, and `onInvitationAccepted`.

```ts
await authClient.invite.send({
  email: "new@user.com",
  role: "member",
  metadata: { teamId: "team_1", locale: "en" },
});
```

### Additional user fields on accept

If your app defines `user.additionalFields`, the accept body forwards them to the created user exactly like sign-up does (required fields are enforced, `input: false` fields are rejected):

```ts
await authClient.invite.accept({ token, password, username: "picked-name" });
```

### Invites and OAuth (sign-up)

An invitation is addressed to an email; OAuth is just another way for the
invitee to prove they own it. Two paths lead to a fully accepted invitation:

- **Via the invite link**: the accept page calls `acceptInvite` with the
  token. With `requirePassword: false` the user is created without a
  credential account and later signs in with any enabled method — a social
  sign-in on the same (verified) email links to the created user through
  Better Auth's account linking.
- **Directly, skipping the link** (`claimOnSignUp`, on by default): if the
  invitee ignores the email and just hits "Continue with Google" (or signs
  up with email, magic link, email OTP, ...), the plugin detects the
  matching pending invitation after the sign-up/sign-in completes and
  claims it — marks it accepted, applies its `role` to the new user, and
  fires `onInvitationAccepted`. The invite token becomes unusable
  (`INVITATION_ALREADY_ACCEPTED`), so a later click on the emailed link
  cannot double-accept.

Claiming is atomic (a concurrent `acceptInvite` or `resend` wins cleanly)
and never breaks the sign-in that triggered it: claim errors are logged,
not thrown. Note that claiming does not verify the invited address beyond
what the sign-up method itself verified — it does not set `emailVerified`.

## The accept-page flow

1. Point `inviteRedirectURL` at a page in your app, e.g. `https://app.example.com/accept-invite`. The invitation email's `url` becomes `https://app.example.com/accept-invite?token=<raw token>`. (This is why the option is required: `/invite/accept` is a POST endpoint that also needs a password in the body, so a browser can't open it from an email link.)
2. On that page, read the `token` query parameter and (optionally) show who's being invited:

   ```ts
   const { data, error } = await authClient.invite.get({ query: { token } });
   // data: { email, name, role, metadata, status, expiresAt }
   ```

3. Ask the user for a password and accept:

   ```ts
   const { data, error } = await authClient.invite.accept({
     token,
     password,
   });
   // user is created and (by default) signed in — redirect to your app
   ```

The invited user lands in your app and sets a password as part of acceptance — atomically, so no passwordless half-registered state ever exists: if any step of acceptance fails after the user row is created, the plugin deletes the partial user and returns the invitation to `pending` so the same link can be retried.

## Errors

Exposed on the plugin as `$ERROR_CODES` (and exported as `INVITE_ERROR_CODES`):

`USER_ALREADY_EXISTS`, `INVITATION_NOT_FOUND`, `INVITATION_EXPIRED`, `INVITATION_ALREADY_ACCEPTED`, `INVITATION_CANCELED`, `INVITATION_ALREADY_SENT`, `NOT_AUTHORIZED_TO_INVITE`, `FAILED_TO_CREATE_USER`, `PASSWORD_TOO_SHORT`, `PASSWORD_TOO_LONG`, `PASSWORD_REQUIRED`, `ROLE_NOT_ALLOWED`.

## Security notes

- **Hashed at rest**: only the SHA-256 hash of the invite token is stored. A database leak does not expose usable invite links. The raw token appears exactly once, in your `sendInvitationEmail` callback; the `send`/`resend` endpoints never return it to the caller.
- **Single-use**: acceptance atomically flips the invitation from `pending` to `accepted` (guarded update conditioned on both status and token hash), so a token can only ever create one user, even under concurrent accepts — and a token rotated by a concurrent resend loses the race too. If user creation fails mid-acceptance, the partial user is deleted and the claim released, so no orphaned verified user is left behind.
- **Expiring**: invitations expire after `expiresIn` seconds (default 24h, capped at 1 year); expiry is enforced at read/accept time with a distinct `INVITATION_EXPIRED` (HTTP 410) error.
- **Rotation**: re-inviting or resending invalidates the previous token immediately.
- **Rate limited**: the plugin ships rate-limit rules (10/min for `get`/`accept`, 20/min for `send`/`resend`) that plug into Better Auth's rate limiter.
- **No user enumeration on accept**: `get`/`accept` only respond to a valid token; guessing a 32-char alphanumeric token is infeasible (~190 bits). `send`, however, intentionally reports `USER_ALREADY_EXISTS` — see the `canInvite` notes above before granting invite rights broadly.
- **Token travels in the URL**: like Better Auth's own email-verification links, the raw token is a query parameter of the emailed link and of `GET /invite/get`, so it can end up in server/proxy access logs and browser history until it is used or expires. Tokens are single-use, high-entropy (~190 bits), and short-lived; keep `expiresIn` short and have your accept page exchange the token via the POST accept call promptly. Treat log access as sensitive.
- **Unique email index**: correctness under a concurrent independent sign-up for the invited address relies on the `user.email` unique index from Better Auth's core schema (the plugin also re-checks inside the acceptance claim). SQL adapters get this from migrations; for MongoDB, create the unique index yourself. The in-memory adapter enforces no uniqueness and is for tests only.

## Naming

The database model and routes use the short noun — table `invite`, routes `/invite/*`, endpoints `sendInvite`/`cancelInvite`/... — because the `invitation` model name is already taken by the organization plugin. Domain nouns follow the organization plugin's vocabulary: the `Invitation` type, `invitationId` body fields, `sendInvitationEmail`, and `INVITATION_*` error codes.

## License

MIT
