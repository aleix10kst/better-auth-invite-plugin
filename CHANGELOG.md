# Changelog

## Unreleased

Requires better-auth 1.7 and a migration: the `invite` table gains an index on
`createdAt` and two compound indexes, and `status` can now hold `"rejected"`.

### Fixed

- `claimOnSignUp` no longer relies on a hard-coded list of sign-up routes,
  which silently missed flows that create users — `/sign-in/email-otp` among
  them, leaving the invitation `pending` forever with its `role`, `metadata`
  and `onInvitationAccepted` never applied, and the invite link later failing
  with `USER_ALREADY_EXISTS`. Claiming now hangs off a `user.create` database
  hook, so it covers every flow. It is also cheaper: previously every social
  sign-in by an existing user paid an invitation lookup that could never
  match.
- A failing `sendInvitationEmail` no longer strands the invitation. `send`
  rolls the new invitation back (restoring any pending invitation it
  superseded) and `resend` restores the previous token, so a delivery failure
  never kills a working link or leaves a live token nobody received. Both
  report `FAILED_TO_SEND_INVITATION_EMAIL`.
- `acceptInvite` took its password bounds from a hard-coded `min(8)`/`max(512)`
  instead of `emailAndPassword`'s `minPasswordLength`/`maxPasswordLength`, so
  an app configured below 8 rejected passwords that sign-up accepted, with a
  schema error rather than `PASSWORD_TOO_SHORT`.
- `role` in the accept body is now always discarded. Apps whose own user
  schema declares `role` as an input-able additional field could previously
  let an invitee choose their own role while accepting.

### Added

- `requireInvite`: invite-only sign-up. Enforced as a `user.create` database
  hook, so it covers every sign-up flow, with `allowFirstUser`,
  `allowedEmailDomains` and a custom `allow()` as escape hatches.
- `POST /invite/send-bulk` (`sendBulkInvites`): up to 100 invitations in one
  call, with per-address results instead of an all-or-nothing batch.
- `POST /invite/reject` (`rejectInvite`): lets a recipient decline an
  invitation, with a new `rejected` status and `INVITATION_REJECTED` error.
- `POST /invite/purge` (`purgeInvites`): delete finished invitations
  (`expired`/`canceled`/`rejected`, optionally `accepted`), with an
  `olderThan` window — for a cron job.
- `/invite/get` now returns the inviter's `{ name, image }`, so an accept page
  can say who invited you. Deliberately not their email address.
- `inviteRedirectURL` accepts a function of `{ invitation, inviter }`, for
  per-tenant invite links.
- `onInvitationSent` and `onInvitationCanceled` lifecycle hooks (best-effort:
  errors are logged, never surfaced).
- `maxMetadataSize` (default 4096) caps invitation metadata, rejecting larger
  payloads with `METADATA_TOO_LARGE`.
- Indexes matching the queries the plugin issues: `invite.createdAt` for the
  unfiltered list, plus compound `(status, createdAt)` and `(status, expiresAt)`
  indexes — the latter using better-auth 1.7's table-level `indexes` — for the
  status filters in `listInvites` and the expired sweep in `purgeInvites`.

### Changed

- Accepting an invitation now runs as a single transaction — the claim, the
  user, their credential account, the `acceptedUserId` backfill and
  `onInvitationAccepted` — via Better Auth's `runWithTransaction`. **Behavior
  change**: `onInvitationAccepted` throwing now rolls the acceptance back
  instead of leaving an accepted invitation and a created user behind, so
  provisioning either completes or the invite stays usable. Keep that hook
  database-local; an external API call would hold the transaction open.
  Adapters without transaction support fall back to the previous compensating
  writes.
- `sendInvitationEmail` is dispatched through
  `advanced.backgroundTasks.handler` when the app configures one (`waitUntil`,
  a queue, ...) instead of blocking the response, matching Better Auth core's
  own verification emails.
- `@better-auth/core` is now a peer dependency (it already ships as a
  dependency of `better-auth`; declaring it matters for strict package
  managers).
- **Requires better-auth 1.7.** The peer range is now `>=1.7.0 <2.0.0`, up from
  `^1.6.17`. 1.7 changed two internal-adapter signatures the plugin depends on:
  `createUser` takes a provisioning source as a second argument, and
  `linkAccount` requires an `issuer`. Accepting an invitation now passes
  `{ method: "invite" }` as the provisioning source — so a
  `user.validateUserInfo` gate can single out invite-provisioned users — and
  issues its credential account with `createLocalAccountIssuer("credential")`,
  the same helper core sign-up uses. Supporting 1.6 alongside this would mean
  type casts at both call sites and a fallback for a helper that does not exist
  there, so 1.6 is dropped rather than faked; stay on 0.1.x for better-auth
  1.6.
- Tests now also run against a real SQLite database (kysely + better-sqlite3,
  schema built by Better Auth's own migrations) alongside the in-memory
  adapter, covering the generated indexes, the atomic claim, transactional
  rollback, `deleteMany` counts, and the database-enforced unique indexes that
  the memory adapter cannot model. `oxlint`/`oxfmt` are wired up, and CI runs a
  better-auth version matrix plus `publint`/`attw`.
- **The package is now ESM-only.** The CommonJS build is gone: no `main`, no
  `require` condition in `exports`, no `.cjs`/`.d.cts` in `dist`. `better-auth`
  is itself ESM-only, so the CJS entrypoint only ever worked on runtimes with
  unflagged `require(esm)`. `require()` of this package no longer resolves —
  import it, or stay on 0.1.x.

## 0.1.1

- Add a `./package.json` export subpath, so bundlers and tooling that read a
  dependency's manifest (e.g. `npm-check-updates`) can resolve it instead of
  failing with `ERR_PACKAGE_PATH_NOT_EXPORTED`.

## 0.1.0

Initial release.

- `invite()` server plugin with a dedicated `invite` table: hashed single-use
  tokens, configurable expiry (default 24h), status lifecycle
  (`pending` / `accepted` / `canceled`, virtual `expired`).
- Endpoints: `POST /invite/send`, `GET /invite/get`, `POST /invite/accept`,
  `POST /invite/cancel`, `GET /invite/list`, `POST /invite/resend`.
- Invite semantics: inviting an existing user fails with
  `USER_ALREADY_EXISTS`; re-inviting revokes the previous token; accepting
  creates the user with `emailVerified: true` and signs them in.
- Options: required `sendInvitationEmail` and `inviteRedirectURL`,
  `expiresIn`, `canInvite`, `allowedRoles`, `autoSignIn`, `allowReInvite`,
  `requirePassword`, `claimOnSignUp`, `onInvitationAccepted` hook,
  invitation `metadata`, `user.additionalFields` support on accept.
- `claimOnSignUp`: a pending invitation is automatically claimed (accepted,
  role applied, hook fired) when the invited email signs up through another
  flow — OAuth/social callback, email sign-up, magic link, email OTP.
- `inviteClient()` client plugin with full type inference.
- 50 integration tests against a real Better Auth instance.
