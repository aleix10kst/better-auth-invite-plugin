# Changelog

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
