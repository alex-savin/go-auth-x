# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] — 2026-07-15

A feature pass adding self-service, session-management, admin, and hardening capabilities that fit a
same-origin Go BFF. Everything slots into the existing seams (the `completeLogin` funnel, the
pluggable-backend pattern, small store interfaces).

### Added

- **HIBP password-breach check (opt-in).** A pluggable `BreachChecker` interface with a default Have I
  Been Pwned k-anonymity implementation (`NewHIBPBreachChecker`) — only the first 5 hex chars of the
  SHA-1 are sent, and the checker is fail-open by default so a HIBP outage degrades to the embedded
  common-password list rather than blocking signups. Enable with `HIBP_BREACH_CHECK=true` or
  `SetBreachChecker`. Consulted on signup, password reset, password change, and admin set-password.
- **Signing-key rotation without mass logout.** `Config.PreviousSessionSecrets` (env
  `SESSION_SECRET_PREVIOUS`, comma-separated) is a verify-only list: sessions/step-up/flow/2FA cookies
  are always *signed* with the primary `SESSION_SECRET` but *verified* against the primary plus any
  previous keys, so a key can be rotated and the old one retired after one TTL window. Previous keys are
  length-validated (≥ 32 bytes) at `New`.
- **Email OTP (numeric sign-in code).** `POST /auth/email-otp/send` + `POST /auth/email-otp/verify` — a
  6-digit code alternative to the magic link (better for mail-scanner link-prefetch and native apps).
  Codes are `crypto/rand`, salted-sha256-at-rest, **email-scoped** (a guessed code can't match another
  user's), single-use, and bounded by a per-code attempt counter plus the per-IP limiter.
- **Server-side session revocation (opt-in).** A pluggable `SessionStore` interface (reference impls in
  `gormstore` + `memory`) records a random `sid` per session and lets you revoke it. New self-service
  endpoints `GET /auth/api/sessions`, `DELETE /auth/api/sessions/{sid}`,
  `POST /auth/api/sessions/revoke-others`, plus admin `GET/POST /auth/admin/users/{id}/sessions[/revoke]`.
  `nil` store = today's stateless behavior; when wired, `GateHTTP`/self-gated endpoints consult
  revocation and logout revokes the current session.
- **Self-service account lifecycle.** `DELETE /auth/api/account` (step-up gated; cascades all
  credentials/2FA/sessions and anonymizes the audit trail — GDPR erasure) and verified change-email
  (`POST /auth/api/account/email` → confirmation link to the NEW address → `GET /auth/email/change`),
  which never writes the new address until it's proven and notifies the old address.
- **OAuth unlink + a real last-method guard.** `DELETE /auth/api/identities/{provider}` removes a linked
  social/OIDC identity, and both it and passkey removal now refuse to strip the user's **last** sign-in
  method counted across password + passkeys + OAuth (the previous guard was passkey-only). `AccountInfo`
  now lists linked `oauth` providers. New store methods `UnlinkOAuth` / `OAuthIdentities`.
- **Passkey rename.** `POST /auth/api/passkeys/{id}` relabels a passkey (`RenamePasskey`).
- **Admin user verbs.** `POST /auth/admin/users` (create), `POST /auth/admin/users/{id}/password`
  (set/reset, policy-checked), `DELETE /auth/admin/users/{id}` (hard delete), and
  `POST /auth/admin/users/{id}/ban` (time-boxed ban with reason). Bans are enforced in the login callers
  and, when a session store is wired, revoke live sessions immediately.
- **Admin impersonation.** `POST /auth/admin/users/{id}/impersonate` mints a short-lived session
  carrying an `ImpersonatedBy` marker (surfaced at `/auth/me`); `POST /auth/api/stop-impersonating` ends
  it. `adminGuard` refuses admin actions from an impersonated session.
- **Trusted-origins allow-list (defense-in-depth).** `Config.TrustedOrigins` (env `TRUSTED_ORIGINS`)
  adds an `Origin`/`Referer` allow-list check *on top of* the CSRF token, seeded from `AppURL`. Fails
  open when the header is absent or nothing is configured, so no legitimate same-origin POST is rejected.

### Changed

- **`429` responses now carry `Retry-After`** on every auth rate-limit / lockout throttle.
- **IPv6 rate-limit keys collapse to the `/64`** so an actor can't dodge per-IP limits by rotating
  within its allocation (IPv4 keys are unchanged; audit/display still records the full address).
- **Password length is capped at 72 bytes** (bcrypt's hard input limit), replacing the prior 200-byte
  cap — an over-limit password is now a clean `400` instead of passing validation and failing to hash.
- **`GET /auth/config`** now advertises `emailOtp`; **`GET /auth/me`** now returns `impersonatedBy`.

### Security

- **Revoking a user is durable when a `SessionStore` is wired.** Ban, disable, and hard-delete revoke the
  target's live sessions; delete **tombstones** them (marks revoked + nulls the PII) rather than deleting
  the rows, so an absent record can't be misread as "not revoked" and re-admit a deleted user on another
  device. **Without a `SessionStore` (the stateless default), active sessions cannot be revoked before
  they expire** — ban/disable/delete take effect on the next login; wire a `SessionStore` for immediate,
  cross-device termination.
- **Password reset validates the new password before consuming the token** (via the new `PeekToken`), so
  a policy-rejected attempt no longer burns the single-use reset link.
- **Defense-in-depth on the unauthenticated entry points.** The trusted-origins allow-list now also
  guards the CSRF-exempt login endpoints (e.g. `/auth/email-otp/verify`) against login-CSRF; the
  change-email endpoint is rate-limited; the signup rate limiter runs before any outbound HIBP call; the
  last-sign-in-method removal guard is serialized against concurrent removals; and admin impersonation
  always records a non-empty actor (`apikey:<id>` for API-key callers). Both reference stores are at
  parity on duplicate-email conflicts and audit anonymization.
- **Microsoft/Entra multi-tenant email is no longer trusted (nOAuth).** The `common`/`organizations`/
  `consumers` (and unset) endpoints accept tokens from any tenant, so their email claim is
  attacker-controllable; the Microsoft preset now only assume-verifies the email when a single tenant is
  pinned (`MICROSOFT_TENANT`), and logs a warning otherwise. Prevents linking an attacker's identity onto
  a victim's verified account.
- **A social-login-only deployment now still gates.** `enforcing()` counts configured social providers,
  so `GateHTTP`/`CSRFHTTP` no longer no-op (serving protected routes unauthenticated) when only social
  login is wired.
- **Session-cookie verification fails closed on an under-strength key** (symmetric with signing), the
  post-login `next` redirect rejects control bytes (a tab-based scheme-relative open-redirect), a SCIM
  `CREATE`/`PUT` onto an existing email returns `409 uniqueness` instead of silently rebinding/reclaiming
  the account, LDAP deprovision keys on LDAP presence (not on whether the per-user upsert succeeded), an
  untracked session (a lost `RecordSession`) fails closed rather than staying un-revocable, and
  passkey-as-2FA can't be satisfied by the same credential used for the first factor.

### Breaking

- `CredentialStore` gains `SetEmail`, `DeleteUser`, `RenamePasskey`, `UnlinkOAuth`, `OAuthIdentities`,
  `CreateEmailOTP`, `VerifyEmailOTP`, `PeekToken`; `DirectoryStore` gains `SetUserBan` and `UserByEmail`
  (the latter lets SCIM enforce create-uniqueness); and a new optional `SessionStore` interface is
  introduced. `AuthUser` gains `Banned` / `BannedUntil` / `BanReason`. `SessionStore.IsRevoked` now
  treats an unknown (non-empty) SID as revoked. Custom store implementations must add the new methods
  (both reference stores already do).

## [0.4.1] — 2026-07-02

### Fixed

- **`/auth/me` reports auth as enabled and reads the session in local-only mode.** The `Me` handler
  branched on the OIDC-only `Enabled()` predicate, so a deployment with local methods on but OIDC off
  (`SetLocalEnabled`, no issuer) reported `authEnabled:false` and never parsed the session cookie —
  frontends could not render the signed-in state or a logout control despite an active gated session.
  `Me` now treats local-enabled as auth-enabled and parses the session in that mode.

## [0.4.0] — 2026-07-02

### Security

- **Session signing fails closed on a weak/absent `SESSION_SECRET`.** `signJWT` now refuses to sign
  any cookie when the secret is shorter than 32 bytes, closing a hole where local-only auth with an
  unset `SESSION_SECRET` would silently mint cookies signed with an empty (publicly known) HMAC key.
  `SetLocalEnabled` logs a clear warning in that case. JWT parsing also pins `HS256` via
  `WithValidMethods` (defense-in-depth alongside the existing keyfunc check).
- **Account-linking gate enforced on the primary OIDC callback.** The OIDC callback now rejects a
  token whose email isn't verified (unless `OIDC_ASSUME_VERIFIED`), matching the social path; and both
  reference stores now require the *incoming* login to prove the email before rebinding an existing
  verified/bootstrap row to a new subject — preventing takeover of a verified account by an unproven
  login. The gormstore reclaim (delete squatter + create clean user) is now a single transaction.
- **Sign in with Apple no longer blocked by CSRF.** Social provider callbacks
  (`/auth/social/*/callback`, incl. Apple's cross-site `form_post`) are exempt from the double-submit
  CSRF check (they're protected by the OAuth `state` parameter).
- **2FA brute-force throttling in OIDC/social-only deployments.** Rate limiters are now installed when
  a `TwoFactorStore` is wired (not only via `SetLocalEnabled`); `POST /auth/reauth` and
  `POST /auth/2fa/disable` are rate-limited like `/auth/2fa/verify`.
- **TOTP replay guard is atomic.** A new `TwoFactorStore.ClaimTOTPStep` records a just-used time-step
  only if it advances, in one atomic store operation (no check-then-write TOCTOU). WebAuthn sign-count
  updates are monotonic (never regress under concurrency). *(Interface change: custom `TwoFactorStore`
  implementations must add `ClaimTOTPStep`.)*
- **`AssumeVerified` only fills in an absent `email_verified`** — an explicit `email_verified:false`
  is always honored.
- **Recovery codes** widened to 80 bits of entropy.
- **Request bodies are size-capped** (JSON handlers and SCIM, incl. `/Bulk`) to prevent
  memory-exhaustion; SCIM filter parsing is depth-bounded against stack-overflow DoS.
- **Open-redirect hardening** — the post-login `next` now rejects backslash scheme-relative targets
  (`/\evil.com`).
- **SCIM create without `active` no longer disables the account** (RFC 7644 default is true); SCIM/admin
  error responses no longer leak internal error strings; SCIM `If-Match` uses strong comparison;
  duplicate group create returns 409; PATCH group `replace`/valuePath-`remove` handled correctly.
- **LDAP** sync uses paged searches (works past the server size limit), honors `InsecureTLS` for
  `ldaps://`, and normalizes DNs when matching group members.
- **Email/SMTP** — CTA URLs are HTML-escaped in emails; SMTP headers are sanitized against CRLF
  injection; magic-link / reset sends run off the request path to remove an account-enumeration timing
  oracle.

### Added

- `Config.BrandName` / `BRAND_NAME` — product name for auth emails and the default WebAuthn RP display
  name (replaces the hardcoded app name).
- Transparent bcrypt rehash-on-login: a stored hash below the current cost is upgraded on successful
  sign-in.
- `Authenticator.Close()` stops the built-in rate-limiter GC goroutine.

## [0.3.0] — 2026-07-01

### Added

- **Social login: Microsoft/Entra, Discord, and any OIDC provider.** Sign in with Microsoft
  (Entra ID / Azure AD — work, school, and personal accounts; tenant-scoped or `common`) and Discord
  (OAuth2 + a verified-email check). A new `Config.SocialOIDC` registers *any* standards-compliant
  OIDC identity provider (GitLab, Okta, Auth0, Keycloak, …) as a social login at
  `/auth/social/<name>/{login,callback}`, reusing Google's PKCE + nonce + `azp` + `email_verified`
  path. `GET /auth/config` now reports every enabled provider in a `socialProviders` array. New env:
  `MICROSOFT_CLIENT_ID`/`MICROSOFT_CLIENT_SECRET`, `MICROSOFT_TENANT`, `DISCORD_CLIENT_ID`/`DISCORD_CLIENT_SECRET`.
- **SCIM: pagination** — `startIndex` / `count` on the Users and Groups list endpoints
  (RFC 7644 §3.4.2.4), with accurate `totalResults` / `startIndex` / `itemsPerPage` in the ListResponse
  (`count=0` is a valid count-only query).
- **SCIM: resource timestamps** — `meta.created` / `meta.lastModified` on Users and Groups (surfaced
  from the store; omitted when unavailable).
- **SCIM: full schema documents** — `GET /Schemas` now returns a ListResponse of complete User +
  Group schema definitions (attributes, types, mutability, uniqueness), plus `GET /Schemas/{id}`
  (RFC 7643 §7 / RFC 7644 §4).

## [0.2.0] — 2026-06-30

### Security

- **RFC-compliance audit fixes.** Token audiences segregate session / oauth-flow / 2fa-pending /
  webauthn cookies (a 2fa-pending token can no longer be replayed as a session — closes a 2FA bypass;
  RFC 7519). WebAuthn now **requires** user verification (RFC/WebAuthn L2). `randToken` fails closed on
  a `crypto/rand` error instead of emitting a guessable state/CSRF/API-key token (RFC 6749 §10.10).
  TOTP validation is past-leaning (fixes a ~90s window + a replay-guard lockout; RFC 6238) and
  `/auth/2fa/verify` is rate-limited (RFC 4226 §7.3). LDAP StartTLS sets `ServerName` and refuses a
  cleartext bind (RFC 4513). OIDC validates `azp` (Core §3.1.3.7). The admin Bearer guard returns
  `401 + WWW-Authenticate` / `403 insufficient_scope` per RFC 6750 §3.

### Added

- **Two-factor auth (2FA): TOTP + recovery codes** — a genuine second factor, **no third-party
  dependency** (RFC 4226/6238 in the stdlib, verified against the published vectors). Enrollment
  (`POST /auth/2fa/totp/begin` → `otpauth://` URI + secret; `/confirm` validates a code, enables it,
  returns single-use recovery codes once), `/auth/2fa/disable` (requires a current code), and login
  enforcement: when 2FA is on, `completeLogin` issues a short-lived signed `2fa_pending` cookie
  instead of the session, and `POST /auth/2fa/verify` (a TOTP or recovery code) finishes it. Replay
  is rejected via a stored last-used time-step; recovery codes are sha256-at-rest + single-use. Wire
  the optional `TwoFactorStore` (reference impls in gormstore + memory) with `SetTwoFactorStore`. ([#1])
- **Passkey as a second factor** — a login halted for 2FA can complete the second step with a
  registered passkey (`POST /auth/2fa/webauthn/begin` + `/finish`, a non-discoverable assertion) as an
  alternative to a TOTP/recovery code. ([#1])
- **Step-up / re-authentication** — `RequireStepUpHTTP(maxAge)` middleware + `StepUpFresh` accessor
  gate sensitive routes on a recent re-auth; `POST /auth/reauth` (password or a 2FA code) sets a
  short-lived signed step-up cookie bound to the session subject. ([#1])
- **Social login: Apple + Facebook.** Sign in with Apple (OIDC — the library signs the ES256
  client-secret JWT from your `.p8` and handles Apple's `form_post` callback via a `SameSite=None`
  flow cookie) and Facebook (Graph API `/me` with an `appsecret_proof`). Both follow the same
  verified-email account-linking rule as Google/GitHub. New env: `FACEBOOK_CLIENT_ID/SECRET`,
  `APPLE_CLIENT_ID`/`APPLE_TEAM_ID`/`APPLE_KEY_ID`/`APPLE_PRIVATE_KEY`. ([#3])
- **SCIM: boolean-composed filters** — `and` / `or` / `not` + parentheses over
  `eq`/`ne`/`co`/`sw`/`ew`/`gt`/`ge`/`lt`/`le`/`pr` (previously single-term, eq/co/sw/pr only), plus
  **valuePath** (`emails[type eq "work"]`, `members[value eq "42"]`), on `userName`/`emails`/`externalId`/`active`/`id`
  (users) and `displayName`/`id`/`members` (groups). Malformed filters return `400` `invalidFilter`. ([#4])
- **SCIM: sorting** — `sortBy` / `sortOrder` on the list endpoints. ([#4])
- **SCIM: ETags** — strong ETags on resources (`meta.version` + `ETag` header), `If-None-Match` (→ `304`)
  on reads, and `If-Match` (→ `412`) optimistic-concurrency on PUT/PATCH/DELETE. `ServiceProviderConfig`
  now advertises `sort` + `etag` supported. ([#4])

## [0.1.1] — 2026-06-30

### Security

- **`SESSION_SECRET` minimum length is now enforced at construction.** `New()` fails closed when
  auth will mint cookies (OIDC configured, or a secret supplied for local/social) and the secret is
  shorter than 32 bytes — the guarantee the docs already described. Previously only a non-empty
  secret was required, so a short, weak HMAC key was silently accepted.

### Fixed

- **Docs:** corrected the passkey `rpID` description — it is derived from the configured app origin
  (override via `WEBAUTHN_RPID`), **not** the request `Host`, so it can't be spoofed. The previous
  "never host-inferred" wording was inaccurate.

## [0.1.0] — 2026-06-30

First tagged release. A self-contained, embeddable authentication library for Go web apps
(BFF model: one signed HS256 session cookie, no separate identity provider to run). Pure
`net/http`, Go 1.26, MIT-licensed.

### Added

- **Core auth engine (`authx`)** — every login method funnels into a single login-completion
  path that runs the `Authorizer`, enriches the session with the user's groups, mints the
  cookie, and issues a CSRF token.
- **BFF sessions** — one HMAC-signed (HS256) HttpOnly cookie; the SPA never handles a token.
  `SameSite=Lax`, `Secure` auto-on under TLS / `X-Forwarded-Proto`; 12 h default TTL, 30 d
  with remember-me.
- **Password auth** — bcrypt (cost 12), NIST-style policy (≥10 chars, common-password
  blocklist, no email local-part); signup → verification email, login requires a verified email.
- **Passkeys / WebAuthn** — same-origin, discoverable (resident-key required, usernameless)
  login with cross-device QR (FIDO2 hybrid transport); clone detection refuses login on a
  `CloneWarning`; self-service enrollment and removal with a last-method guard.
- **Email magic-links** — passwordless sign-in plus email verification and password reset on
  shared single-use token machinery (15 m / 24 h / 1 h TTLs); redeeming a link marks the email
  verified.
- **OIDC client** — Authorization Code + PKCE (S256) with `state` + `nonce`; discovery fails
  closed at boot; enforces `OIDC_ALLOWED_GROUPS`; optional `Authorizer` post-login hook.
- **Social login** — Google (OIDC, `email_verified` required) and GitHub (REST, primary +
  verified email required); links to an existing verified user else creates, refuses an
  unverified squatter (`409`) unless a directory reclaim applies.
- **Pure `net/http`** — `Handler()` mounts `/auth/*` in any mux; `GateHTTP` / `CSRFHTTP` /
  `RequireGroupsHTTP` middleware; `SessionFromRequest` / `GroupsFromRequest` accessors;
  configurable public paths (`Config.PublicPath`).
- **Auth method discovery** — public `GET /auth/config` reports which methods are wired.
- **Directory layer (optional)** — first-class groups surfaced in the session, per-group
  access control, and an admin REST API under `/auth/admin` (owner session or `admin`-scoped
  API key).
- **API keys** — `axk_`-prefixed, sha256-at-rest, with optional expiry and deny-by-default
  scopes; validated via `ValidateAPIKey` / `ValidateAPIKeyScope`; raw key shown once.
- **LDAP sync (`ldapsync`)** — one-way pull of users and groups from LDAP/Active Directory
  (OpenLDAP/AD attribute mapping, StartTLS), additive by default, with optional
  deprovision-by-absence (disable, not delete) guarded against empty results.
- **SCIM 2.0 server (`scim`)** — mountable provisioning server: Users + Groups create / read /
  list (`eq`, `co`, `sw`, `pr` filters) / PATCH / PUT / delete, deprovision via `active=false`,
  a `/Bulk` endpoint (max 100), and `ServiceProviderConfig` / `ResourceTypes` / `Schemas`
  discovery; Bearer-authed.
- **Reference stores** — `gormstore` (self-migrating `authx_*` tables, atomic single-use token
  consumption with a row lock, one-user-per-email unique index, the safe linking rule, and a
  reference `Authorizer`) and `memory` (zero-dependency, in-process); both implement
  `CredentialStore` + `DirectoryStore`.
- **SMTP mailer (`mailer`)** — multipart text+html sender requiring explicit STARTTLS (refuses
  if the server lacks it), wired through the `Mailer` interface.
- **Configuration** — `ConfigFromEnv()` plus a programmatic `Config{}`.
- **Pluggable rate-limit backends** — `RateLimiter` interface + `SetRateLimiters`, with a
  built-in in-memory sliding-window default (20 / 5 min per IP, 10 / 15 min per account).

### Security

- **Account-linking invariant** — an email row is adopted only if it is a bootstrap
  placeholder or already verified. A verified incoming login reclaims a squatter
  (cascade-deleting it and its credentials, then provisioning a clean verified user); an
  unverified collision is refused (`ErrEmailConflict`). Covered by tests.
- **Sessions** — alg-confusion pinned (the parser rejects any non-HMAC algorithm).
- **CSRF** — double-submit token (`sweep_csrf`), constant-time compare, enforced on
  state-changing `/api` + `/auth`, except unauthenticated entry points and Bearer requests.
- **Tokens** (magic-link / verify / reset) — sha256-at-rest, single-use (atomic redemption with
  a row lock), per-purpose TTL, generic always-200 anti-enumeration responses.
- **Passwords** — constant-time dummy-hash compare on unknown users/credentials to defeat
  enumeration.
- **Passkeys** — sign-count clone detection refuses login on a `CloneWarning`.
- **OAuth/OIDC** — PKCE (S256) + `state` + `nonce` with constant-time compares; email trusted
  only when `email_verified` is set (or `OIDC_ASSUME_VERIFIED`, default off, for a single
  trusted IdP).
- **API-key scopes** — deny-by-default (an empty scope list grants nothing; `["*"]` grants all).
- **Per-account lockout** — soft lockout from durable audit history (5 failures / 15 min),
  owner-email exempt; recovery paths stay open.
- **Trusted-proxy client-IP** — `X-Forwarded-For` honored only when the direct peer is a
  trusted proxy (`TRUSTED_PROXIES`, or private-range default), so the client IP can't be spoofed.

[0.4.1]: https://github.com/alex-savin/go-auth-x/releases/tag/v0.4.1
[0.4.0]: https://github.com/alex-savin/go-auth-x/releases/tag/v0.4.0
[0.3.0]: https://github.com/alex-savin/go-auth-x/releases/tag/v0.3.0
[0.2.0]: https://github.com/alex-savin/go-auth-x/releases/tag/v0.2.0
[0.1.1]: https://github.com/alex-savin/go-auth-x/releases/tag/v0.1.1
[0.1.0]: https://github.com/alex-savin/go-auth-x/releases/tag/v0.1.0
[#1]: https://github.com/alex-savin/go-auth-x/issues/1
[#3]: https://github.com/alex-savin/go-auth-x/issues/3
[#4]: https://github.com/alex-savin/go-auth-x/issues/4
