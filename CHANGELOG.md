# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Two-factor auth (2FA): TOTP + recovery codes** — a genuine second factor, **no third-party
  dependency** (RFC 4226/6238 in the stdlib, verified against the published vectors). Enrollment
  (`POST /auth/2fa/totp/begin` → `otpauth://` URI + secret; `/confirm` validates a code, enables it,
  returns single-use recovery codes once), `/auth/2fa/disable` (requires a current code), and login
  enforcement: when 2FA is on, `completeLogin` issues a short-lived signed `2fa_pending` cookie
  instead of the session, and `POST /auth/2fa/verify` (a TOTP or recovery code) finishes it. Replay
  is rejected via a stored last-used time-step; recovery codes are sha256-at-rest + single-use. Wire
  the optional `TwoFactorStore` (reference impls in gormstore + memory) with `SetTwoFactorStore`. ([#1])
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
- **SCIM: ETags** — weak ETags on resources (`meta.version` + `ETag` header), `If-None-Match` (→ `304`)
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

[0.1.1]: https://github.com/alex-savin/go-auth-x/releases/tag/v0.1.1
[0.1.0]: https://github.com/alex-savin/go-auth-x/releases/tag/v0.1.0
[#1]: https://github.com/alex-savin/go-auth-x/issues/1
[#3]: https://github.com/alex-savin/go-auth-x/issues/3
[#4]: https://github.com/alex-savin/go-auth-x/issues/4
