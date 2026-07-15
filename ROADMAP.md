# go-auth-x roadmap

Direction and planned work for the library. Authoritative usage/feature docs live in the
[README](./README.md); this file tracks what's shipped and what's next.

## Shipped

### v0.5.0

- **New capabilities** — features that fit a same-origin embedded Go BFF (IdP-shaped / multi-tenant /
  framework-DX items were deliberately left out of scope):
  - **HIBP password-breach check** (pluggable `BreachChecker` + k-anonymity default, fail-open, opt-in).
  - **`SESSION_SECRET` rotation** via a `PreviousSessionSecrets` verify-only list (no mass logout).
  - **Email OTP** (numeric code) alongside the magic link — email-scoped, salted-at-rest, attempt-capped.
  - **Server-side session revocation** (optional `SessionStore`): list/revoke devices, sign-out-everywhere,
    ban-revokes-all.
  - **Self-service account lifecycle**: delete-account (GDPR cascade + audit anonymization) and verified
    change-email; **OAuth unlink** + a cross-method last-sign-in-method guard; **passkey rename**.
  - **Admin verbs**: create-user, set/reset password, hard-delete, time-boxed **ban**, and
    **impersonation** (with an `ImpersonatedBy` marker `adminGuard` refuses).
  - **Hardening quick-wins**: `429 + Retry-After`, IPv6 `/64` rate-limit keying, and a **trusted-origins**
    allow-list layered on top of the CSRF token.
- **BREAKING** — `CredentialStore` / `DirectoryStore` grew methods and a new optional `SessionStore`
  interface was added (see CHANGELOG); `AuthUser` gained ban fields. Both reference stores implement them.

### v0.4.1

- **`/auth/me` local-only fix** — the `Me` handler branched on the OIDC-only `Enabled()` predicate, so
  a local-methods-on / OIDC-off deployment reported `authEnabled:false` and never parsed the session;
  it now treats local-enabled as auth-enabled and reads the session in that mode.

### v0.4.0

- **Security hardening pass** (from a full audit) — fail-closed session signing on a weak/absent
  `SESSION_SECRET`; the account-linking invariant enforced on the primary OIDC callback and gated on a
  proven email before a store rebinds a verified/bootstrap row (with an atomic squatter-reclaim); Sign
  in with Apple's `form_post` callback exempted from CSRF; rate limiters installed with 2FA (throttling
  `/auth/reauth` + `/auth/2fa/disable`); an atomic TOTP replay guard and monotonic WebAuthn sign
  counts; request body-size limits + SCIM filter depth cap; SCIM `active`-defaults-true, strong
  `If-Match`, PATCH group replace/valuePath-remove, and non-leaking errors; LDAP paged search + TLS +
  DN normalization; email URL escaping, SMTP header sanitization, and constant-time send paths.
- **BREAKING** — `TwoFactorStore` gains `ClaimTOTPStep` (atomic replay guard); custom implementations
  must add it.
- **Added** — `Config.BrandName` (email + WebAuthn RP branding), bcrypt rehash-on-login, and
  `Authenticator.Close()` to stop the built-in rate-limiter GC goroutine.

### v0.3.0

- **Social login: Microsoft/Entra + Discord + any OIDC provider** — Microsoft (Entra ID / Azure AD)
  and Discord as named providers, plus a generic `Config.SocialOIDC` registration for any OIDC IdP
  (GitLab, Okta, Auth0, Keycloak, …). `GET /auth/config` reports enabled providers in `socialProviders`.
- **SCIM niceties** — `startIndex`/`count` pagination, `meta.created`/`meta.lastModified`, and full
  `/Schemas` documents + `GET /Schemas/{id}`.

### v0.2.0

- **Two-factor auth (2FA)** — TOTP + single-use recovery codes (RFC 4226/6238, **stdlib, no
  dependency**), login enforcement via a signed `2fa_pending` cookie, **passkey as a second factor**,
  and **step-up / re-auth** (`RequireStepUpHTTP`) for sensitive actions. ([#1])
- **Social login: Apple + Facebook** — Sign in with Apple (ES256 client-secret JWT, `form_post`) and
  Facebook (Graph API + `appsecret_proof`), alongside Google + GitHub. ([#3])
- **SCIM 2.0** — full filter grammar (`eq`/`ne`/`co`/`sw`/`ew`/`gt`/`ge`/`lt`/`le`/`pr` with
  `and`/`or`/`not`, parens, valuePath), sorting, strong ETags, `Location`/`meta.location`,
  `uniqueness` scimType, PATCH validation, `/Bulk`. ([#4])
- **RFC-compliance hardening** — token-audience segregation (closed a 2FA-bypass), WebAuthn
  UV=Required, LDAP StartTLS `ServerName` + no cleartext bind, OIDC `azp`, Bearer
  `401 + WWW-Authenticate`, fail-closed `randToken`, and more (see CHANGELOG).

### v0.1.x

- Zero-framework core (pure `net/http`); password, passkey/WebAuthn (+ QR), magic-link, OIDC, Google +
  GitHub social; GORM + in-memory stores; SMTP mailer; groups + per-group access control; API keys with
  deny-by-default scopes + admin REST API; LDAP sync; SCIM 2.0 (PUT + basic filters + `/Bulk`); the safe
  account-linking + squatter-reclaim rule; `SESSION_SECRET` ≥ 32-byte enforcement.

## Planned

### Opaque entity IDs (uuid-friendly stores) — [#2](https://github.com/alex-savin/go-auth-x/issues/2) · breaking · deferred

Make the public user/group/API-key ID type an opaque `string` across the store interfaces so
uuid/ULID/KSUID consumers pass their IDs straight through (the reference GORM store keeps its `uint`
PKs and converts at its boundary — no DB migration). Verified safe (the IDs are never used
arithmetically). **Deferred past v0.2.0** — no current consumer needs it, and it's cheapest to land as
a pre-v1.0 breaking change if/when a uuid-keyed consumer adopts the library or the API is frozen for 1.0.

### Also on the list

- **More named social providers** as demand warrants — the generic `Config.SocialOIDC` registration
  already covers any OIDC IdP; named presets (like Microsoft) are added for convenience/quirks.
- **SCIM** — remaining depth: PATCH on complex multi-valued sub-attributes, `/Me`, and richer
  `$ref` handling. Core filters, sorting, ETags, pagination, timestamps, and schemas are done.

---

_Updated 2026-07-15._
