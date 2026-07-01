# go-auth-x roadmap

Direction and planned work for the library. Authoritative usage/feature docs live in the
[README](./README.md); this file tracks what's shipped and what's next, and is updated as items land.

## Shipped

- **Zero-framework core** — pure `net/http`, no Gin/router dependency.
- **Auth methods** — password (bcrypt 12), passkey/WebAuthn (discoverable + QR/FIDO2 hybrid + clone
  detection), email magic-link, OIDC (Auth Code + PKCE/S256 + `state` + `nonce`), social
  (Google, GitHub).
- **Stores** — GORM reference store + a zero-dependency in-memory store; SMTP mailer.
- **Directory layer** — groups + per-group access control, API keys with **deny-by-default scopes**,
  admin REST API.
- **Enterprise** — LDAP sync (+ deprovision-by-absence); SCIM 2.0 (PUT, `eq`/`co`/`sw`/`pr` filters,
  `/Bulk`).
- **Hardening** — the safe account-linking rule + **squatter-reclaim**; `email_verified`-gated OIDC
  linking; configurable public paths (`Config.PublicPath`); pluggable rate-limit backends
  (`SetRateLimiters`).

## Planned

Tracked in the **[v0.2.0 milestone](https://github.com/alex-savin/go-auth-x/milestone/1)**.

### Two-factor authentication (2FA / MFA) — TOTP + recovery codes — [#1](https://github.com/alex-savin/go-auth-x/issues/1)

The library has several *single*-factor login methods today but **no second-factor step** — there's no
flow that authenticates with one factor and then requires another. Add genuine two-step verification:

- **TOTP (authenticator app)** — an enroll/confirm flow (RFC 6238, via `github.com/pquerna/otp`):
  generate a secret + `otpauth://` URI for a QR, verify a code to enable. The secret is encrypted at
  rest in a new credential side-table, reached through new `CredentialStore` methods
  (`SetTOTPSecret` / `TOTPSecret` / disable).
- **Recovery codes** — a set of single-use, sha256-at-rest codes (reusing the existing single-use
  token infrastructure) so a user who loses their authenticator can still sign in.
- **Login enforcement** — when 2FA is enabled, `completeLogin` issues a short-lived signed
  **`2fa_pending`** flow cookie (the same pattern as the WebAuthn challenge cookie) **instead of** the
  full session, and requires `POST /auth/2fa/verify` (a TOTP code or a recovery code) before the real
  session is minted.
- **Passkey as a second factor** *(optional)* — let a registered passkey satisfy the second step, not
  only act as a primary method. (A passkey is already phishing-resistant and combines possession + user
  verification in one step, so this is mainly for password-primary accounts.)
- **Step-up / re-auth** for sensitive actions (e.g. changing the password, revoking sessions) is a
  natural follow-on once the `2fa_pending` machinery exists.

### Opaque entity IDs (uuid-friendly stores) — [#2](https://github.com/alex-savin/go-auth-x/issues/2) · breaking

Make the public user/group/API-key ID type an opaque `string` across the store interfaces so
uuid/ULID/KSUID consumers pass their IDs straight through. The reference GORM store keeps its `uint`
primary keys and converts (`FormatUint`/`ParseUint`) at its own boundary — **no database migration**.
Verified safe: the IDs are never used arithmetically, ordered, or compared, and the session is keyed by
`Sub` (a string), not the numeric ID. Removes the `uuid ↔ uint` adapter friction for non-`uint` apps.

### Social providers — [#3](https://github.com/alex-savin/go-auth-x/issues/3)

- **Apple** (Sign in with Apple — ES256 client-secret JWT) and **Facebook** login.

### SCIM — [#4](https://github.com/alex-savin/go-auth-x/issues/4) · ✅ landed on `main` (unreleased)

- AND/OR-composed filters, sorting, and ETags. Done — ships in v0.2.0.

---

_Updated 2026-06._
