# go-auth-x roadmap

Direction and planned work for the library. Authoritative usage/feature docs live in the
[README](./README.md); this file tracks what's shipped and what's next.

## Shipped

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

_Updated 2026-07._
