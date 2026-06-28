# go-auth-x — Go Authentication, eXtended

A self-contained, batteries-included authentication library for Go web apps, extracted from a
production backend-for-frontend (BFF). One signed `HttpOnly` session cookie; the SPA never touches
tokens. Supports **passwords, passkeys (WebAuthn, incl. cross-device QR), email magic-link, and OIDC**
behind one `completeLogin` funnel, so no method can bypass provisioning or the verified/disabled gates.

> Module path is `github.com/alex-savin/go-auth-x` (placeholder). Rename in `go.mod` + the two
> `authx "github.com/alex-savin/go-auth-x"` imports under `store/` to your own path.

## What's in the box

| Package | Role |
|---|---|
| `authx` (root) | The auth engine: session (HS256), password, WebAuthn, magic-link, OIDC, CSRF, rate-limit, the `CredentialStore` / `Authorizer` / `Mailer` interfaces |
| `store/gormstore` | Reference `CredentialStore` over GORM (Postgres/SQLite), **+ the safe verified-email linking rule** |
| `store/memory` | Zero-dependency in-memory `CredentialStore` (tests, demos, single-process) |
| `mailer` | Reference SMTP (STARTTLS) `Mailer` |

## Security model

- **BFF sessions**: HS256-signed cookie, `alg:none`/alg-confusion rejected, `exp`/`iat` enforced.
- **Passkeys**: fixed `rpID`/origin (never host-inferred), signed challenge cookie, **clone detection**
  (`CloneWarning`), discoverable login → the browser offers **"use a phone" QR** (FIDO2 hybrid). Registration
  requires resident keys and allows cross-platform authenticators, so QR cross-device sign-in works.
- **Passwords**: bcrypt (cost 12), constant-cost dummy-hash anti-enumeration, NIST-style policy.
- **Email tokens**: 256-bit, sha256-at-rest, single-use (atomic), per-purpose TTL, always-200 anti-enumeration.
- **CSRF**: double-submit, enforced on state-changing `/api`+`/auth`; cookie ensured per-session.
- **OAuth/OIDC**: Authorization Code + **PKCE (S256)** + `state` + `nonce`, constant-time compares (RFC 9700).
- **Account-linking invariant** (the headline safety rule, shipped in both reference stores + tested):
  a credential links to an existing user ONLY on a **provider-verified or redemption-proven** email; an
  unverified squatter is refused (`ErrEmailConflict`), never adopted — no cross-provider takeover.

## Quick start (Gin)

```go
cfg := authx.ConfigFromEnv()           // OIDC_*, SESSION_SECRET(>=32B), APP_URL, OWNER_EMAIL, COOKIE_SECURE
authn, _ := authx.New(ctx, cfg)

store, _ := gormstore.New(db)          // reference GORM store (your *gorm.DB)
authn.SetCredentialStore(store)
authn.SetMailer(mailer.FromEnv())      // SMTP_* — enables magic-link/verify/reset
authn.SetAuthorizer(store.Authorizer())// safe identity upsert; wrap to add your own provisioning
authn.SetLocalEnabled(true)            // turn on password/passkey/email (else OIDC-only)

r := gin.New()
r.SetTrustedProxies(authx.TrustedProxies()) // TRUSTED_PROXIES or private-range default
r.Use(authn.Middleware())              // gate + ensure CSRF cookie
r.Use(authn.CSRFMiddleware())          // enforce CSRF on mutations
authn.Register(r)                      // /auth/* endpoints (JSON + ceremonies; NO UI pages)
// ... your routes + your own login/landing UI ...
```

Your app provides the login UI (the original ships a Next.js `(auth)` route set as a reference). The
library serves only JSON + the WebAuthn/OIDC ceremony endpoints under `/auth/*`.

## Framework-agnostic consumption

Handlers are Gin internally, but you don't need Gin to consume the library:

```go
mux := http.NewServeMux()
mux.Handle("/auth/", authn.Handler())                 // mountable http.Handler (net/http, chi, echo)
gated := authn.GateHTTP(authn.CSRFHTTP(appHandler))   // net/http middleware: session gate + CSRF
// in a handler: sub, email, ok := authx.SessionFromRequest(r)
```

The session + CSRF cookies are shared, so a login served by `Handler()` is recognized by `GateHTTP`.

## Social login

Set `GOOGLE_CLIENT_ID/SECRET` and/or `GITHUB_CLIENT_ID/SECRET`; callbacks are
`AppURL + /auth/social/{google,github}/callback`. Google uses OIDC (verified-email id_token + nonce);
GitHub uses REST (`/user` + `/user/emails`, primary+verified required). Identities key on
`(provider, subject)`; a new identity links to a **verified-email** user or creates one, and refuses an
unverified email squatter (`ErrEmailConflict`).

## Status / roadmap

- **Done**: OIDC, password, passkey (incl. QR), magic-link, **social (Google/GitHub)**, **net/http
  adapter** (consume from chi/echo/stdlib), GORM + in-memory reference stores, SMTP mailer.
- **Dropped on extraction** (app-specific): the legacy-IdP admin bridge and branded HTML pages.
- **Follow-ups**: a true zero-Gin handler core (off `*gin.Context`); a squatter-reclaim path; more
  WebAuthn/social ceremony tests.

Tested: `go test ./...` green — session round-trip + tamper, bcrypt, the account-linking takeover
matrix (squatter-refused / bootstrap-adopted / verified-linked), OAuth identity round-trip, and the
net/http adapter.
