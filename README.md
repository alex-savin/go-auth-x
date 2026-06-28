# go-auth-x

**Go Authentication, eXtended** — a self-contained, batteries-included authentication library for
Go web apps. Embed multi-method auth directly in your service with **no separate identity provider
to run**: one signed, HttpOnly session cookie; the browser never sees a token.

[![Go Reference](https://img.shields.io/badge/go-reference-blue)](https://pkg.go.dev/github.com/alex-savin/go-auth-x)
[![Go 1.26+](https://img.shields.io/badge/go-1.26%2B-00ADD8)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](./LICENSE)

```go
import authx "github.com/alex-savin/go-auth-x"
```

> Extracted from a production trading platform's backend-for-frontend (BFF). Passwords, passkeys
> (incl. **cross-device QR**), email magic-links, OIDC, and social login — all behind a single
> `completeLogin` funnel, plus an optional enterprise directory layer (groups, API keys, LDAP, SCIM).

---

## Table of contents

- [Why go-auth-x](#why-go-auth-x)
- [Feature overview](#feature-overview)
- [Install](#install)
- [Quick start](#quick-start)
- [Architecture](#architecture)
- [Configuration](#configuration)
- [Authentication methods](#authentication-methods)
- [HTTP endpoints](#http-endpoints)
- [Directory layer: groups, access control, API keys, LDAP & SCIM](#directory-layer)
- [Storage: reference stores & writing your own](#storage)
- [Security model](#security-model)
- [Framework support (Gin / net/http / chi / echo)](#framework-support)
- [Testing](#testing)
- [Project layout](#project-layout)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Why go-auth-x

Most Go auth options force a choice between two extremes:

1. **Run a separate identity provider** (Keycloak, ORY, Auth0). Powerful, but now you
   operate another service, your passkeys live on a different origin, and simple apps inherit a lot
   of moving parts.
2. **Hand-roll it.** A session cookie here, a bcrypt call there, a WebAuthn ceremony you hope you
   got right — and the account-linking edge cases that cause real takeovers.

go-auth-x is the **middle path: a library you embed**. It runs in your process, authenticates users
**directly** with whatever methods you enable, and hands your app one signed session cookie. Because
it's same-origin, **passkeys (including the phone-scanned QR / cross-device flow) just work** — no
IdP hand-off, no "double login page."

**Use go-auth-x when** you want full-featured auth *inside one Go app* without operating an IdP.
**Use a dedicated IdP when** you need centralized SSO across many separate services.

---

## Feature overview

**Authentication methods**
- 🔑 **Passwords** — bcrypt (cost 12), NIST-style policy, constant-time anti-enumeration.
- 🟢 **Passkeys / WebAuthn** — discoverable (usernameless) login, **cross-device QR** (FIDO2 hybrid),
  clone detection, self-service enrollment & removal.
- ✉️ **Email magic-links** — passwordless sign-in + email verification + password reset, all via
  single-use, hashed-at-rest tokens.
- 🌐 **OIDC client** — Authorization Code + PKCE; consume any OIDC provider (Keycloak, Auth0, …).
- 👥 **Social login** — Google (OIDC) and GitHub (REST), verified-email only.

**Session & transport**
- 🍪 **BFF sessions** — one HMAC-signed (HS256) HttpOnly cookie; the SPA never handles tokens.
- 🛡 **CSRF** — double-submit token, enforced on state-changing requests.
- 🧩 **Framework-agnostic** — mount as an `http.Handler`; net/http middleware for chi/echo/stdlib.

**Directory (optional, enterprise tier)**
- 🗂 **Groups** + per-group **access control** middleware.
- 🔐 **API keys** (Bearer) + an **admin REST API**.
- 🏢 **LDAP** sync and a minimal **SCIM 2.0** provisioning server.

**Operational**
- 🚦 Rate limiting + soft lockout, trusted-proxy-aware client IP.
- 🧪 Reference **GORM** and **in-memory** stores; swap in your own via small interfaces.

---

## Install

```bash
go get github.com/alex-savin/go-auth-x
```

Requires **Go 1.26+**. Sub-packages:

| Import | Purpose |
|---|---|
| `github.com/alex-savin/go-auth-x` | The auth engine (`authx`) |
| `github.com/alex-savin/go-auth-x/store/gormstore` | Reference GORM `CredentialStore` + `DirectoryStore` |
| `github.com/alex-savin/go-auth-x/store/memory` | Zero-dependency in-memory store (tests/demos) |
| `github.com/alex-savin/go-auth-x/mailer` | SMTP (STARTTLS) `Mailer` |
| `github.com/alex-savin/go-auth-x/ldapsync` | LDAP/AD → directory sync |
| `github.com/alex-savin/go-auth-x/scim` | SCIM 2.0 provisioning server |

---

## Quick start

### With Gin

```go
package main

import (
	"context"
	"log"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	authx "github.com/alex-savin/go-auth-x"
	"github.com/alex-savin/go-auth-x/mailer"
	"github.com/alex-savin/go-auth-x/store/gormstore"
)

func main() {
	db, _ := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	store, _ := gormstore.New(db) // migrates the authx_* tables

	cfg := authx.ConfigFromEnv() // SESSION_SECRET (>=32B), APP_URL, OWNER_EMAIL, OIDC_*, GOOGLE_*, ...
	authn, err := authx.New(context.Background(), cfg)
	if err != nil {
		log.Fatal(err)
	}
	authn.SetCredentialStore(store)
	authn.SetDirectoryStore(store)     // optional: groups / API keys / admin API
	authn.SetMailer(mailer.FromEnv())  // optional: enables magic-link / verify / reset
	authn.SetAuthorizer(store.Authorizer()) // safe identity upsert (wrap to add provisioning)
	authn.SetLocalEnabled(true)        // turn on password + passkey + email

	r := gin.New()
	_ = r.SetTrustedProxies(authx.TrustedProxies())
	r.Use(authn.Middleware())     // gate every route + ensure CSRF cookie
	r.Use(authn.CSRFMiddleware()) // enforce CSRF on mutations
	authn.Register(r)             // mounts /auth/* (JSON + ceremony endpoints; you own the UI)

	// your routes; gate sensitive ones by group:
	r.GET("/admin", authn.RequireGroups("admins"), adminHandler)

	r.Run(":8080")
}
```

### With net/http / chi / echo

```go
mux := http.NewServeMux()
mux.Handle("/auth/", authn.Handler())                  // /auth/* as a standard http.Handler
mux.Handle("/scim/v2/", http.StripPrefix("/scim/v2",   // optional SCIM provisioning
	scim.NewServer(store, func(t string) bool { _, ok := authn.ValidateAPIKey(t); return ok }).Handler()))

// gate your own routes:
app := authn.GateHTTP(authn.CSRFHTTP(yourHandler))
http.ListenAndServe(":8080", app)

// inside a handler:
sub, email, ok := authx.SessionFromRequest(r)
groups := authx.GroupsFromRequest(r)
```

> **You provide the login UI.** The library serves JSON + the WebAuthn/OIDC ceremony endpoints under
> `/auth/*`; your app renders the login/register pages and calls them (see [HTTP endpoints](#http-endpoints)).

---

## Architecture

go-auth-x is a **backend-for-frontend**. The single-page app talks only to your backend; the backend
holds all secrets and issues one signed cookie.

```
 Browser/SPA                 Your Go app (go-auth-x embedded)              External
 ┌──────────┐   cookie       ┌───────────────────────────────┐
 │  /login  │ ─────────────► │  Middleware (gate + CSRF)      │
 │  /app    │ ◄───────────── │  /auth/* handlers ──┐          │
 └──────────┘  sweep_session │                     ▼          │           ┌────────────┐
                             │   completeLogin()  ── Authorizer hook ────►│ provisioning│
                             │     │  (every method funnels here)         └────────────┘
                             │     ├─ CredentialStore  (persist users/creds)  ┌──────────┐
                             │     ├─ DirectoryStore   (groups/API keys) ────►│ Postgres │
                             │     └─ Mailer           (magic-links) ─────────│  / LDAP  │
                             │   OIDC / Google / GitHub clients ──────────────┤  / SMTP  │
                             └───────────────────────────────┘                └──────────┘
```

**The funnel.** Password, passkey, magic-link, OIDC, and social logins all end in **one**
`completeLogin` — which runs the `Authorizer`, enriches the session with the user's groups, mints the
cookie, and issues a CSRF token. No method can mint a session that skips your provisioning or the
disabled/verified gates.

**The seams** (all small interfaces, so you control storage and policy):

| Interface | Responsibility | Reference impl |
|---|---|---|
| `CredentialStore` | persist users, passwords, passkeys, tokens, OAuth identities | `gormstore`, `memory` |
| `Authorizer` | post-login hook: identity upsert (+ your provisioning) | `store.Authorizer()` |
| `Mailer` | send auth emails | `mailer` (SMTP) |
| `DirectoryStore` *(optional)* | groups, membership, API keys, admin user mgmt | `gormstore`, `memory` |

---

## Configuration

`authx.ConfigFromEnv()` reads the environment; or build `authx.Config{}` yourself. Local methods are
turned on with `SetLocalEnabled(true)`; email methods activate when a `Mailer` is set; each social
provider activates when its client id + secret are present.

| Env var | Config field | Notes |
|---|---|---|
| `SESSION_SECRET` | `SessionSecret` | **Required, ≥ 32 bytes.** HMAC key for the session/flow/CSRF cookies. |
| `APP_URL` | `AppURL` | Public origin, e.g. `https://app.example.com`. Used for email links + redirects. |
| `OWNER_EMAIL` | `OwnerEmail` | Exempt from hard lockout; gates the admin API via session. |
| `COOKIE_SECURE` | `CookieSecure` | Force the `Secure` flag (also auto-on under TLS / `X-Forwarded-Proto: https`). |
| `OIDC_ISSUER` | `Issuer` | Enables the OIDC client (with `OIDC_CLIENT_ID`). |
| `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | `ClientID` / `ClientSecret` | Confidential OIDC client. |
| `OIDC_REDIRECT_URL` | `RedirectURL` | e.g. `https://app.example.com/auth/callback`. |
| `OIDC_ALLOWED_GROUPS` | `AllowedGroups` | Comma-sep allow-list; empty = any authenticated user. |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | `GoogleClientID` / `…Secret` | Enables Google login. |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | `GitHubClientID` / `…Secret` | Enables GitHub login. |
| `TRUSTED_PROXIES` | — (`authx.TrustedProxies()`) | CSV of proxy CIDRs; default = private ranges + loopback. |
| `WEBAUTHN_RPID` / `WEBAUTHN_RP_NAME` | — | Override the passkey relying-party id/name (default: app host). |
| `SMTP_HOST` `SMTP_PORT` `SMTP_USER` `SMTP_PASS` `SMTP_FROM` | — (`mailer.FromEnv()`) | STARTTLS sender. |

Boot **fails closed** if auth is active and `SESSION_SECRET` is shorter than 32 bytes.

---

## Authentication methods

### Passwords
`POST /auth/password/signup` → creates an unverified user and emails a verification link.
`POST /auth/password/login` → verifies bcrypt, requires a verified email, mints the session. NIST-style
policy (length + breach/email-localpart checks), constant-cost dummy-hash on unknown users to defeat
enumeration, and a transparent rehash path via a stored algorithm tag.

### Passkeys / WebAuthn (incl. cross-device QR)
Same-origin WebAuthn — no IdP hop. **Registration requires a discoverable (resident) credential and
does not pin `authenticatorAttachment`**, so an enrolled passkey works passwordless *and* cross-device.
**Login is discoverable (usernameless)**, which is exactly what makes the browser offer "use a phone
or tablet" → a **QR code** (FIDO2 hybrid transport). Sign-count **clone detection** rejects copied
authenticators. Challenges live in a short-lived signed cookie; the relying-party id is fixed config.

### Email magic-links
`POST /auth/email/request` emails a one-time sign-in link; `GET /auth/email/login` redeems it (and marks
the email verified). Same machinery powers email verification and password reset. All tokens are 256-bit,
**sha256-at-rest**, **single-use** (atomic redemption), per-purpose TTL, with always-200 anti-enumeration.

### OIDC
`GET /auth/login` runs Authorization Code + **PKCE (S256)** with `state` + `nonce`; `GET /auth/callback`
verifies the id_token, enforces `OIDC_ALLOWED_GROUPS`, and funnels into `completeLogin`. `state`/`nonce`
are compared in constant time (OAuth 2.0 Security BCP / RFC 9700).

### Social (Google & GitHub)
`GET /auth/social/{google,github}/login`. Google uses OIDC (verified-email id_token + nonce); GitHub uses
REST (`/user` + `/user/emails`, primary+verified required). Identities key on **(provider, subject)**; a
new identity links to a **verified-email** user or creates one, and **refuses an unverified email
squatter** (see [account-linking invariant](#account-linking-invariant)).

---

## HTTP endpoints

Mounted by `Register` (Gin) or `Handler()` (net/http) under `/auth`:

| Method | Path | Purpose | Auth |
|---|---|---|---|
| GET | `/auth/login` · `/auth/callback` | OIDC start / callback | public |
| GET | `/auth/logout` · `/auth/me` · `/auth/config` | logout / session info / enabled methods | public |
| POST | `/auth/password/signup` · `/auth/password/login` | password signup / login | public |
| POST | `/auth/password/reset/request` · `/auth/password/reset/confirm` | password reset | public |
| POST | `/auth/email/request` | request a magic-link | public |
| GET | `/auth/email/login` · `/auth/email/verify` | redeem magic-link / verify email | token |
| POST | `/auth/webauthn/login/begin` · `/auth/webauthn/login/finish` | passkey sign-in (discoverable / QR) | public |
| POST | `/auth/webauthn/register/begin` · `/auth/webauthn/register/finish` | enroll a passkey | session |
| GET | `/auth/social/:provider/login` · `/auth/social/:provider/callback` | Google / GitHub | public |
| GET | `/auth/api/account` | account + passkeys | session |
| POST | `/auth/api/account/password` | set/change password | session + CSRF |
| DELETE | `/auth/api/passkeys/:id` | remove a passkey | session + CSRF |

---

## Directory layer

Optional. Wire `SetDirectoryStore(store)` to enable groups, access control, API keys, the admin REST
API, and the LDAP/SCIM integrations.

### Groups & access control
Groups are first-class and **surfaced in the session at login**. Gate routes by group membership —
for sessions *and* API keys:

```go
r.GET("/reports", authn.RequireGroups("analysts", "admins"), reportsHandler) // Gin
mux.Handle("/reports", authn.RequireGroupsHTTP("analysts")(reportsHandler))   // net/http
```

### API keys
`axk_`-prefixed, **sha256-at-rest**, with optional expiry + groups. The `Authorization: Bearer <key>`
header is authenticated by `APIKeyAuth()` (Gin) or validated via `authn.ValidateAPIKey(raw)`. CSRF is
correctly **skipped** for Bearer requests (not cookie-based). The raw key is shown **once** at creation.

### Admin REST API (`/auth/admin`)
Gated by an **owner session** (`OWNER_EMAIL`) **or** a valid API key:

| Method | Path | Purpose |
|---|---|---|
| GET / POST | `/auth/admin/groups` | list / create groups |
| DELETE | `/auth/admin/groups/:id` | delete a group |
| GET | `/auth/admin/groups/:id/members` | list members |
| POST / DELETE | `/auth/admin/groups/:id/members/:userId` | add / remove a member |
| GET | `/auth/admin/users` | list users |
| POST | `/auth/admin/users/:id/disabled` | disable / enable a user |
| GET / POST | `/auth/admin/apikeys` | list / create keys (create returns the raw key once) |
| DELETE | `/auth/admin/apikeys/:id` | revoke a key |

### LDAP sync
One-way scheduled pull of users + groups + membership from LDAP/Active Directory:

```go
syncer := ldapsync.New(ldapsync.Config{
	URL: "ldaps://ldap.example.com", BindDN: "...", BindPassword: "...",
	UserBaseDN: "ou=people,dc=example,dc=com", GroupBaseDN: "ou=groups,dc=example,dc=com",
	// AD: AttrUID:"sAMAccountName", GroupFilter:"(objectClass=group)", AttrGroupMember:"member"
}, store)
result, err := syncer.Sync() // run on a schedule
```

### SCIM 2.0
A mountable provisioning server so an upstream IdP (Okta, Entra/Azure AD, JumpCloud) can push and
deprovision Users + Groups. Supports create / read / list (`userName eq` filter) / **PATCH deprovision
(`active=false`)** / delete, plus `ServiceProviderConfig` / `ResourceTypes` / `Schemas`. Bearer-auth via
`ValidateAPIKey`. *(Pragmatic v0 — no PUT-replace / complex filters / bulk.)*

```go
mux.Handle("/scim/v2/", http.StripPrefix("/scim/v2",
	scim.NewServer(store, func(t string) bool { _, ok := authn.ValidateAPIKey(t); return ok }).Handler()))
```

---

## Storage

go-auth-x ships two reference stores; both implement `CredentialStore` **and** `DirectoryStore`:

- **`gormstore`** — Postgres/SQLite via GORM. `New(db)` migrates self-contained `authx_*` tables
  (so it won't collide with yours) and adds a unique-email index. Ships the **safe verified-email
  linking rule** and a reference `Authorizer`.
- **`memory`** — zero-dependency, in-process. Great for tests, demos, and single-process apps; state
  is lost on restart and not shared across replicas.

**Bring your own:** implement `CredentialStore` (and optionally `DirectoryStore`) over your database.
The interfaces are deliberately small and return storage-agnostic DTOs, so `authx` never imports your
ORM. Compile-time conformance: `var _ authx.CredentialStore = (*MyStore)(nil)`.

---

## Security model

- **Sessions** — HS256-signed cookie; **alg-confusion pinned** (rejects `alg:none`/non-HMAC); `exp`/`iat`
  enforced; rotated on every login. Remember-me extends the TTL (12 h → 30 d).
- **CSRF** — double-submit token (`X-CSRF-Token` ↔ `sweep_csrf` cookie), constant-time compare, enforced
  on non-GET `/api` + `/auth`; ensured per-session in the gate; skipped for Bearer (API-key) requests.
- **Passwords** — bcrypt cost 12; NIST-style policy; constant-cost dummy-hash anti-enumeration; rehash tag.
- **Tokens** (magic-link / verify / reset) — 256-bit `crypto/rand`, sha256-at-rest, single-use (atomic),
  per-purpose TTL, always-200 anti-enumeration.
- **Passkeys** — fixed `rpID`/origin (never host-inferred), signed challenge cookie, **clone detection**.
- **OAuth/OIDC** — Authorization Code + **PKCE (S256)** + `state` + `nonce`, constant-time compares.
- **Rate limiting** — sliding-window per-IP + soft per-account lockout (durable counts; recovery paths
  stay open; owner exempt).
- **Trusted proxies** — `SetTrustedProxies(authx.TrustedProxies())` so `X-Forwarded-For` can't be spoofed
  to defeat per-IP limits.

### Account-linking invariant
The single most important rule, shipped in both reference stores and **covered by tests**: a credential
or social identity links to an existing user **only** on a **provider-verified or redemption-proven
email**. An unverified, non-bootstrap "squatter" row is **refused** (`ErrEmailConflict`), never adopted —
which prevents the classic cross-provider account takeover (attacker pre-registers `victim@x`, victim
later logs in and inherits the attacker's credentials).

---

## Framework support

- **Gin** — first-class: `Register(r)`, `Middleware()`, `CSRFMiddleware()`, `RequireGroups()`, `APIKeyAuth()`.
- **net/http / chi / echo** — `Handler()` (mount `/auth/*`), `GateHTTP` / `CSRFHTTP` (middleware),
  `SessionFromRequest` / `GroupsFromRequest`, `RequireGroupsHTTP`. The SCIM server is pure net/http.

> Handlers are Gin internally and Gin is a transitive dependency; a true zero-Gin handler core is on the
> [roadmap](#roadmap). Today, non-Gin apps integrate fully via the net/http adapter above.

---

## Testing

```bash
go test ./...
```

Covers: session mint/parse + tamper rejection, bcrypt, the **account-linking takeover matrix**
(squatter-refused / bootstrap-adopted / verified-linked), OAuth-identity round-trip, the net/http
adapter, the directory store + API-key auth + `RequireGroups` allow/deny, and the **SCIM user lifecycle**
(provision → filter → deprovision). The reference stores carry compile-time interface assertions.

---

## Project layout

```
go-auth-x/
├── *.go                  authx engine: session, password, webauthn, magic-link, oidc, social,
│                         csrf, ratelimit, middleware, http adapter, directory, admin
├── store/
│   ├── gormstore/        reference GORM CredentialStore + DirectoryStore (+ linking rule)
│   └── memory/           zero-dependency in-memory store
├── mailer/               SMTP (STARTTLS) Mailer
├── ldapsync/             LDAP/AD → directory sync
├── scim/                 SCIM 2.0 provisioning server
├── LICENSE               MIT
└── README.md
```

---

## Roadmap

- **Done**: OIDC, password, passkey (+ QR), magic-link, social (Google/GitHub), net/http adapter,
  GORM + in-memory stores, SMTP mailer, groups + per-group access control, API keys + admin REST API,
  LDAP sync, minimal SCIM 2.0.
- **Planned**: a true **zero-Gin** handler core; **Apple + Facebook** social; a squatter-reclaim path;
  fuller SCIM (PUT, richer filters) + LDAP deprovision-by-absence; per-API-key fine-grained scopes.

---

## Contributing

Issues and PRs welcome. Please run `go test ./...` and `go vet ./...` before submitting, and keep the
storage-agnostic boundary intact (the `authx` package must not import a specific ORM or framework beyond
the documented Gin handlers). New auth methods should funnel through `completeLogin` and respect the
account-linking invariant.

---

## License

[MIT](./LICENSE) © 2026 Alex Savin.
