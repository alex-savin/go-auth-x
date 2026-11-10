# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.14.0] — 2026-11-10

A security release. A second review, of v0.13.0, found ways to get another user's OAuth tokens, to
become the instance owner through SCIM or an unproven signup, and to keep access after removal from a
group; all are fixed here, each with a regression test. **Upgrade promptly.** Several fixes change
behavior callers can notice — see "Behavior changes" below; the one most deployments will meet is
that **API keys need the new `app` scope** to pass `GateHTTP` / `RequireGroupsHTTP`.

### Security

- **`oidcprovider` handed a request's code to anyone who knew its id** — `{Prefix}/authorize/callback`
  checked only that the request was approved. Whoever starts a request knows its id: someone with no
  session could start one with their own PKCE verifier, send a signed-in user its link, let them
  approve what is a genuine client (or nothing at all, with no consent screen), then fetch the code
  from the callback and redeem it — tokens for that user. The callback now issues the code only in a
  session of the user who signed in for the request (never an impersonation session), and once per
  request (asking again used to mint another valid code).
- **gormstore returned membership-row ids as user and group ids** — `GroupMembers`, `UserGroups` and
  `UserOrgGroups` joined without selecting columns, so the membership row's `id` was scanned into the
  result. On gormstore, removing a member through SCIM (PUT, PATCH `remove`, PATCH `replace`) answered
  200 and removed nobody, or someone else; SCIM and the admin API reported the wrong member ids.
- **The global SCIM mount verified an unproven signup** — an IdP that found someone's signup under a
  user's address (its create answers 409, so it matches by filter and replaces) marked the row
  verified with the signup's password still on it, which then signed in — as the owner, for
  `OWNER_EMAIL`. A replace no longer verifies anything.
- **A `scim`-scoped key could still become the instance owner** — moving a SCIM account's email kept
  its sessions and credentials and arrived verified: sign in to an account of your own, move it onto
  an unregistered `OWNER_EMAIL`, and the session was the owner's. A provisioning source (SCIM, LDAP
  sync) that moves an account to another address now hands over an account nothing signs in to: its
  sessions end and its password, passkeys, linked providers, TOTP, pending links and OAuth grants are
  removed, in the same write.
- **A signup in flight could outlive the mailbox proof** — signup read "unverified", hashed the
  password, and wrote it unconditionally; if the address's owner opened their verify link, magic link
  or code in between, the signup's password landed on the verified account. The write is now
  conditional on the account still being unverified, and a mailbox proof verifies and drops the
  unproven password in one step.
- **Sign-in failed open on store errors** — the funnel discarded the error of its one read of the
  user and treated any TOTP read error as "no second factor": during a database hiccup a password
  alone signed in to a TOTP account, a banned user got through the OIDC callback, and the lockout
  lapsed. Only "not found" now means absent; any other error ends the sign-in. Adding a factor and
  restarting TOTP enrollment fail closed the same way.
- **Open redirect after sign-in** — `next=/./\evil.example` passed the check (only the second byte
  was inspected) and `http.Redirect`'s path cleaning turned it into `/\evil.example`, which browsers
  read as `//evil.example`: reachable through `/auth/login?next=` and through a genuine magic link
  mailed with an attacker's `next`. The target is cleaned before it is validated, and a backslash
  anywhere is refused.
- **A pending email change outlived the account's recovery** — the confirm link needed only its
  token: someone with a stolen password could ask for the change, wait out the owner's password
  reset, and open the link with no session. It is now confirmed in a browser signed in to the
  account, and a password reset or change or signing out the other sessions cancels it.
- **Lower severity** — a magic or verify link signs in only the account it was mailed for (not
  another that holds the address since); signup sets its cookie for registered addresses too (its
  absence told them apart); display names are capped (a 6 KB name chosen at signup made every later
  session cookie too large for a browser to keep); every `/auth` body is capped at 1 MiB, including
  the WebAuthn ceremonies and `form_post` callbacks a library reads; a sign-in attempt for something
  that isn't an address writes no audit row.
- **Impersonation sessions could change the account** — the marker was enforced only by the admin
  API and the OAuth login step. An impersonated user with no password or TOTP has no step-up, so the
  session could set a password and sign in again as the user, unmarked (as the owner, for the
  owner's account); it could also delete the account, change its email, add factors, and manage its
  orgs, all audited as the user's own actions. Under `/auth` an impersonation session now only
  reads, switches the active org and ends itself; `oidcprovider`'s consent endpoint refuses it too.
  An impersonation started with an admin key is attributed to the key, not to a session cookie
  sent along.
- **A password-only step-up let a session replace TOTP** — a passkey completes the second-factor
  step, and adding one took any step-up: with a stolen session and the password, never a code,
  someone could add their own passkey and use it instead of the TOTP from then on. A TOTP user now
  steps up with a code (or recovery code) to add a sign-in method, checked at passkey enrolment's
  finish as well as its start.
- **An operator's password reset left the account signed in** — `POST /auth/admin/users/{id}/password`
  revoked nothing, and no reset ended the user's OAuth grants. The user's reset, the operator's
  reset and the operator's session revoke now end the account's sessions, its OAuth grants and a
  pending change of address.
- **The app's gate let any API key through** — `GateHTTP` and `RequireGroupsHTTP` admitted every
  valid global key, whatever its scopes: the `scim` key handed to an IdP, or a key with none, reached
  every gated route of the app. A key is a principal there only with the new `app` scope
  (`authx.ScopeApp`) or `*`.
- **API keys and the owner** — an admin key could mint a wider key that never expires, and could
  ban, disable, delete, re-password or impersonate the owner. A key now mints only scopes it has
  and no later expiry than its own, and the owner's account is changed only from an owner session.
- **Org admins could grant the app's own roles** — only the literal `owner` role was protected, so
  an admin could give themselves, a member or an invited address a role the app gates like the
  owner's (the README's own `billing`). Roles other than `admin` and `member` are an owner's to
  grant, unless `Config.OrgAdminMayGrant` says otherwise; an invite is re-checked the same way when
  it is accepted.
- **Lower severity** — `ban` and `disabled` refuse a body without their flag (a malformed one read
  as `false` and lifted the ban) and answer 404 for an unknown user; a group membership can't be
  made for a user or group that doesn't exist (the next account with that id inherited it), and the
  global group verbs refuse an org's groups; a banned or disabled manager's pending invites grant
  nothing; a sole owner can't leave an org ownerless by deleting their account; a key that
  authorizes nothing no longer switches CSRF off for a session cookie sent with it; every
  state-changing admin call is audited with who made it.
- **SCIM acknowledged deprovisions that failed** — `PATCH active=false` (what Entra and Okta send)
  and a create with `active:false` answered 200/201 when the store write failed, and a failed group
  member removal was only logged: the IdP never retried, and the leaver kept their account or
  group. These now answer 5xx. (A failed member *add* stays best-effort and logged.)
- **The global `scim` scope reached accounts SCIM didn't provision** — a scim-only key could disable
  the owner's local account, and a replace that left `active` out re-enabled an account an operator
  had disabled. SCIM activates and deactivates only accounts it provisioned; a replace without
  `active` leaves the state alone. (Groups remain fully writable by the scope — see the README.)
- **LDAP sync never removed a group membership** — a user taken out of an LDAP group, or whose
  group left the directory, kept the directory group and what it gates. Memberships of synced users
  that LDAP no longer lists are now removed (`Config.KeepStaleMemberships` restores the old
  behavior).
- **LDAP: a shared uid re-pointed an account** — the account `ldap:<uid>` followed whichever entry
  came last, so an entry able to set its own uid attribute to an administrator's moved that account
  onto its own mailbox. A uid found on more than one entry is synced from none and reported.
- **Lower severity** — a SCIM create for a userName that already has an account is a 409 (it
  re-pointed the account, past `If-Match`); a group PATCH this server can't apply is a 400, not a
  silent 200, and `members[value ne "1"]` no longer removes user 1; the SCIM mount refuses an empty
  or non-Bearer token before its validator sees it; LDAP DNs are normalized without unescaping
  (`cn=a\,ou\=b` is not `cn=a,ou=b`).
- **`oidcprovider` told callers why a client lookup failed** — on the token endpoint a
  metadata-document `client_id` such as `https://db.internal/x` was answered with "db.internal
  resolves to 10.0.0.5, which is not public": an oracle for internal hostnames. A failed lookup is
  now a bare `invalid_client`; the reason is logged.
- **`oidcprovider` stored unbounded authorization requests** — anyone who knew a client id could
  have `/authorize` keep megabytes of `state` per request, unthrottled, until an hourly clean-up.
  Parameters are capped, requests are limited per address, and unfinished ones are removed within
  minutes of expiring.
- **Lower severity (`oidcprovider`)** — `/revoke` no longer acts on the store's own keys (a refresh
  token's hash or an access token's row id, what a copy of the database holds, revoked grants); a
  signing key stored in the clear is ignored unless `AcceptPlaintextKeys` asks for it (one written
  row planted a signing key); `ReplaceKeys` drops retired keys at once after a leak (`RotateKeys`
  keeps them trusted for `KeyGrace`); a client's self-declared name and links are stored without
  markup characters; the metadata no longer advertises RP-initiated logout or client assertions the
  provider doesn't do. Reference stores: reclaiming an unverified account ends its sessions
  (gormstore) and removes its OAuth records (both), as deleting it does.
- **The owner's password had no failed-attempt threshold** — exempt from the lockout, it was
  guessable at the per-IP rate from every address an attacker has (and from one, wherever a client
  on a private network picks its own `X-Forwarded-For`). The owner's password login now pauses
  after 30 failures in 15 minutes when a mailer is configured (the link and reset paths stay open);
  without one the owner is still never locked out.
- **Lower severity** — sign-out is available as `POST /auth/logout` with the CSRF token, and `GET`
  can be turned off (any page could sign a user out); cookies can be sent under `__Host-` names
  (opt-in), which a sibling subdomain can't plant; the change-of-address request mails off the
  request path (its duration told a taken address from a free one); the SMTP sender has a deadline;
  logout clears the step-up cookie; the default trusted proxies include the IPv6 private range.
- **A social sign-in replaced provisioned accounts** — a provider-verified email that matched an
  unverified account an org's SCIM (or SCIM, or LDAP) had provisioned deleted it like a signup
  squatter's and made a new one: the person lost their org and group memberships, and the IdP could
  no longer update or deprovision them. Such an account is now kept — verified, linked, with nothing
  that signs in carried over. A self-signup's unverified row is still replaced.
- **A disconnected provider reconnected itself** — the "disconnected" record was spent by the first
  reconnect and could not be made again, so after a second disconnect the provider linked back by
  email; and reconnecting was any visit to the provider's login in a signed-in browser, which any
  page can cause. The record now stays, and reconnecting takes
  `POST /auth/api/identities/{provider}/connect` (session + CSRF) first.
- **Lower severity** — emails are keyed without folding a non-ASCII letter into an ASCII one
  (`vİctim@x.com` was `victim@x.com`; `authx.NormalizeEmail`, used by both stores); Microsoft's
  consumer tenant given by its id is treated as the multi-tenant endpoint it is; a login flow is
  finished only at the provider it was started with; a WebAuthn challenge is single-use (a captured
  finish request replayed within five minutes signed in again); a banned or disabled user's cookie
  drives no account endpoint even without a `SessionStore`; a TOTP code checked by `/auth/reauth`
  draws on the same attempt budget as `/auth/2fa/verify`; recovery codes are stored before TOTP is
  switched on; an org invite's mailbox proof drops an unproven password like a sign-in link's; API
  key groups and scopes can't contain a comma or whitespace.

### Behavior changes

- `oidcprovider`: `{Prefix}/authorize/callback` answers 403 without the session of the user who
  signed in for the request, and 400 once the request's code was issued. Send the user's browser to
  the URL `Approve` returns (as the README has it); a server-side fetch of it no longer works.
- Global SCIM: `PUT /Users/{id}` never marks an account verified.
- SCIM and LDAP sync: changing the email of an account they provisioned signs it out and removes its
  sign-in methods (see above). Its user signs in through the IdP, or proves the new mailbox by link,
  code or password reset. The account's id and its group and org memberships stay.
- gormstore: `GroupMembers`, `UserGroups` and `UserOrgGroups` return the users' and groups' own ids.
- The email-change link (`GET /auth/email/change`) must be opened in a browser signed in to the
  account; otherwise it redirects to `/login?…&next=` back to itself, unspent.
- A store error during sign-in is a failed sign-in (`500`), where it used to be read as "no such
  user" / "no second factor".
- Display names are cut to 128 characters at signup and in session cookies; passkey labels to 64.
- An impersonation session gets `403` on every state-changing `/auth` endpoint except
  `stop-impersonating`, `org/switch` and the sign-in entry points.
- A user with TOTP re-authenticates with a code (`POST /auth/reauth {"code":…}`) before adding a
  passkey or a first password; a password-only step-up answers `403 reauth_required` there.
- A password reset (the user's or an operator's) and `POST /auth/admin/users/{id}/sessions/revoke`
  also end the user's `oidcprovider` grants.
- **API keys need the `app` scope to pass `GateHTTP` / `RequireGroupsHTTP`.** Add `"app"` to the
  scopes of keys that call your own gated routes; keys with only `admin`, `scim` or no scope stop
  passing (their groups stop counting too).
- A key minting a key (`POST /auth/admin/apikeys`) is refused scopes it lacks (`403`) and an expiry
  later than its own; a key it mints without an expiry gets the minter's. Org-bound keys keep their
  free choice of scopes.
- An admin key gets `403` on `disabled`, `ban`, `password`, `impersonate` and `DELETE` for the
  owner's account.
- An org admin gets `403` granting or inviting with a custom role (set `Config.OrgAdminMayGrant` to
  allow some).
- `POST /auth/admin/users/{id}/ban` and `/disabled` require `banned` / `disabled` in the body
  (`400` otherwise) and answer `404` for an unknown user; the global group-member verbs answer
  `404` for an unknown user or an org's group.
- `DELETE /auth/api/account` answers `409` for the sole owner of an organization.
- gormstore: `AddUserToGroup` returns `ErrNoUser` / `ErrNoGroup` for ids that name no row; the
  batch form skips such users.
- Global SCIM: `DELETE`, `PATCH active` and a `PUT` that changes `active` answer `400 mutability`
  for an account SCIM didn't provision; a `PUT` without `active` no longer reactivates. Per-org SCIM
  (`NewOrgScopedDirectory`) is unchanged: deactivating there removes the member from the org.
- SCIM: a failed deactivation or member removal answers `500`; `POST /Users` with an existing
  userName answers `409`; unsupported group PATCH forms answer `400`.
- ldapsync removes memberships LDAP no longer lists (synced `ldap:` users only; not when the user or
  group search comes back empty) and skips a uid that several entries share. `Result.Removed`
  counts the removals.
- `oidcprovider`: `/authorize` answers `400` for oversized parameters (`state` over 2048 bytes,
  `nonce` over 512, …) and `429` past 120 requests per address in 10 minutes; a failed client lookup
  is always `invalid_client`; `/revoke` with something that isn't a bearer value revokes nothing;
  `end_session_endpoint`, `claims_supported` and the client-assertion algorithms are gone from the
  metadata.
- `oidcprovider`: a signing key stored unsealed (a database last used before v0.11) is ignored and
  replaced unless `Config.AcceptPlaintextKeys` is set for the first start.
- The owner's password login answers `429` after 30 failed attempts in 15 minutes when a mailer is
  configured.
- The default `TRUSTED_PROXIES` also trusts `fc00::/7`.
- Reconnecting a provider the user disconnected: `POST /auth/api/identities/{provider}/connect`,
  then send the browser to the `next` it returns. Visiting the provider's login while signed in no
  longer reconnects it (`409`).
- A social sign-in on a provider-verified email that matches an unverified SCIM- or LDAP-provisioned
  account signs in to that account (it used to be replaced by a new one).
- `MICROSOFT_TENANT=9188040d-6c67-4c5b-b112-36a304b66dad` (personal accounts) is refused like
  `consumers`.
- Email addresses with a letter that Unicode lower-cases to ASCII (`İ`, the Kelvin sign) are no
  longer the same account as their ASCII look-alike. Custom stores should key emails with
  `authx.NormalizeEmail`.

### Added

- `SignupStore` — an optional `CredentialStore` upgrade (`SetPasswordHashIfUnverified`,
  `VerifyEmailKeepingPassword`) that makes the signup write and the mailbox proof atomic on every
  replica; both reference stores implement it. A store without it is covered within one process (the
  `Authenticator` serializes the two).
- Store contract: `UpsertExternalUser` moving an existing account to another email must remove what
  signs in to it and end its sessions (documented on `DirectoryStore`; both reference stores do).
- `TokenRevoker` — an optional `CredentialStore` upgrade (`DeleteTokens(purpose, userID)`), used to
  cancel pending email changes; both reference stores implement it.
- `authx.ScopeApp` (`"app"`), `Config.OrgAdminMayGrant`.
- An audit row (`method` `admin`, the route as the action, the actor as the detail) for every
  state-changing admin API call.
- `ldapsync.Config`: `KeepStaleMemberships`, `OwnGroupsOnly` (leave same-named groups the sync
  didn't create alone) and `MaxDeprovision` (cap on users one run may disable).
- `oidcprovider`: `Provider.ReplaceKeys`, `Config.AcceptPlaintextKeys`.
- `POST /auth/logout`; `Config.DisableGetLogout` (`LOGOUT_POST_ONLY`).
- `Config.HostCookies` (`COOKIE_HOST_PREFIX`): `__Host-` cookie names, needs an https `APP_URL`;
  `Authenticator.CSRFCookieName()` and `csrfCookie` in `GET /auth/config`.
- `POST /auth/api/identities/{provider}/connect`; `authx.NormalizeEmail`.
- `SECURITY.md` (how to report a vulnerability); Dependabot for Go modules and workflow actions;
  workflow actions pinned to commits; the release job runs the race detector and govulncheck.

### Fixed

- Documentation: the README's admin API table lists the `/auth/admin/orgs` routes, its install
  table the `oidcprovider` package; the API-key scopes, the gate's fixed public paths, what the
  `scim` scope can do, and the limits of sessions without a `SessionStore` are spelled out; the
  claims that `X-Forwarded-For` "can't be spoofed" and that metadata fetches follow https redirects
  are corrected.
- `examples/demo`: `/api/notes` verifies an OAuth access token for the resource it advertises, and
  encodes its answer as JSON.

### Known limitations

- `oidcprovider`: presenting an already-used authorization code or refresh token ends its grant
  without client authentication (RFC 6749 §4.1.2, OAuth Security BCP): someone who finds a spent
  code in a log can't get tokens, but can end that connection.
- `oidcprovider`: a user can still be led to approve an authorization request someone else started;
  the code then goes only to the client's registered redirect, in the user's own browser.
- Without a `SessionStore`, sessions are stateless: logout, a password reset, a ban and deleting the
  account don't end a cookie someone already holds.

## [0.13.0] — 2026-11-09

A security release. An audit (seven independent reviews, every finding proven with a test) found
account-takeover and privilege-escalation paths in v0.12.1 and earlier; all are fixed here, each with a
regression test. **Upgrade promptly.** Several fixes change behavior callers can notice — see
"Behavior changes" below.

### Security

- **Signup squatting** — a password set by an unproven signup survived the real owner's sign-in by
  magic link, email code or verify link, letting whoever signed up first log in (as the instance owner,
  for `OWNER_EMAIL`). A mailbox proof now drops a password nobody proved; the verify link keeps it only
  in the browser that signed up with it. Signup never touches a bootstrap placeholder.
- **Provisioning sources asserting identities** — a customer's per-org SCIM could mark any address
  verified and re-point accounts' emails (cross-tenant takeover, global admin); a `scim`-scoped key on
  the global mount could re-point the owner's email and take it over through password reset. The org
  view never verifies an address and can't re-point a mailbox-proven account; the global mount only
  re-points emails of accounts SCIM provisioned; a changed email is no longer "verified"; reset links
  die when the account leaves the address; `ValidateAPIKey` refuses org-bound keys (the README's global
  SCIM wiring now uses `ValidateAPIKeyScope(t, "scim")`).
- **Owner check** — the owner is the live, verified account with `OWNER_EMAIL`, compared exactly (a
  Unicode case-fold alias like `opſ@` passed before), not the email a cookie was minted with.
- **OIDC callback** — it bypassed the login funnel: banned/disabled users signed in, TOTP was never
  asked. It now goes through `completeLogin` (which itself refuses blocked users).
- **OIDC email trust** — `OIDC_ASSUME_VERIFIED` overrode an explicit `email_verified: false`, and logins
  without an email seized each other's accounts. The flag now fills only an absent claim; an empty
  email is never verified or used to link; IdP subjects in the library's namespaces (`scim:`, `ldap:`,
  `local:`, …) are refused; a generic provider's `preferred_username` never stands in for an email.
- **2FA from a stolen session** — `/auth/2fa/totp/confirm` on an enabled TOTP was an unthrottled code
  oracle that minted new recovery codes; enrolling TOTP or a passkey, or setting a first password,
  needed only a session. Confirm refuses an enabled TOTP and is throttled; adding a factor takes a
  fresh step-up when the user has one.
- **Sessions outliving account changes** — a password reset or change, SCIM/LDAP deprovisioning,
  removal from a group, and an account rebound to a new subject all left sessions live. Resets revoke
  all sessions, changes all but the current one; disabling/banning revokes inside the reference stores;
  `RequireGroupsHTTP` re-reads directory groups live; rebinding moves sessions and OAuth records.
- **LDAP sync** took over verified local accounts (and deleted unverified ones) by email — now skipped
  and reported unless `Config.AdoptExisting`.
- **SCIM `/Bulk`** could nest itself (any path spelling) — one sub-1 MiB request pinned gigabytes of
  heap; malformed operations panicked. Nesting is refused, malformed operations are per-op 400s, group
  filters load members once, filters are capped at 4 KiB.
- **OAuth endpoints' CORS** — `oidcprovider` kept zitadel's default policy, which echoes any `Origin`
  back with `Access-Control-Allow-Credentials: true` on every endpoint under the prefix. Any origin may
  still call them (`*`), never with the user's cookies. (Found by the new ZAP scan; `SameSite=Lax`
  session cookies limited it to same-site origins.)
- **Client IP** — only the first `X-Forwarded-For` line was read and `ip:port` entries became their own
  rate-limit keys; every line is walked now, ports stripped.
- **Lower severity** — logins no longer write back stale user rows (a concurrent ban or deletion
  survived as undone); CIMD fetches follow no redirect; a junk `Authorization` header no longer skips
  CSRF; the gate decides on the cleaned path; email-code checks, signup mail, password-change checks
  and 2FA disable are throttled per account/address; org ids are canonical (no `01` alias past the
  last-owner guard), the acting member's role is re-read under the lock, and invites die with their
  inviter's privilege; changing to a taken email no longer reveals it; a disconnected social provider
  doesn't re-link by email until reconnected while signed in; RP-initiated logout revokes no grants;
  impersonation sessions can't approve OAuth grants; cookies are `Secure` when `APP_URL` is https.

### Behavior changes

- Verify links opened in another browser drop the signup's password (the user sets one after).
- Adding TOTP, a passkey or a first password needs a fresh step-up when the user already has a
  password or TOTP (`403 reauth_required`).
- A password change signs the user's other sessions out; a reset signs out all of them.
- Per-org SCIM accounts stay unverified until their user proves the mailbox; a verified account's email
  can't be changed through the org view, and it can't be re-added after leaving (use an invite).
- The global SCIM mount refuses (`400 mutability`) email changes of accounts it didn't provision; a
  deprovisioning PUT only deprovisions.
- `ValidateAPIKey` refuses org-bound keys.
- OIDC: an explicit `email_verified: false` is refused even with `OIDC_ASSUME_VERIFIED`; subjects
  starting `local:`, `bootstrap:`, `scim:`, `ldap:` or `social:` are refused; TOTP users get the
  second-factor step.
- `oidcprovider`: `Approve` grants `offline_access` only when `Decision.Scopes` includes it (or is nil).
- Changing to a taken email answers 200 (the address's owner is emailed instead of the caller told).
- ldapsync needs `AdoptExisting: true` to take over accounts it didn't create.
- Cookies are `Secure` whenever `APP_URL` is https.

### Added

- `Identity.Local` (a login read from the store; Authorizers shouldn't write its email back),
  `ldapsync.Config.AdoptExisting`, `SessionClaims.AuthTime`/`DirGroups` are populated as described above.
- Store contracts: `SetPasswordHash` with an empty hash removes the password; a store that implements
  `SessionStore` should revoke a user's sessions when `SetUserDisabled(true)`/`SetUserBan(true)`, and
  move them when it rebinds a subject (both reference stores do). gormstore's unique email index becomes
  partial (`email <> ''`), migrated automatically.

### Known limitations

- A customer's per-org SCIM learns whether an address has an account anywhere from the 409 a duplicate
  gets (provisioning can't create a second account for an address); rate-limit or monitor org keys.
- Token introspection answers any authenticated client about a token it holds.

## [0.12.1] — 2026-11-09

A runnable demo, and security scanning in CI: govulncheck and OWASP ZAP. No library code changed.

### Added

- `examples/demo`: a runnable server wiring every surface against the in-memory store.
- CI: a `security` workflow — govulncheck (moved from the lint job) and an OWASP ZAP scan of the
  demo: a passive baseline on every change, a full active scan weekly and on demand. Rules in
  `.zap/rules.tsv`; reports are uploaded as workflow artifacts, not opened as issues.

## [0.12.0] — 2026-11-07

`prompt=login` / `max_age` in the `oidcprovider`, OAuth records that go with the user, private email
logs, updated dependencies, and CI on every pull request.

### Added

- **`oidcprovider` honors `prompt=login` and `max_age`.** The login step used to accept any
  existing session; a client asking for a fresh sign-in now gets one. A session signed in before
  the request (`prompt=login`, or `max_age=0`) or longer ago than `max_age` is sent to the new
  `Config.ReauthURL` (default `LoginURL`) to sign in again; coming back still stale fails with
  `login_required` rather than looping, as does `prompt=none`. `OAuthAuthRequest.MaxAge` stores the
  request's `max_age` (both reference stores persist it).
- **`SessionClaims.AuthTime`** — the session cookie's `auth_time` claim: when the user signed in.
  Unlike `iat`, a re-mint that isn't a sign-in (switching the active org) keeps it. Cookies minted
  before it existed have none, and count as not fresh for `prompt=login` / `max_age`.
- **`Provider.RevokeUser(ctx, subject)`** — ends every grant of a user ("disconnect all apps", or
  account deletion with a store that doesn't remove OAuth records itself).

### Fixed

- **Deleting an account removes the user's `oidcprovider` records** — grants, the tokens issued
  under them, and auth requests in flight — in both reference stores (keyed by the user's subject).
  They were left behind; since v0.11 they couldn't be used, but they were kept. A custom store that
  implements both `CredentialStore` and `OAuthStore` should do the same (documented on `DeleteUser`).
- **Grants left without any token are cleaned up** — a grant with no end date whose refresh tokens
  had all expired could never issue again, yet stayed forever. `DeleteExpiredOAuth` now also
  removes grants with no token left (created before `requestsBefore`); both reference stores do.
- **ID tokens' `auth_time` is the sign-in time**, from the session's `auth_time`, instead of the
  time the user approved the consent screen; refreshed ID tokens keep it.

### Changed

- **Auth emails no longer log the recipient's address** — a failure logs it masked
  (`a***@example.com`) at Error, a successful send only at Debug (it was Info, unmasked).

- **Dependencies updated** — `golang.org/x/crypto` v0.58.0 (clears three advisories in `x/crypto/ssh`,
  none reachable from this module; the remaining one, the unmaintained `openpgp` package, isn't
  imported and has no tagged fix), `go-ntlmssp` v0.1.1 (via `go-ldap`), `go-jose` v4.1.9,
  `zitadel/oidc` v3.51.17, `go-oidc` v3.21.0, `go-ldap` v3.4.15, `go-webauthn` v0.18.2, and the
  test-only SQLite driver.
- **CI** — every pull request and push to `main` runs gofmt, a tidy-`go.mod` check, vet,
  `go test -race` on Go 1.26.x and the current release, staticcheck and govulncheck.

## [0.11.0] — 2026-11-07

Security hardening of the `oidcprovider` from a review of v0.9–v0.10.1, and a fix that makes
`/userinfo`, `/introspect` and access-token revocation work for go-auth-x users.

### Security

- **`oidcprovider`: no silent approval of self-registered clients.** With no consent screen
  (`ConsentURL` nil) the login step approved *any* client, so with `Registration` or
  `ClientMetadataDocuments` on, anyone could register a client and receive a signed-in user's code
  by sending them an `/authorize` link. `New` now refuses a nil `ConsentURL` with either option, and
  without a consent screen only clients the app registered (`RegisterClient`) are approved — a
  dynamic client (one left in the store from an earlier configuration, say) is refused with
  `access_denied`.
- **`oidcprovider`: authorization codes are single-use across replicas.** Single use was tracked
  per process, and zitadel deletes the request only after minting the tokens, so two replicas could
  both redeem one code. A grant's ID is now derived from its code, so the store's unique ID refuses
  the second exchange on any replica; a code presented again ends the grant it made (RFC 6749
  §4.1.2). Single use is spent only by an exchange that passed client and PKCE checks, so a code
  stolen without its verifier can no longer be burned — and the per-process map of used codes
  (which unauthenticated junk codes could grow) is gone. `OAuthStore.CreateOAuthGrant` must refuse
  an existing ID (both reference stores do; a primary key does it).
- **`oidcprovider`: access tokens end with their user.** `Verify`, `/userinfo` and `/introspect`
  now share one check — token live, grant neither revoked nor past its end, user still allowed to
  sign in — so a disabled, banned or deleted user's tokens stop at once instead of at expiry, and
  `/userinfo` no longer serves a token whose grant was revoked.
- **`oidcprovider`: metadata-document fetches are throttled.** Anyone could make the provider fetch
  a fresh URL with every `/authorize`; fetches the cache can't answer are now limited per address
  (30 an hour; being limited is not cached against the document), and concurrent lookups of one
  document share a single fetch.
- **`oidcprovider`: signing keys are sealed at rest** with AES-GCM under a key derived (HKDF) from
  `CryptoKey`, bound to the key's id, so a copy of the store alone can't forge ID tokens. Keys stored
  in the clear by v0.10 load as before and are sealed by the next key upkeep. A key this
  `CryptoKey` can't open is ignored with a warning, and deleted once it would have expired anyway;
  changing `CryptoKey` therefore replaces the signing keys (as it already ended access tokens).
- **`oidcprovider`: the registration limit keys IPv6 by /64**, like the built-in limiters, so
  rotating addresses within one /64 no longer dodges it.

### Fixed

- **`oidcprovider`: `/userinfo`, `/introspect` and access-token revocation work for go-auth-x
  subjects.** zitadel splits a decrypted access token (`id:subject`) on every colon and wants two
  parts; go-auth-x subjects (`local:…`, `google:…`) have one more, so userinfo answered 401 for
  every user, introspection reported every token inactive, and a client revoking an access token got
  a 200 while the token kept working. The token's wire format is unchanged — tokens already issued
  keep working.
- **`oidcprovider`: a narrowed refresh keeps the grant's scopes.** A refresh asking for fewer scopes
  narrowed the new refresh token too, losing the rest for good; the access token is narrowed, the
  refresh token keeps the presented one's scopes (RFC 6749 §6).
- **`oidcprovider`: `New` no longer rewrites the caller's `Config.Resources`** slice while
  normalizing it.

### Added

- **`authx.RateLimitKey`** — normalizes a client IP into a rate-limit key the way the built-in
  limiters do (IPv6 by /64), for limiters outside the package.

## [0.10.1] — 2026-11-05

### Fixed

- **`oidcprovider`: a client naming a grant type the provider does not offer is no longer
  refused** when it also names the authorization code or refresh tokens. The extra grant is left
  out: a client metadata document's client gets the code (and refresh tokens when it asks), and a
  dynamic registration's response lists what it got (RFC 7591 lets the server replace what was
  asked). claude.ai's client metadata lists `urn:ietf:params:oauth:grant-type:jwt-bearer` beside
  the code, so its connectors failed at `/authorize` with "unable to retrieve client by id". A
  client asking only for grants not offered is still refused.

## [0.10.0] — 2026-10-29

### Added

- **Signing-key rotation (`oidcprovider`)** — the provider's clean-up replaces the ID-token signing
  key when it is older than `Config.KeyRotation` (default 90 days; negative = never) and retires
  the previous one, which stays in the JWKS for `Config.KeyGrace` (default 24 hours, never less than
  an ID token's life plus five minutes) and is then deleted. Only the newest key not retired signs.
  Each replica reads the keys from the store again every five minutes, so a rotation done by one
  replica reaches the others; two replicas rotating at once leave one extra, retired key, which is
  harmless. `Provider.RotateKeys` forces a rotation (e.g. after a suspected leak).
- **Client ID Metadata Documents (`oidcprovider`)** — with `Config.ClientMetadataDocuments`, a
  client may use an https URL as its `client_id` (MCP authorization spec 2025-11-25,
  draft-ietf-oauth-client-id-metadata-document). The provider fetches the document there, checks
  it (its `client_id` must be the URL exactly; redirect URIs as for dynamic registration; public
  clients only — `token_endpoint_auth_method` `none`), and treats it as a dynamic public client
  with PKCE. Documents are cached in memory (`Cache-Control` max-age held to 5 minutes – 24 hours,
  default 1 hour; at most 1000 entries) and never stored. Discovery advertises
  `client_id_metadata_document_supported`. The fetch is guarded against SSRF: only public
  addresses (no private, loopback, link-local, CGNAT, multicast or special-purpose ranges, IPv4 or
  IPv6, IPv4-mapped included), the connection is pinned to the checked address (no DNS
  rebinding), no proxy, https-only redirects (at most 3), JSON only, 64 KB, 5 seconds.
- **`OAuthStore.RetireOAuthSigningKey` / `DeleteOAuthSigningKey`** — store-interface addition for
  key rotation, implemented by both reference stores. A custom `OAuthStore` must add the two
  methods. Retiring an already retired key keeps its first time.

### Changed

- **`oidcprovider` signing keys are re-read from the store periodically** (every five minutes, and
  at each clean-up) instead of only at `New`, so replicas see each other's keys.

## [0.9.0] — 2026-10-28

### Added

- **Embeddable OAuth 2.1 / OIDC provider (`oidcprovider`)** — an app embedding go-auth-x can issue
  tokens to other programs: satellite services, or AI assistants' connectors following the MCP
  authorization spec. Built on `zitadel/oidc` (codes, PKCE, refresh, signing, discovery) behind an
  authx facade: `oidcprovider.New(ctx, Config{Issuer, Auth, Store, CryptoKey, …})`, then mount
  `Handler()` on `Patterns()`. What it adds:
  - The user signs in with the go-auth-x session. Consent is the app's own screen
    (`Config.ConsentURL`, then `Pending` / `Approve` / `Deny`), or JSON endpoints at
    `{Prefix}/consent`.
  - RFC 8414 metadata at `/.well-known/oauth-authorization-server`.
  - Optional dynamic client registration (RFC 7591), limited per address, with unused clients
    expiring.
  - RFC 8707 resource indicators bind tokens to a resource (`VerifyFor`).
  - Clients that may refresh get refresh tokens without asking for `offline_access`.
  - `DefaultScopes` for requests that name no scope.
  - PKCE is required for public clients, S256 only.
  - Access tokens are opaque (`Verify`). Refresh tokens rotate and are single-use: replaying one
    ends its grant (OAuth Security BCP).
  - `Decision.Ref` ties a grant to the app's own record, and `RevokeRef` ends it.
- **`OAuthStore`** — the provider's storage interface (clients, auth requests, grants, access and
  refresh tokens, signing keys; secrets kept as hashes), implemented by both reference stores
  (`gormstore` migrates `authx_oauth_*` tables).
- **`Authenticator.SessionOf`, `UserBySub` (+ `ErrUserBlocked`), `ClientIP`, `CSRFValid`** — public
  accessors for handlers outside `/auth` and `GateHTTP`.
- **Pluggable logger (`log/slog`)** — `Config.Logger` and `Authenticator.SetLogger` route the
  library's internal warnings and errors (the `SESSION_SECRET` / `TRUSTED_PROXIES` / Microsoft
  multi-tenant warnings, failed auth emails, admin-API store errors) to any `*slog.Logger`. Nil =
  `slog.Default()`, resolved at log time, so a later `slog.SetDefault` is honored and the zero-value
  `Authenticator` stays valid. Set `Config.Logger` (not `SetLogger`) to capture the warnings `New`
  itself emits. The SCIM server gains `Server.SetLogger` for its internal errors and incomplete
  membership writes.
- **Batch group membership** — an optional `BatchGroupStore` upgrade interface (`AddUsersToGroup` /
  `RemoveUsersFromGroup`, detected by type assertion — custom `DirectoryStore`s keep compiling), plus
  `authx.AddGroupMembers` / `authx.RemoveGroupMembers`, which use it when present and otherwise fall
  back member by member. Both are best-effort per member: an id that names no user is skipped, never
  failing the batch. Both reference stores implement it — `gormstore` with chunked
  `INSERT … ON CONFLICT DO NOTHING` / `DELETE … IN` (500 rows per statement), `memory` under one lock.

### Changed

- **SCIM group syncs batch their membership writes** — group create / `PUT` / `PATCH` issue one
  membership write per change instead of one per member. A write that fails is now logged at Warn
  (previously dropped silently); the response still reflects the membership actually stored.
- **Org-scoped SCIM group syncs are no longer N+1** (the v0.7 review note) — the per-customer view
  checks group ownership once per change instead of per member, and validates membership with one
  member-list read for batches of 16+ ids (per-id lookups below that, so a one-member `PATCH` on a
  large org stays cheap). The trust boundary is unchanged: only the org's own group, only its members.
- **Log output** moved from `log.Printf` to leveled, structured `slog` records — the `WARNING` prefix
  became the level, and values ride as attributes (`min_bytes`, `tenant`, `subject`, `to`, `group`,
  `error`). With no logger configured, output still goes through the standard `log` package (slog's
  default handler). Update any log scraping that matched the old text.

## [0.8.0] — 2026-07-16

### Changed — BREAKING

- **Public entity IDs are now opaque `string`s** across every store interface (issue #2). `AuthUser.ID`,
  `Group.ID`, `APIKeyInfo.ID`, `Passkey.ID`, `OrgInvite.ID`, `TokenClaim.UserID`, and
  `SessionRecord.UserID` changed from `uint` to `string`, and every `CredentialStore` /
  `DirectoryStore` / `TwoFactorStore` / `SessionStore` / `OrgStore` / `OrgDirectoryStore` method that
  took or returned a `uint` id now uses `string`. IDs are treated as opaque — the auth package never
  parses or does arithmetic on them — so a store keyed by uuid/ULID/KSUID passes its IDs straight
  through. Empty (`""`) is the reserved "no user" sentinel (e.g. a pre-resolution audit row).
  - **Migration for consumers of the reference stores: none.** `gormstore` keeps its `uint` primary
    keys and converts to/from decimal strings at its boundary — **no database migration**, IDs render
    identically (`"1"`, `"2"`, …). `memory` likewise keeps `uint` keys internally.
  - **Migration for custom store implementers:** change your method signatures to the `string` id
    types (the compiler points at each one) and treat an unparseable/unknown id as the method's
    documented miss (`ErrNoUser` / `ErrNoGroup` / a no-op delete) rather than coercing it to a real
    key. SCIM member `value`s and the `{id}` path segment are now passed through verbatim.

## [0.7.0] — 2026-07-16

Org-scoped resources — the enterprise slice on top of the v0.6 org core, unlocking per-customer SCIM.

### Added

- **First-class invite records** — org invites became listable + revocable `OrgInvite` records:
  `GET /auth/org/invites` lists pending invites and `DELETE /auth/org/invites/{id}` revokes one;
  re-inviting an address replaces its pending invite. The org + role bind to the stored RECORD (not
  the URL), so nothing in the accept link can be tampered with; a failed invitation email leaves the
  valid, listable record in place to resend/revoke rather than deleting it.
- **Org-scoped groups and API keys** via the optional `OrgDirectoryStore` upgrade interface (detected
  by type assertion; a `DirectoryStore` that doesn't implement it keeps compiling — the features just
  501):
  - **Org-scoped groups** — `Group.OrgID` ("" = global); names unique per (org, name), so two orgs
    both own "engineering". The GLOBAL verbs (`Groups`/`GroupByName`) never see them, and they
    never ride in the session cookie (names collide across orgs) — **`RequireOrgGroupsHTTP`** gates
    on LIVE org-group membership in the active org instead. Org membership removal cascades the
    member out of the org's groups. Admin CRUD under `/auth/admin/orgs/{id}/groups`.
  - **Org-bound API keys** — `APIKeyInfo.OrgID`; minted via the admin API (`POST /auth/admin/apikeys`
    with `"org"`). An org-bound key is refused by EVERY global surface — `adminGuard` (even with the
    `admin` scope), `ValidateAPIKeyScope`, group merging, `GateHTTP`, and the empty-groups
    `RequireGroupsHTTP` — and only satisfies the new **`ValidateOrgAPIKeyScope(raw, scope, orgID)`**
    for its own org.
- **Org-scoped SCIM** — **`NewOrgScopedDirectory(dir, orgs, orgID)`** wraps a `DirectoryStore` in a
  view confined to one org, mountable per customer with `scim.NewServer` + an org-bound key. The
  trust boundary is enforced in the view: provisioned subjects are **namespaced per org** (two
  customers' "jdoe" are two accounts), an existing outside account's email/identity is **never
  adopted or rebound** (`ErrEmailConflict` → SCIM 409 — existing users join via the consent-based
  invite flow), deprovision (`active=false`/DELETE) **removes the user from the org** — never the
  global account — and org owners can't be deprovisioned by a customer IdP.

### Fixed / Security

- **SCIM server hardening** — `PATCH`/`PUT /Users/{id}` no longer dereference a post-update refetch
  miss (an org-scoped deprovision removes the user from view mid-request); an owner-deprovision
  refusal renders as **403** (not a silent 200 that fakes offboarding, nor a retryable 500), and
  group `PUT`/`PATCH`/`DELETE` on an out-of-scope id returns **404** instead of fabricating a 200/500.
- **Cross-tenant takeover closed** (adversarial review) — the org-scoped view never rebinds the
  global identity of an account its org's IdP didn't provision, so a customer IdP's SCIM `PUT` can no
  longer rewrite an invited member's login email (verified, no mailbox proof).

## [0.6.0] — 2026-07-16

Organizations (tenant/org layer) — a first-class org concept for B2B-shaped apps.

### Added

- **Organizations.** A fourth optional capability store, `OrgStore` (wire with `SetOrgStore`; nil =
  feature off, zero behavior change), implemented by both reference stores:
  - **Model** — `Org` + per-org role memberships (reserved `owner`/`admin`/`member`, app-extensible).
    Users stay global (one account, many orgs); email uniqueness and the safe account-linking rule are
    untouched. Org IDs are **opaque strings** — the reference stores keep numeric PKs and convert at
    the boundary.
  - **Sessions** — additive `org`/`orgRole` claims carry the ACTIVE org only (a sole membership is
    auto-activated at login; several = none until the app switches). `POST /auth/org/switch` re-mints
    the cookie after a live membership check, preserving SID and remaining lifetime. `/auth/me` gains
    `org`, `orgRole` (live), and `orgs`; `/auth/config` reports `orgs`.
  - **`RequireOrgHTTP(roles...)`** middleware — re-verifies membership/role against the store per
    request, so an org removal or demotion takes effect immediately instead of at cookie expiry.
  - **Email invites** — `POST /auth/org/invites` (owner/admin; only owners may invite owners) emails a
    single-use, hashed-at-rest token bound to org + role, redeemed through the login funnel. Accepting
    requires a session whose email MATCHES the invited address; the wrong account can't burn the token
    (peek-before-consume), and redemption marks the email verified. (Invites become listable/revocable
    first-class records in v0.7.0.)
  - **Self-service member management** — `GET/POST/DELETE /auth/org/members[/{userId}]` with a
    serialized last-owner guard (can't demote/remove the final owner) and self-removal (leave).
  - **Admin verbs** — org CRUD + membership under `/auth/admin/orgs` (admin API deliberately bypasses
    the last-owner guard as the recovery path).
  - **GDPR parity** — `DeleteUser` cascades org memberships (and pending invites to the erased email);
    `DeleteOrg` cascades its memberships.

## [0.5.1] — 2026-07-15

Follow-up hardening from a post-merge review of v0.5.0.

### Fixed

- **A lost `RecordSession` write at login now fails the login** rather than minting a session the
  fail-closed revocation check would reject on its next request ("logged in, then instantly logged
  out"). Sessions are recorded *before* the cookie is issued, at every mint site.
- **`adminSetBan` now writes an audit record** (`ban` / `unban`), matching the other admin verbs.
- **Passwordless (social/OIDC-only) users can delete their account and change email.** Those endpoints
  no longer demand a step-up re-auth that a user with no password or TOTP can never satisfy — it was a
  permanent lockout. Users who *do* have a re-authable factor still require step-up.

### Security

- **`Sec-Fetch-Site: cross-site` requests are refused** on the CSRF-token-exempt login entry points
  (e.g. `/auth/email-otp/verify`), closing a cross-site login-CSRF even when no `TrustedOrigins`/`AppURL`
  allow-list is configured (Fetch Metadata; a missing or non-cross-site value is unaffected, so no
  legitimate same-origin request breaks).

### Changed

- The in-memory `SessionStore` prunes expired rows on write and is documented as **demo / single-process
  only** — because an unknown SID fails closed, a process restart (which empties the map) logs every
  outstanding user out; use `gormstore` (or another durable `SessionStore`) for anything that restarts
  or scales.

### Migration (from v0.5.0)

- A **social-login-only** deployment now enforces the gate + CSRF (`enforcing()` counts configured
  social providers — the fix for a gate that previously no-op'd while login still minted sessions). If
  your app made state-changing `POST /api/...` calls without the double-submit CSRF token, it must now
  send the `X-CSRF-Token` header.

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

[Unreleased]: https://github.com/alex-savin/go-auth-x/compare/v0.14.0...HEAD
[0.14.0]: https://github.com/alex-savin/go-auth-x/releases/tag/v0.14.0
[0.13.0]: https://github.com/alex-savin/go-auth-x/releases/tag/v0.13.0
[0.12.1]: https://github.com/alex-savin/go-auth-x/releases/tag/v0.12.1
[0.12.0]: https://github.com/alex-savin/go-auth-x/releases/tag/v0.12.0
[0.11.0]: https://github.com/alex-savin/go-auth-x/releases/tag/v0.11.0
[0.10.1]: https://github.com/alex-savin/go-auth-x/releases/tag/v0.10.1
[0.10.0]: https://github.com/alex-savin/go-auth-x/releases/tag/v0.10.0
[0.9.0]: https://github.com/alex-savin/go-auth-x/releases/tag/v0.9.0
[0.8.0]: https://github.com/alex-savin/go-auth-x/releases/tag/v0.8.0
[0.7.0]: https://github.com/alex-savin/go-auth-x/releases/tag/v0.7.0
[0.6.0]: https://github.com/alex-savin/go-auth-x/releases/tag/v0.6.0
[0.5.1]: https://github.com/alex-savin/go-auth-x/releases/tag/v0.5.1
[0.5.0]: https://github.com/alex-savin/go-auth-x/releases/tag/v0.5.0
[0.4.1]: https://github.com/alex-savin/go-auth-x/releases/tag/v0.4.1
[0.4.0]: https://github.com/alex-savin/go-auth-x/releases/tag/v0.4.0
[0.3.0]: https://github.com/alex-savin/go-auth-x/releases/tag/v0.3.0
[0.2.0]: https://github.com/alex-savin/go-auth-x/releases/tag/v0.2.0
[0.1.1]: https://github.com/alex-savin/go-auth-x/releases/tag/v0.1.1
[0.1.0]: https://github.com/alex-savin/go-auth-x/releases/tag/v0.1.0
[#1]: https://github.com/alex-savin/go-auth-x/issues/1
[#3]: https://github.com/alex-savin/go-auth-x/issues/3
[#4]: https://github.com/alex-savin/go-auth-x/issues/4
