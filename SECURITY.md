# Security policy

## Reporting a vulnerability

Please report security issues privately, not in a public issue or pull request: use GitHub's
**Report a vulnerability** button on the repository's *Security* tab
(https://github.com/alex-savin/go-auth-x/security/advisories/new).

Include what you found, how to reproduce it (a failing test is ideal), and the version or commit.
You should get an answer within a few days. Fixes are released with a regression test and a
`### Security` entry in [CHANGELOG.md](./CHANGELOG.md); a GitHub Security Advisory is published for
anything that lets someone sign in as, or act as, somebody else.

## Supported versions

go-auth-x is pre-1.0: security fixes go into the latest release only. Upgrade to it — the
CHANGELOG's "Behavior changes" lists what an upgrade can affect.

## What to expect of the library

The [Security model](./README.md#security-model) section of the README states what the library
defends against and what it leaves to the application (among them: row-level isolation of your own
data, the consent screen's rendering, and ending sessions when no `SessionStore` is wired).
