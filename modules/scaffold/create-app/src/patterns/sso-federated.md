# sso-federated

- Use: single sign-on through upstream identity providers, with no password of its own; the code flow with refresh, and client credentials.
- Composes: federation with OpenID Connect, Google, GitHub and Apple, its upstream tokens, logout (a client's too, sent on upstream), authorization, consent, OpenID Connect with its userinfo, and refresh.
- The providers are named in `federation.idps`. Users come from an outside ledger; `--axis @mod/users=@mod/users` lists them in the configuration instead. A password login is not composed: `--login` replaces this group, so it lists the federation modules with `@mod/login-password`.
- The deployment serves the login page that offers the providers (`authorize.login-page`), and the consent page (`consent.page`) only for clients that are not first-party; the providers and the ledger are reached through `outbound.allow`.
- Not composed unless added: `--add @mod/subject-revocation-http` lets the ledger revoke a subject here too (`POST /ledger/subject-revocations`), sent from its `sources` with its `credential`; it boots only behind a proxy named in `http.trusted-proxies`, which tells a request as https.
