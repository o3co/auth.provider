# a2a

- Use: services only; no user, session or login. Client credentials and the JWT bearer grant (`jwt-bearer.issuers`), clients by `private_key_jwt` or a secret, tokens bound by mTLS or DPoP.
- Composes both mTLS and DPoP (its `binding` group, which `--binding` replaces); the keys they read, those the deployment must set among them, are in `.env.example` and the configuration reference.
- The deployment provides the proxy that forwards client certificates (`http.client-certificate`), and lets the issuers' and clients' key sets be fetched (`outbound.allow`).
- `--add @mod/token-exchange` also brings refresh, session, session tokens and the code grant; `--add @mod/clients-cimd` brings authorization, consent, acr, the code grant, login gates, session and CSRF, and needs `authorize.login-page`.
- Either brings users, from an outside ledger unless `--axis @mod/users=@mod/users` keeps them in the configuration.
- Federation grants need a login: `--login @mod/login-password --grants @mod/jwt-bearer,@mod/federation-grants` (a group flag replaces the pattern's group).
