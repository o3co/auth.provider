# simple-web

- Use: a web login by password; clients use the code flow with refresh. Services that use client credentials add it (`--add @mod/client-credentials`): without it, a client allowed `client_credentials` refuses boot.
- Composes: the login and its session, logout (a client's too), authorization, consent, OpenID Connect with its userinfo, refresh, and the token endpoint with introspection and revocation.
- The deployment serves the login page (`authorize.login-page`), and the consent page (`consent.page`) only for clients that are not first-party.
- With its default axes, no outside system; another `--axis` brings its own, as "Store, users, audit and mail" below says. A client's back-channel logout goes only to the hosts in `outbound.allow`.
- With the default users axis, users are listed in `users.registered`, which no example holds: write it in the local layer. With a user ledger (`--axis @mod/users=@mod/users-http`), write none: boot refuses both.
