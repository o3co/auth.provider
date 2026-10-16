# simple-web

- Use: a web login by password; clients use the code flow with refresh, services client credentials.
- Composes: the login and its session, logout (a client's too), authorization, consent, OpenID Connect with its userinfo, refresh, and the token endpoint with introspection and revocation.
- The deployment serves the login page (`authorize.login-page`), and the consent page (`consent.page`) only for clients that are not first-party.
- No outside system. A client's back-channel logout goes only to the hosts in `outbound.allow`.
