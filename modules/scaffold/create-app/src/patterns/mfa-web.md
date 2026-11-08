# mfa-web

- Use: a web login by password with a second factor (TOTP and recovery codes; a code by email is added, `--add @mod/mfa-email`, and counts as one only where its `adds-second-factor` is set); the code flow with refresh. Client credentials only added (`--add @mod/client-credentials`): without it, a client allowed `client_credentials` refuses boot.
- Composes: simple-web's login and code flow (userinfo included), the second factor and its flows (enrolment, login, reset, lock release), the proof of the account's address mailed before a first binding, a session's management of its own factors, and the acr it meets.
- Its store is in Redis: losing it loses the registered factors.
- Whether a second factor is required: `mfa.mode`.
- The deployment serves the login page (`authorize.login-page`), the page that raises authentication, and the consent page (`consent.page`) only for clients that are not first-party.
