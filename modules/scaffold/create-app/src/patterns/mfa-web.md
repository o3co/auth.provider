# mfa-web

- Use: a web login by password with a second factor (TOTP and recovery codes, and a code by email, which counts as one only where mfa-email's `adds-second-factor` is set); the code flow with refresh. Client credentials only added (`--add @mod/client-credentials`): without it, a client allowed `client_credentials` refuses boot.
- Composes: simple-web's login and code flow (userinfo included), the second factor and its flows (enrolment, login, reset, lock release), a session's management of its own factors, and the acr it meets.
- Its store is in Redis: losing it loses the registered factors.
- Factors are sealed with the `seal` key ring (`seal.current`, and `seal.previous` while one rotates).
- Whether a second factor is required: `mfa.mode`.
- The deployment serves the login page (`authorize.login-page`), the page that raises authentication (`authorize.step-up-page`), and the consent page (`consent.page`) only for clients that are not first-party.
- Users are listed in `users.registered`, which no example holds: write it in the local layer.
