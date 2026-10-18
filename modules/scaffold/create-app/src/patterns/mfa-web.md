# mfa-web

- Use: a web login by password with a second factor (TOTP, a code by email, recovery codes); the code flow with refresh, and client credentials.
- Composes: simple-web's login and code flow (userinfo included), the second factor and its flows (enrolment, login, reset, lock release), and the acr it meets.
- Its store is in Redis: losing it loses the registered factors.
- Factors are sealed with the `seal` key ring (`seal.current`, and `seal.previous` while one rotates).
- Whether a second factor is required: `mfa.mode`.
- The deployment serves the login page (`authorize.login-page`), the page that raises authentication (`authorize.step-up-page`), and the consent page (`consent.page`) only for clients that are not first-party.
