# device

- Use: devices without a browser or a keyboard; the user approves a code on another screen. Also the code flow with refresh, and client credentials.
- Composes: simple-web's login and code flow (userinfo included), and the device authorization grant with its approval page.
- The deployment serves the login page (`authorize.login-page`), the consent page (`consent.page`) only for clients that are not first-party, and names where users enter the code (`device-grant.verification-uri`).
- No outside system. A client's back-channel logout goes only to the hosts in `outbound.allow`.
