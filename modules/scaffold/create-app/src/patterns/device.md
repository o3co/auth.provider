# device

- Use: devices without a browser or a keyboard; the user approves a code on another screen. Also the code flow with refresh. Client credentials only added (`--add @mod/client-credentials`): without it, a client allowed `client_credentials` refuses boot.
- Composes: simple-web's login and code flow (userinfo included), and the device authorization grant with the verification interface its page calls (`POST /oauth/device/verification`); the page itself is the deployment's.
- The deployment serves the login page (`authorize.login-page`), the consent page (`consent.page`) only for clients that are not first-party, and the page where users enter and approve the code, named by `device-grant.verification-uri`.
- No outside system. A client's back-channel logout goes only to the hosts in `outbound.allow`.
