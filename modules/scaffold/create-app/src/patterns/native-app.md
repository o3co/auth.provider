# native-app

- Use: native and single-page apps as public clients (no secret), by the code flow with PKCE and refresh.
- Composes: simple-web's login and code flow (userinfo included), and DPoP, so a client may bind its tokens to a key it holds.
- The deployment serves the login page (`authorize.login-page`), and the consent page (`consent.page`) only for clients that are not first-party.
- No outside system. A client's back-channel logout goes only to the hosts in `outbound.allow`.
