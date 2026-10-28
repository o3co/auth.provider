# Your login page

The provider has no login screen of its own. When a browser asks the authorization endpoint without a session fresh enough, the provider sends it to the page you set as `authorize.login-page`, adding `redirect_to`: the URL to come back to. Your page asks for the username and password and makes two requests to the provider. This guide gives each request and answer; it does not prescribe how the page looks.

When the client asked for a new login (`prompt=login`) or a recent one (`max_age`), the provider adds those two beside `redirect_to`. A page that offers sign-in through an upstream hands them on to the upstream's start (`GET /session/oauth/federation/<idp>?redirect_to=…&prompt=login&max_age=…`), so the upstream asks the user to log in again too. A request that comes back from its login still not new enough is refused with `login_required`; it is not sent to the page again.

## Where the page is served

Serve the page from the provider's public origin (`http.public-origin`), for example behind the same reverse proxy. The login is refused unless it carries same-origin evidence (an `Origin` that is the public origin) or the double-submit token, and any cross-origin evidence refuses it; the cookies both requests set belong to that origin. Where the deployment can make cookies secure, a request over plain http is refused.

The page a login through an upstream goes on from, when a second factor holds it (`federation.held-page`), is served from the same origin: `federation` refuses to boot where it is not. See [A login through an upstream that a second factor holds](#a-login-through-an-upstream-that-a-second-factor-holds).

## 1. Get a CSRF token

```http
GET /session/csrf
```

`200`, never cached, with a cookie holding the token and this body:

```json
{
  "csrf_token": "…43 base64url characters…",
  "header_name": "x-csrf-token",
  "body_field": "csrf_token",
  "expires_in": 7200
}
```

A valid token the browser already holds is handed back again, so a form open in another tab stays usable. `expires_in` is in seconds.

## 2. Post the login

```http
POST /session/login
Content-Type: application/x-www-form-urlencoded
X-CSRF-Token: <csrf_token>

username=alice&password=…&redirect_to=<the redirect_to your page received>
```

- The body is a form or JSON, with `username`, `password` and `redirect_to`. Send `redirect_to` as your page received it.
- The token goes in the header the first answer named, or else in the body under `body_field`. The browser sends the cookie with it.
- Send each parameter once: a repeated one is refused.

## 3. Act on the answer

Every answer is never cached.

| Answer | What the page does |
|---|---|
| `200 {"redirect_to": "…"}` | Send the browser to that `redirect_to`, the answer's, not the one you sent. `200 {}` has none to go to. |
| `403` with another body, and cookies | A step after the password holds the login, such as a second factor. The body and cookies are that step's; pass them on as it describes. |
| `401 {"error": "invalid_credentials"}` | Say the sign-in failed. The answer never tells whether the user exists or what was wrong. Where `login-passkey.password = refused-when-held`, a passkey holder's right password is answered the same and counts toward the waits: offer the passkey beside the message. |
| `429 {"error": "too_many_attempts"}` | Wait as `Retry-After` says before trying again. Too many failures for one username make each next try wait; the password is not checked meanwhile. |
| `403 {"error": "csrf"}` | Get a new token, then post again. If it keeps failing, the page is not served from the public origin: a login from another origin is always refused. |
| `400` `invalid_redirect` | The `redirect_to` is not one a login may return to. A login returns to the paths the composed modules let it, such as the authorization endpoint's, written as the public origin and the path exactly (a spelling the URL parser rewrites, such as a dot segment or a backslash, is refused), and to the URLs listed in `login-gates.return-targets`, matched exactly. |
| `400` `invalid_request` or `repeated_parameter` | The request is malformed: fix the page. |
| `415`, with no body | The body is empty, or neither a form nor JSON: fix the page. |
| `503` `temporarily_unavailable` or `service_unavailable` | The provider cannot answer now; try again later. |

After a `200`, the browser holds the session cookie, and the authorization endpoint it returns to goes on to consent or straight to the client.

## Adding passkey login to the app

Passkey login is opt-in: no pattern composes it. Add it when you generate the app, beside your pattern and choices:

```sh
npx @o3co/create-auth-provider my-provider --pattern simple-web --add @mod/login-passkey
```

It brings the passkey store (`passkeys`), the routes a signed-in user registers passkeys with (`passkey-registration`), and WebAuthn (`webauthn`, with its store). Then set:

- `webauthn.rp-id`, `webauthn.rp-name` and `webauthn.origins`: the domain passkeys are bound to (each origin's host, or a domain they lie under), the name an authenticator shows, and the origins your page calls WebAuthn from, matched exactly. The generated README lists them.
- With users from your ledger over HTTP (`--axis @mod/users=@mod/users-http`), `users-http.subject-url`. A passkey names its subject, not a username, so the login looks the user up by subject (`POST {"subject"}`, as the `users-http` card says): without it, every passkey login answers `503`.

What a passkey login changes and the settings that tune it (`login-passkey.counts-as-mfa`, `login-passkey.password`) are in [the runbook](runbook.md#passkey-logins-into-a-session). Two more opt-ins are added the same way, each described there:

- `@mod/passkey-witness-http`, to keep at your ledger which subjects hold a passkey. Refusing passwords of passkey holders needs it ([the runbook](runbook.md#keeping-the-passkey-witness-at-the-ledger)).
- `@mod/passkey-reset`, for an operator to reset a user's passkeys from your own code ([the runbook](runbook.md#resetting-a-subjects-passkeys)).

## A login with a passkey

Where `login-passkey` is composed, the page can offer a passkey beside the password. It makes two requests of its own, both carrying the CSRF token as the password login does.

1. `POST /session/login/passkey/options`, with no body. `200` with WebAuthn request options in JSON (`challenge` in base64url, `rpId`, `userVerification`, `timeout` in milliseconds, and an empty `allowCredentials`), and a cookie naming this browser. Pass them to `navigator.credentials.get({ publicKey })` after decoding the challenge, or give them to a library that does. They ask for a discoverable credential, so `mediation: "conditional"` works: the browser offers the user's passkeys in the username field's autofill.
2. `POST /session/login/passkey` with JSON `{"response": <the credential, as JSON>, "redirect_to": "…"}`: the credential `navigator.credentials.get` answered, serialized as `PublicKeyCredential.toJSON()` writes it (base64url `id`, `rawId`, `response.clientDataJSON`, `response.authenticatorData`, `response.signature`, `response.userHandle`, and `type`).

The options' challenge is good for `webauthn.challenge-lifetime` (2 minutes unless set) and only in the browser that asked: the cookie ties the two. A page that asks options when it loads, for conditional mediation, asks them again before that time runs out, and again after every answer the login gives past the CSRF check and the request count, which ends the challenge whatever it says. A `403 csrf` or a `429` leaves the challenge as it was.

| Answer | What the page does |
|---|---|
| `200 {"redirect_to": "…"}` or `200 {}` | As for a password login. |
| `403` with another body, and cookies | A step after the passkey holds the login, as for a password login. A passkey whose authenticator verified the user proves a second factor too, unless `login-passkey.counts-as-mfa` is false, so that step is rarer. |
| `401 {"error": "passkey_login_failed"}` | Say the sign-in failed, and ask new options before trying again. The answer never tells why: an unknown passkey, a user the ledger does not know, a challenge another browser asked, a revoked session. |
| `429 {"error": "too_many_attempts"}` | Too many requests from this address on that route: wait as `Retry-After` says before trying again. |
| `403 {"error": "csrf"}`, `400` and `503` | As for a password login. |

A user registers passkeys from a signed-in session, through `passkey-registration`'s routes: `/oauth/webauthn/registration/options` and `/oauth/webauthn/registration/verify` register one, and `/oauth/webauthn/registrations`, `/oauth/webauthn/registrations/rename` and `/oauth/webauthn/registrations/remove` list, rename and remove them (see [the routes](routes.md)). Where the operator refuses passwords of users holding a passkey (`login-passkey.password = refused-when-held`), a user who removes their last passkey can sign in by password again, unless the ledger could not answer that removal: their password logins then answer `503` until the operator resets their passkeys. A user who loses every passkey signs in by password only if they are in the exempt group; otherwise the operator resets their passkeys.

## A login through an upstream that a second factor holds

A login through an upstream (`federation`) ends in the upstream's callback, a navigation of the browser rather than a request your page makes. When a second factor holds that login, the provider sends the browser to `federation.held-page` (`303`, with no query). Without that setting the callback answers the held login's `403` JSON, which a browser cannot act on: set it wherever a second factor is composed beside `federation`.

That page goes on with the login:

1. `GET /session/mfa/transaction` with no `MFA-Transaction` header. The browser's cookie names its transaction, and the answer carries `transaction`, `purpose` and `factors`. A `400` means none is in progress, and `401 {"error": "login_required"}` that the user was revoked since it began: start the sign-in again.
2. With `purpose` `login`, prove a factor as the [second-factor recipe](recipe-mfa-page.md) does after a password login: `challenge` where the factor needs one, then `verify`, naming `transaction` in each body. With `enroll-login`, the user has no second factor yet and binds a first one through `enrollment` and `enrollment/complete`, as the recipe's first steps show; `verify` refuses that transaction.
3. Send the browser to the answer's `redirect_to`: where the login was going, else `federation.landing`, else the public origin's root. A first factor bound without a binding proof counts only from the next sign-in: its answer carries the factor, and its recovery codes where recovery codes are composed, but no `redirect_to`, and no session opens, so show any codes, then start the sign-in through the upstream again.

The transaction's identifier never goes in a URL; only this `GET` takes it from the cookie alone.

## Related

- The page a client that is not first-party sends the user to after the login is [your consent page](consent-page.md).
- Each setting named here is in the [configuration reference](configuration.md).
- What the provider guarantees about sessions, cookies and CSRF is in the [security model](security-model.md#browsers-sessions-cookies-and-csrf).
- The module cards of `login-password`, `csrf` and `login-gates` hold the full contract, under `modules/identity/` in the repository, and `login-passkey`'s and `passkey-registration`'s under `modules/passkey/`.
