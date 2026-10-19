# Your login page

The provider has no login screen of its own. When a browser asks the authorization endpoint without a session fresh enough, the provider sends it to the page you set as `authorize.login-page`, adding `redirect_to`: the URL to come back to. Your page asks for the username and password and makes two requests to the provider. This guide gives each request and answer; it does not prescribe how the page looks.

## Where the page is served

Serve the page from the provider's public origin (`http.public-origin`), for example behind the same reverse proxy. The login is refused unless it carries same-origin evidence (an `Origin` that is the public origin) or the double-submit token, and any cross-origin evidence refuses it; the cookies both requests set belong to that origin. Where the deployment can make cookies secure, a request over plain http is refused.

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
| `401 {"error": "invalid_credentials"}` | Say the sign-in failed. The answer never tells whether the user exists or what was wrong. |
| `429 {"error": "too_many_attempts"}` | Wait as `Retry-After` says before trying again. Too many failures for one username make each next try wait; the password is not checked meanwhile. |
| `403 {"error": "csrf"}` | Get a new token, then post again. |
| `400` `invalid_redirect` | The `redirect_to` is not one a login may return to. A login returns to the paths the composed modules let it, such as the authorization endpoint's, and to the URLs listed in `login-gates.return-targets`, matched exactly. |
| `400` `invalid_request` or `repeated_parameter` | The request is malformed: fix the page. |
| `503` `temporarily_unavailable` or `service_unavailable` | The provider cannot answer now; try again later. |

After a `200`, the browser holds the session cookie, and the authorization endpoint it returns to goes on to consent or straight to the client.

## Related

- Each setting named here is in the [configuration reference](configuration.md).
- What the provider guarantees about sessions, cookies and CSRF is in the [security model](security-model.md#browsers-sessions-cookies-and-csrf).
- The module cards of `login-password`, `csrf` and `login-gates` hold the full contract, under `modules/identity/` in the repository.
