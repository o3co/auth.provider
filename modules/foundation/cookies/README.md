# cookies

## Responsibilities
- Builds `Set-Cookie` values for the names routes give, by one rule for this deployment.
- Reads a request's cookies by those names, by the same rule.

## Not here
- Whether cookies can be made secure (`http`'s `site`, from the public origin).
- A request's scheme (`request-source`).
- What a cookie holds (the route's).

## Offers
- `cookies.write`: a name, a value, a lifetime in seconds, and whether the cookie is cross-site → a `Set-Cookie` value.
- `cookies.read`: a request and a name → the cookie's value.
- `cookiesFor`: whether cookies can be made secure → cookies by the same rule, for a stand-in that builds them without composing this module.

## Invariants
- Where cookies can be made secure, a cookie's name gets the `__Host-` prefix.
- Where cookies can be made secure, a cookie gets Secure.
- Every cookie gets Path=/ and HttpOnly.
- No cookie gets a Domain.
- A cookie that is not cross-site gets SameSite=Lax.
- A lifetime of zero seconds removes a cookie.
- A cross-site cookie gets SameSite=None.
- A cross-site cookie is only ever `__Host-`, Secure, Path=/ and without Domain, so no related site can set it.
- Where cookies cannot be made secure, writing a cross-site cookie throws.
- Writing a name that is not an HTTP token, or a value with anything but cookie-octets (RFC 6265), throws, so a write sets one cookie and no attribute of its own.
- Each write takes its attributes from the rule of the deployment writing it; nothing of a cookie is kept between writes.
- A request's cookie is read only when exactly one cookie has that name.
- Where cookies can be made secure, the cookies of a request not over HTTPS are not read.
- The cookies offered are frozen.

## Depends on
- `kernel`, `http` (the request type, `site`), `request-source` (the scheme).
