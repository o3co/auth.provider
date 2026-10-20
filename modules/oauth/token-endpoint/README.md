# token-endpoint

## Responsibilities
- Answers the token endpoint: authenticates the client, then dispatches to a grant by its grant type.
- Built-in grant: client credentials (`clientCredentialsGrantType`).
- Owns the shape of OAuth error responses.

## Not here
- What a grant is given, and how its answer is answered (`grants`).
- What a client may be issued, and its client metadata section (`client-allowance`).

## Offers
- Route `POST /oauth/token`: a form, JSON or no body (any other `415`); cross-origin requests from the operator's origins (`http`) may send `content-type` and `dpop`, and read `dpop-nonce`, `www-authenticate` and `retry-after`.
- Provides `grants`' `composedGrants` (the grant types it dispatches to) and `targets`.
- Where the token endpoint is: its absolute URL on `http`'s public origin, none without one.
- `oauthError`: an error response with the status, the code, an optional description, and the members `grants` lets a grant's refusal keep.
- `authenticateClient`, for other OAuth endpoints too: two methods at once or malformed credentials are `400 invalid_request`, others `401 invalid_client`. Given `audit`, it records a refusal as `client.authentication.failure` with `clients`' `reason` and `source` (when determined), never the client id claimed.
- For tests (`./testing`): `grantCaller` calls a contributed grant as the endpoint does once the client is in, the grant allowed and the binding read, beside `client-allowance`, refusing a mistyped parameter and asking the rule's `untargeted` first; `grantInput` is what it hands the grant.
- `issuer`'s metadata items: `token_endpoint` (none without a public origin), `grant_types_supported`, `token_endpoint_auth_methods_supported` and `token_endpoint_auth_signing_alg_values_supported` (left out when `clients` names none).
- Audit events once the client is authenticated, with `client`, `source` (when determined) and `grant_type` (when dispatched to): `token.issued`, and `token.issued.failure` with `reason` and `error` (the code answered); declared in `./audit-events`, listed in the audit event reference.
- The failure's `reason`: `repeated_parameter`, `mistyped_parameter`, `missing_grant_type`, `unsupported_grant_type`, `grant_type_not_allowed`, `unsupported_body`, `multiple_bindings`, `binding_refused`, `binding_required`, `binding_kind_not_named`, `untargeted`, `grant_refused`, or `issuance_refused` with `policy` and `refusal`.
- Operator section: `requests` per source in each window (1–100000, default 60) and `window` (1s–1d, default `1m`, written with its unit).

## Invariants
- An issued answer leaves `scope` out when a grant gives it empty, for every grant alike, the test caller too.
- Requests are limited per source by `rate-limit`'s policy before any client is authenticated; over it, `429`.
- Checking order: client authentication, repeated parameters, mistyped parameters, `grant_type`, the body the grant takes, the client's allowance, the binding, the client's binding requirement, the rule's `untargeted` for a grant without `targets`, the grant.
- A repeated parameter is `invalid_request` unless the rule's `repeated` answers it, as is an OAuth parameter sent in JSON as neither a string nor `null` (as if left out); `assertion` is its grant's to define.
- A body the grant does not take is `invalid_request`; a request with no body is read as a form.
- A grant type nothing dispatches to is `unsupported_grant_type`, and is never named in the audit or the log.
- A grant `client-allowance` does not allow the client is `unauthorized_client`.
- The binding is read through `sender-binding`: its refusal is answered with its own code and headers, unavailable as `503`, and two bindings are `invalid_request`. A client that must bind and shows none is `invalid_request`, and one bound by a kind it does not name `unauthorized_client`.
- A grant's `401` carries the challenges `clients` answers with the client: its method's, or every method's when it names none.
- Error descriptions keep printable ASCII but `"` and `\`; any other character shows as `?`.
- Unavailable is the route's declared `503` `temporarily_unavailable`, never audited, warned by `http` as `http.unavailable` with the route, what was unavailable and only a grant type dispatched to.
- No token or secret is ever audited or logged.
- Boot is refused, naming the grant type, when a composed grant declares neither `readsAmbient` `none` nor `cookie`: the token route has no own-site policy and relies on that declaration.

## Depends on
- `kernel`, `http`, `request-source`, `grants`, `clients`, `client-allowance`, `issuer`, `tokens`, `sender-binding`, `rate-limit`, `audit`
