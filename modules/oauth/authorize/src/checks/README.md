# checks

Internal module of `authorize`: the form of an authorization request, and the scope it may get.

## Responsibilities
- Checks a request's parameters before anything is looked up for it, and decides the scope and audience allowed for the client.

## Not here
- Reading the parameters, and refusing repeated or too long ones (`route`). acr_values and `claims` (`step-up`). The meaning of each prompt word (`flow`, `reauth`, `consent-decision`).

## Offers
- Request check (client, single values, parameters → what is asked: the PKCE challenge, nonce, prompt words, `max_age` / a refusal). Scope check (client, requested scope, issuer, whether `openid` is required → the scope and audience allowed / a refusal). Target check, built over `token-endpoint`'s composed rule (client, single values, the default audience, issuer → the audience asked within what the client may be issued / `invalid_target`).

## Invariants
- A missing `response_type` gives `invalid_request`; any other than `code`, `unsupported_response_type`. Request objects are refused: `request` as `request_not_supported`, `request_uri` as `request_uri_not_supported` (`request` first when both are sent); and response modes other than query.
- Only a client `client-allowance` allows the code grant gets one, otherwise `unauthorized_client` described as not authorized for grant_type `authorization_code`, with the reason `grant_type_not_allowed`. A scope left out with no default is refused with the reason `scope_omitted_without_default`.
- A PKCE challenge is exactly 43 base64url characters. A nonce is at most 256 characters. `max_age` is 1 to 9 digits. An unknown prompt word, or `none` with another, is `invalid_request`.
- The scope and audience are those `client-allowance` allows the client for the requested scope; its refusal is given as it is.
- After those refusals, with `openid` required, a request whose own scope does not name `openid` is `invalid_scope`; a client's default does not count.

## Depends on
- `client-allowance` (whether a grant is allowed, the allowed issuance range, the allowed audiences); `token-endpoint` (the rule for the audience asked); `clients` (the client type); `code-grant` (the grant's type name)
