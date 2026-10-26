# OpenID Connect Core 1.0

## 1.2 Terminology

- **oidc-core-1.2-a** MUST: the UserInfo endpoint's URL uses the `https` scheme.
- **oidc-core-1.2-b** MUST: a Request URI o3co's RP sends is one the authorization server can retrieve.
  role: rp
  out-of-scope: o3co's RP sends no request object, by value or by reference: upstream-client's authorization URL carries `response_type=code`, `client_id`, `redirect_uri`, `scope`, `state` and PKCE, and the IdP types add only `nonce`, `prompt`, `max_age`, `access_type`, `response_mode=form_post` and a delegation's `resource` (upstream-client's and the IdP types' cards).

## 2 ID Token

- **oidc-core-2-a** MUST: an ID token carries `iss`, the issuer identifier: an `https` URL with no query or fragment.
- **oidc-core-2-b** MUST: an ID token carries `sub`.
- **oidc-core-2-c** MUST NOT: `sub` exceeds 255 ASCII characters.
- **oidc-core-2-d** MUST: an ID token carries `aud`.
- **oidc-core-2-e** MUST: `aud` contains the relying party's `client_id`.
- **oidc-core-2-f** MUST: an ID token carries `exp`.
- **oidc-core-2-g** MUST: an ID token carries `iat`.
- **oidc-core-2-h** MUST: an ID token carries `auth_time` where it is asked as an essential claim.
- **oidc-core-2-i** MUST: an ID token carries `nonce`, the value the authentication request sent, where the request had one.
- **oidc-core-2-j** SHOULD: the OP does nothing else with a `nonce` value.
- **oidc-core-2-k** SHOULD: an `acr` value the OP issues is an absolute URI or a name registered under RFC 6711.
- **oidc-core-2-l** MUST NOT: an `acr` value that is a registered name is used with another meaning than its registered one.
- **oidc-core-2-m** SHOULD: an `amr` value the OP issues is one registered in the IANA Authentication Method Reference Values registry.
- **oidc-core-2-n** MUST: `azp`, where present, is the client ID of the party the ID token was issued to.
- **oidc-core-2-o** MUST: an ID token is signed with JWS.
- **oidc-core-2-p** MUST: an encrypted ID token is signed first, then encrypted, as a nested JWT.
  out-of-scope: ID tokens are signed, never encrypted: `oidc` publishes `id_token_signing_alg_values_supported` alone and no `id_token_encryption_alg_values_supported` (`oidc`'s card).
- **oidc-core-2-q** MUST NOT: an ID token is signed with `none`, unless the response type returns no ID token from the authorization endpoint and the client asked for `none` when it registered.
- **oidc-core-2-s** MUST: the OP ignores claims it does not understand in an ID token it reads, such as an `id_token_hint`.
- **oidc-core-2-r** SHOULD NOT: an ID token uses the header parameter `x5u`, `x5c`, `jku` or `jwk`.
- **oidc-core-2-t** MUST NOT: upstream-client accepts an id_token for a login at or after its `exp`, beyond the IdP type's `clock-skew` (external-jwt).
  role: rp
- **oidc-core-2-u** MUST: upstream-client takes an id_token only while the current time is before its `exp`, give or take the IdP type's `clock-skew` (external-jwt).
  role: rp
- **oidc-core-2-v** MUST: where an id_token carries `nonce`, upstream-client checks that it equals the `nonce` the authentication request sent.
  role: rp
- **oidc-core-2-w** SHOULD NOT: federation lets a login an upstream asserted with `acr` `0` authorize access to a resource of monetary value.
  role: rp

## 3.1.2.1 Authentication Request

- **oidc-core-3.1.2.1-a** MUST: the authorization endpoint takes the authentication request by `GET` and by `POST`.
- **oidc-core-3.1.2.1-b** SHOULD: the OP ignores scope values it does not understand.
- **oidc-core-3.1.2.1-c** MUST: the OP refuses an authentication request without `response_type`.
- **oidc-core-3.1.2.1-d** MUST: the OP refuses an authentication request without `client_id`.
- **oidc-core-3.1.2.1-e** MUST: the OP refuses an authentication request without `redirect_uri`.
- **oidc-core-3.1.2.1-f** MUST: `redirect_uri` exactly matches one the client pre-registered, by simple string comparison.
- **oidc-core-3.1.2.1-g** SHOULD: with `display=page`, the OP shows its authentication and consent UI as a full user-agent page.
- **oidc-core-3.1.2.1-h** SHOULD: with `display=popup`, the OP shows its authentication and consent UI as a popup.
- **oidc-core-3.1.2.1-i** SHOULD: with `display=touch`, the OP shows its authentication and consent UI for a touch interface.
- **oidc-core-3.1.2.1-j** SHOULD: with `display=wap`, the OP shows its authentication and consent UI for a feature phone.
- **oidc-core-3.1.2.1-k** MUST NOT: with `prompt=none`, the OP shows an authentication or consent page.
- **oidc-core-3.1.2.1-l** SHOULD: with `prompt=login`, the OP prompts the End-User to authenticate again.
- **oidc-core-3.1.2.1-m** MUST: with `prompt=login`, an OP that cannot authenticate the End-User again returns an error.
- **oidc-core-3.1.2.1-n** SHOULD: with `prompt=consent`, the OP asks the End-User's consent before returning information to the client.
- **oidc-core-3.1.2.1-o** MUST: with `prompt=consent`, an OP that cannot obtain consent returns an error.
- **oidc-core-3.1.2.1-p** SHOULD: with `prompt=select_account`, the OP prompts the End-User to select an account.
- **oidc-core-3.1.2.1-q** MUST: with `prompt=select_account`, an OP that cannot obtain the End-User's choice returns an error.
- **oidc-core-3.1.2.1-r** MUST: where more time than `max_age` has passed since the End-User last authenticated, the OP attempts to actively authenticate the End-User again.
- **oidc-core-3.1.2.1-s** MUST: where `max_age` was asked, the ID token carries `auth_time`.
- **oidc-core-3.1.2.1-t** SHOULD NOT: `ui_locales` naming locales the OP does not support makes the request an error.
- **oidc-core-3.1.2.1-u** MUST: with `id_token_hint`, where the End-User the hint names is not logged in and is not logged in by the request, the OP returns an error.
- **oidc-core-3.1.2.1-v** SHOULD: with `prompt=none` and no `id_token_hint`, the OP answers successfully where it can (it may otherwise return `invalid_request`).
- **oidc-core-3.1.2.1-w** SHOULD: a redirection URI of the code flow uses `https`; it may instead use `http` for a confidential client where the OP allows it, or for a native client with `localhost`, `127.0.0.1` or `[::1]` as its host, or an alternate scheme, such as one identifying a callback into a native application.
- **oidc-core-3.1.2.1-x** SHOULD: upstream-client sends `state` in every authorization request to an upstream; upstream-round-trip makes it and keeps the round trip under it until the callback, tied to the browser.
  role: rp
- **oidc-core-3.1.2.1-y** SHOULD NOT: an IdP type sends `response_mode` naming the default mode of the response type it asks for (upstream-client sends none; idp-apple sends `form_post` alone).
  role: rp
- **oidc-core-3.1.2.1-z** MUST: upstream-round-trip makes each round trip's `nonce` from enough entropy that it cannot be guessed.
  role: rp
- **oidc-core-3.1.2.1-aa** SHOULD: where o3co's RP sends `prompt=none`, it sends an `id_token_hint` where it can.
  role: rp
  out-of-scope: o3co's RP never sends `prompt=none`: `upstreams`' prompt is `login` alone, and idp-oidc and idp-google add only `consent`.
- **oidc-core-3.1.2.1-ab** MUST: to use an encrypted id_token as `id_token_hint`, o3co's RP first decrypts the signed id_token inside it.
  role: rp
  out-of-scope: o3co's RP takes signed id_tokens alone (external-jwt verifies a compact JWS) and negotiates no encryption: its clients at the upstreams are the operator's static settings.
- **oidc-core-3.1.2.1-ac** SHOULD: a `login_hint` o3co's RP sends matches the value it used for discovery.
  role: rp
  out-of-scope: o3co's RP sends no `login_hint` and discovers no issuer from an identifier (upstream-client's authorization URL; idp-oidc's `issuer` is a setting).

## 3.1.2.2 Authentication Request Validation

- **oidc-core-3.1.2.2-a** MUST: the OP checks that `scope` is present and holds `openid`; a request without it is no OpenID Connect request.
- **oidc-core-3.1.2.2-b** MUST: the OP validates every OAuth 2.0 parameter of the request by OAuth 2.0's rules.
- **oidc-core-3.1.2.2-c** MUST: the OP checks that every required parameter is present and used as this specification says.
- **oidc-core-3.1.2.2-d** MUST: where a specific `sub` is asked (by `id_token_hint` or a requested claim value), the OP answers positively only where that End-User has an active session or authenticated by the request.
- **oidc-core-3.1.2.2-e** MUST NOT: where a specific `sub` is asked, the OP replies with an ID token or access token for another user, even one with an active session.
- **oidc-core-3.1.2.2-f** MUST: where `id_token_hint` is present, the OP checks that it issued the ID token.
- **oidc-core-3.1.2.2-g** SHOULD: the OP takes an `id_token_hint` whose `exp` has passed where the client it names has a current or recent session at the OP.
- **oidc-core-3.1.2.2-h** SHOULD: the OP ignores request parameters it does not recognize.
- **oidc-core-3.1.2.2-i** MUST: on any error in the request, the OP returns an error response (Section 3.1.2.6).

## 3.1.2.3 Authorization Server Authenticates End-User

- **oidc-core-3.1.2.3-a** MUST: the OP attempts to authenticate the End-User where the End-User is not yet authenticated, or the request asks `prompt=login`.
- **oidc-core-3.1.2.3-b** MUST: with `prompt=login`, the OP authenticates the End-User again even where the End-User is already authenticated.
- **oidc-core-3.1.2.3-c** MUST NOT: with `prompt=none`, the OP interacts with the End-User.
- **oidc-core-3.1.2.3-d** MUST: with `prompt=none`, where the End-User is not already authenticated or cannot be authenticated silently, the OP returns an error.
- **oidc-core-3.1.2.3-e** MUST: when it interacts with the End-User, the OP takes measures against cross-site request forgery and clickjacking.

## 3.1.2.4 Authorization Server Obtains End-User Consent/Authorization

- **oidc-core-3.1.2.4-a** MUST: the OP obtains an authorization decision before releasing information to the client.

## 3.1.2.5 Successful Authentication Response

- **oidc-core-3.1.2.5-a** MUST: a successful authentication response of the code flow returns OAuth 2.0's parameters (RFC 6749 §4.1.2) as query parameters of the `redirect_uri`, form-encoded, unless another response mode was asked.

## 3.1.2.6 Authentication Error Response

- **oidc-core-3.1.2.6-a** SHOULD NOT: an error response returns parameters other than the error's and `state`.
- **oidc-core-3.1.2.6-b** MUST NOT: the OP redirects the user agent to an invalid redirection URI.
- **oidc-core-3.1.2.6-c** MUST: an error response carries `error`.
- **oidc-core-3.1.2.6-d** MUST: an error response carries the `state` the request carried, where it carried one.

## 3.1.2.7 Authentication Response Validation

- **oidc-core-3.1.2.7-a** MUST: federation validates an upstream's code-flow authentication response by RFC 6749, especially §4.1.2 and §10.12: it takes a callback only through the round trip whose `state` it carries, in the browser that began it (upstream-round-trip: bound to its cookie, compared in constant time, taken once), and an `error` or a missing code ends it without an exchange.
  role: rp

## 3.1.3.1 Token Request

- **oidc-core-3.1.3.1-a** MUST: the OP authenticates a confidential client at the token endpoint by the method it registered.

## 3.1.3.2 Token Request Validation

- **oidc-core-3.1.3.2-a** MUST: the OP authenticates the client at the token endpoint where it was issued credentials or uses another authentication method.
- **oidc-core-3.1.3.2-b** MUST: the OP checks that the authorization code was issued to the authenticated client.
- **oidc-core-3.1.3.2-c** MUST: the OP checks that the authorization code is valid.
- **oidc-core-3.1.3.2-d** MUST: where it can, the OP checks that the authorization code was not used before.
- **oidc-core-3.1.3.2-e** MUST: the OP checks that `redirect_uri` is identical to the one in the initial authorization request; where it is absent and the client registered only one, the OP may return an error or proceed.
- **oidc-core-3.1.3.2-f** MUST: the OP checks whether the authorization code was issued in answer to an OpenID Connect authentication request, so that an ID token is returned for such a code.

## 3.1.3.3 Successful Token Response

- **oidc-core-3.1.3.3-a** MUST: the token response's `token_type` is `Bearer`, unless another token type was negotiated with the client.
- **oidc-core-3.1.3.3-b** SHOULD: the OP supports the `Bearer` token type.
- **oidc-core-3.1.3.3-c** MUST: a successful token response for a code issued in answer to an OpenID Connect authentication request carries `id_token`.
- **oidc-core-3.1.3.3-d** MUST: a token response holding tokens, secrets or other sensitive information carries `Cache-Control: no-store`.
- **oidc-core-3.1.3.3-e** SHOULD: upstream-client ignores parameters it does not recognize in an upstream's token response.
  role: rp

## 3.1.3.5 Token Response Validation

- **oidc-core-3.1.3.5-a** MUST: idp-oidc, idp-google and idp-apple validate a token response by RFC 6749 (§5.1, §10.12), by Section 3.1.3.7 for its id_token and by Section 3.1.3.8 for its access token: one without an id_token is refused, the id_token is checked through upstream-client, and a given `at_hash` is checked against the access token.
  role: rp

## 3.1.3.7 ID Token Validation

- **oidc-core-3.1.3.7-a** SHOULD: upstream-client takes an id_token whose `alg` is `RS256`, or the algorithm o3co sent in `id_token_signed_response_alg` when it registered at the upstream.
  role: rp
- **oidc-core-3.1.3.7-b** MUST: upstream-client validates the id_token of every token response it takes by this section's steps before the login is used.
  role: rp
- **oidc-core-3.1.3.7-c** SHOULD: where id_token encryption was negotiated at registration, o3co's RP rejects an id_token that is not encrypted.
  role: rp
  out-of-scope: o3co's RP takes signed id_tokens alone (external-jwt verifies a compact JWS) and negotiates no encryption: its clients at the upstreams are the operator's static settings.
- **oidc-core-3.1.3.7-d** MUST: upstream-client checks that the id_token's `iss` exactly matches the IdP type's issuer identifier (idp-oidc's `issuer`, which its discovered description must name; Google's and Apple's fixed issuers).
  role: rp
- **oidc-core-3.1.3.7-e** MUST: upstream-client checks that the id_token's `aud` contains the client's `client-id` registered at that issuer.
  role: rp
- **oidc-core-3.1.3.7-f** MUST: upstream-client rejects an id_token that does not list the client among its audiences, or that lists other audiences the client does not trust.
  role: rp
- **oidc-core-3.1.3.7-g** SHOULD: where an IdP type uses an extension under which `azp` is present (idp-google: Google's cross-client identity), it validates `azp` as that extension says.
  role: rp
- **oidc-core-3.1.3.7-h** SHOULD: where `azp` is present, upstream-client checks that it is the client's `client-id`.
  role: rp
- **oidc-core-3.1.3.7-i** MUST: upstream-client validates the id_token's signature by JWS under the algorithm its `alg` header names, one of the IdP type's `algorithms` (external-jwt), and never takes TLS server validation in its place.
  role: rp
- **oidc-core-3.1.3.7-j** MUST: upstream-client checks the signature only with keys the issuer provides: the `jwks_uri` of idp-oidc's description (or its `jwks-uri` setting without discovery), or Google's or Apple's key set.
  role: rp
- **oidc-core-3.1.3.7-k** MUST: where the authentication request sent a `nonce` (every OpenID Connect IdP type sends one), upstream-client refuses an id_token without a `nonce` equal to it.
  role: rp
- **oidc-core-3.1.3.7-l** SHOULD: o3co's RP checks the `nonce` against replay: upstream-round-trip lets a round trip, and with it its nonce, be taken once.
  role: rp
- **oidc-core-3.1.3.7-m** SHOULD: where o3co's RP asked for `acr`, it checks that the asserted value is appropriate.
  role: rp
  out-of-scope: o3co's RP never asks for `acr`: it sends no `acr_values` and no `claims` (upstream-client's authorization URL).
- **oidc-core-3.1.3.7-n** SHOULD: where `auth_time` was asked for (by `max_age`), federation checks the upstream's `auth_time` and requests re-authentication where too much time has passed.
  role: rp

## 3.2.2.1 Authentication Request

- **oidc-core-3.2.2.1-a** MUST: in the implicit flow, the OP refuses a request without `redirect_uri`.
  out-of-scope: the implicit and hybrid flows are not offered: `response_types_supported` is `code` alone (`authorize`'s card).
- **oidc-core-3.2.2.1-b** MUST: in the implicit flow, `redirect_uri` exactly matches one the client pre-registered.
  out-of-scope: the implicit and hybrid flows are not offered: `response_types_supported` is `code` alone (`authorize`'s card).
- **oidc-core-3.2.2.1-c** MUST NOT: in the implicit flow, `redirect_uri` uses the `http` scheme, but for a native client's loopback one.
  out-of-scope: the implicit and hybrid flows are not offered: `response_types_supported` is `code` alone (`authorize`'s card).
- **oidc-core-3.2.2.1-d** MUST: in the implicit flow, the OP refuses a request without `nonce`.
  out-of-scope: the implicit and hybrid flows are not offered: `response_types_supported` is `code` alone (`authorize`'s card).
- **oidc-core-3.2.2.1-e** MUST: in the implicit flow, the OP refuses a request without `response_type`.
  out-of-scope: the implicit and hybrid flows are not offered: `response_types_supported` is `code` alone (`authorize`'s card).
- **oidc-core-3.2.2.1-f** MUST: in the implicit flow, o3co's RP's `nonce` values have enough entropy that they cannot be guessed.
  role: rp
  out-of-scope: o3co's RP uses the code flow alone: upstream-client asks `response_type=code`, which an IdP type cannot change, and takes id_tokens from the token endpoint alone (upstream-client's card).

## 3.2.2.5 Successful Authentication Response

- **oidc-core-3.2.2.5-a** MUST: an implicit flow response's `token_type` is `Bearer` or one negotiated with the client.
  out-of-scope: the implicit and hybrid flows are not offered: `response_types_supported` is `code` alone (`authorize`'s card).
- **oidc-core-3.2.2.5-b** MUST: an implicit flow response carries `id_token`.
  out-of-scope: the implicit and hybrid flows are not offered: `response_types_supported` is `code` alone (`authorize`'s card).
- **oidc-core-3.2.2.5-c** MUST: an implicit flow response carries the `state` the request carried, where it carried one.
  out-of-scope: the implicit and hybrid flows are not offered: `response_types_supported` is `code` alone (`authorize`'s card).
- **oidc-core-3.2.2.5-d** MUST: an RP using the implicit flow supports RFC 6750 bearer token usage.
  role: rp
  out-of-scope: o3co's RP uses the code flow alone: upstream-client asks `response_type=code`, which an IdP type cannot change, and takes id_tokens from the token endpoint alone (upstream-client's card).
- **oidc-core-3.2.2.5-e** MUST: in the implicit flow, o3co's RP checks that the response's `state` equals the one its request sent.
  role: rp
  out-of-scope: o3co's RP uses the code flow alone: upstream-client asks `response_type=code`, which an IdP type cannot change, and takes id_tokens from the token endpoint alone (upstream-client's card).

## 3.2.2.6 Authentication Error Response

- **oidc-core-3.2.2.6-a** MUST: an implicit flow error is returned in the redirection URI's fragment.
  out-of-scope: the implicit and hybrid flows are not offered: `response_types_supported` is `code` alone (`authorize`'s card).

## 3.2.2.8 Authentication Response Validation

- **oidc-core-3.2.2.8-a** MUST: o3co's RP validates an implicit flow response as this section says.
  role: rp
  out-of-scope: o3co's RP uses the code flow alone: upstream-client asks `response_type=code`, which an IdP type cannot change, and takes id_tokens from the token endpoint alone (upstream-client's card).

## 3.2.2.9 Access Token Validation

- **oidc-core-3.2.2.9-a** SHOULD: o3co's RP validates an access token issued from the authorization endpoint with an id_token against its `at_hash`.
  role: rp
  out-of-scope: o3co's RP uses the code flow alone: upstream-client asks `response_type=code`, which an IdP type cannot change, and takes id_tokens from the token endpoint alone (upstream-client's card).
- **oidc-core-3.2.2.9-b** MUST: in that check, `at_hash` matches the left half of the access token's hash, base64url-encoded.
  role: rp
  out-of-scope: o3co's RP uses the code flow alone: upstream-client asks `response_type=code`, which an IdP type cannot change, and takes id_tokens from the token endpoint alone (upstream-client's card).

## 3.2.2.10 ID Token

- **oidc-core-3.2.2.10-a** MUST: an ID token of the implicit flow carries `nonce`.
  out-of-scope: the implicit and hybrid flows are not offered: `response_types_supported` is `code` alone (`authorize`'s card).
- **oidc-core-3.2.2.10-b** MUST: an ID token issued with an access token from the authorization endpoint carries `at_hash`.
  out-of-scope: the implicit and hybrid flows are not offered: `response_types_supported` is `code` alone (`authorize`'s card).

## 3.2.2.11 ID Token Validation

- **oidc-core-3.2.2.11-a** MUST: in the implicit flow, o3co's RP validates the id_token as Section 3.1.3.7 says, but for this section's differences.
  role: rp
  out-of-scope: o3co's RP uses the code flow alone: upstream-client asks `response_type=code`, which an IdP type cannot change, and takes id_tokens from the token endpoint alone (upstream-client's card).
- **oidc-core-3.2.2.11-b** MUST: in the implicit flow, o3co's RP validates the id_token's signature by JWS under its `alg`.
  role: rp
  out-of-scope: o3co's RP uses the code flow alone: upstream-client asks `response_type=code`, which an IdP type cannot change, and takes id_tokens from the token endpoint alone (upstream-client's card).
- **oidc-core-3.2.2.11-c** MUST: in the implicit flow, o3co's RP checks that `nonce` equals the one the request sent.
  role: rp
  out-of-scope: o3co's RP uses the code flow alone: upstream-client asks `response_type=code`, which an IdP type cannot change, and takes id_tokens from the token endpoint alone (upstream-client's card).
- **oidc-core-3.2.2.11-d** SHOULD: in the implicit flow, o3co's RP checks the `nonce` against replay.
  role: rp
  out-of-scope: o3co's RP uses the code flow alone: upstream-client asks `response_type=code`, which an IdP type cannot change, and takes id_tokens from the token endpoint alone (upstream-client's card).

## 3.3.2.1 Authentication Request

- **oidc-core-3.3.2.1-a** MUST: in the hybrid flow, the OP refuses a request without `nonce` for `code id_token` and `code id_token token`.
  out-of-scope: the implicit and hybrid flows are not offered: `response_types_supported` is `code` alone (`authorize`'s card).
- **oidc-core-3.3.2.1-b** MUST: in the hybrid flow, the OP refuses a request without `response_type`.
  out-of-scope: the implicit and hybrid flows are not offered: `response_types_supported` is `code` alone (`authorize`'s card).
- **oidc-core-3.3.2.1-c** MUST: in the hybrid flow, o3co's RP's `nonce` values have enough entropy that they cannot be guessed.
  role: rp
  out-of-scope: o3co's RP uses the code flow alone: upstream-client asks `response_type=code`, which an IdP type cannot change, and takes id_tokens from the token endpoint alone (upstream-client's card).

## 3.3.2.6 Authentication Error Response

- **oidc-core-3.3.2.6-a** MUST: a hybrid flow error is returned in the redirection URI's fragment.
  out-of-scope: the implicit and hybrid flows are not offered: `response_types_supported` is `code` alone (`authorize`'s card).

## 3.3.2.8 Authentication Response Validation

- **oidc-core-3.3.2.8-a** MUST: o3co's RP validates a hybrid flow response as this section says.
  role: rp
  out-of-scope: o3co's RP uses the code flow alone: upstream-client asks `response_type=code`, which an IdP type cannot change, and takes id_tokens from the token endpoint alone (upstream-client's card).

## 3.3.2.10 Authorization Code Validation

- **oidc-core-3.3.2.10-a** SHOULD: o3co's RP validates a code issued from the authorization endpoint with an id_token against its `c_hash`.
  role: rp
  out-of-scope: o3co's RP uses the code flow alone: upstream-client asks `response_type=code`, which an IdP type cannot change, and takes id_tokens from the token endpoint alone (upstream-client's card).
- **oidc-core-3.3.2.10-b** MUST: where `c_hash` is present, it matches the left half of the code's hash, base64url-encoded.
  role: rp
  out-of-scope: o3co's RP uses the code flow alone: upstream-client asks `response_type=code`, which an IdP type cannot change, and takes id_tokens from the token endpoint alone (upstream-client's card).

## 3.3.2.11 ID Token

- **oidc-core-3.3.2.11-a** MUST: an ID token of the hybrid flow carries the request's `nonce`, where it had one.
  out-of-scope: the implicit and hybrid flows are not offered: `response_types_supported` is `code` alone (`authorize`'s card).
- **oidc-core-3.3.2.11-b** MUST: an ID token of `code id_token token` from the authorization endpoint carries `at_hash`.
  out-of-scope: the implicit and hybrid flows are not offered: `response_types_supported` is `code` alone (`authorize`'s card).
- **oidc-core-3.3.2.11-c** MUST: an ID token of `code id_token` or `code id_token token` from the authorization endpoint carries `c_hash`.
  out-of-scope: the implicit and hybrid flows are not offered: `response_types_supported` is `code` alone (`authorize`'s card).

## 3.3.2.12 ID Token Validation

- **oidc-core-3.3.2.12-a** MUST: in the hybrid flow, o3co's RP validates an id_token from the authorization endpoint as Section 3.2.2.11 says.
  role: rp
  out-of-scope: o3co's RP uses the code flow alone: upstream-client asks `response_type=code`, which an IdP type cannot change, and takes id_tokens from the token endpoint alone (upstream-client's card).

## 3.3.3.6 ID Token

- **oidc-core-3.3.3.6-a** MUST: the two ID tokens of a hybrid flow carry identical `iss` and `sub`.
  out-of-scope: the implicit and hybrid flows are not offered: `response_types_supported` is `code` alone (`authorize`'s card).
- **oidc-core-3.3.3.6-b** SHOULD: the two ID tokens of a hybrid flow both carry every claim about the authentication that either carries.
  out-of-scope: the implicit and hybrid flows are not offered: `response_types_supported` is `code` alone (`authorize`'s card).
- **oidc-core-3.3.3.6-c** SHOULD: claims about the End-User present in both ID tokens of a hybrid flow have the same values.
  out-of-scope: the implicit and hybrid flows are not offered: `response_types_supported` is `code` alone (`authorize`'s card).

## 3.3.3.7 ID Token Validation

- **oidc-core-3.3.3.7-a** MUST: in the hybrid flow, o3co's RP validates an id_token from the token endpoint as Section 3.1.3.7 says.
  role: rp
  out-of-scope: o3co's RP uses the code flow alone: upstream-client asks `response_type=code`, which an IdP type cannot change, and takes id_tokens from the token endpoint alone (upstream-client's card).

## 4 Initiating Login from a Third Party

- **oidc-core-4-a** MUST: federation checks a `target_link_uri` it is passed, so that it is not used as an open redirector to outside sites.
  role: rp
  out-of-scope: o3co's RP has no login initiation endpoint: federation's start takes `redirect_to`, `prompt`, `max_age` and `link` alone, and no `iss`, `login_hint` or `target_link_uri` (federation's card).
- **oidc-core-4-b** MUST: federation ignores the parameters it does not understand at a login initiation endpoint.
  role: rp
  out-of-scope: o3co's RP has no login initiation endpoint: federation's start takes `redirect_to`, `prompt`, `max_age` and `link` alone, and no `iss`, `login_hint` or `target_link_uri` (federation's card).
- **oidc-core-4-c** SHOULD: at a login initiation endpoint, federation uses frame busting and other techniques to stop third-party sites logging an End-User in without their knowledge.
  role: rp
  out-of-scope: o3co's RP has no login initiation endpoint: federation's start takes `redirect_to`, `prompt`, `max_age` and `link` alone, and no `iss`, `login_hint` or `target_link_uri` (federation's card).

## 5.1 Standard Claims

- **oidc-core-5.1-a** SHOULD: a `profile` claim's page is about the End-User.
  out-of-scope: the claim is not released: claims come from the fixed claim table alone (`name`, `picture`, `email`, `email_verified`, `groups`; `oidc`'s card).
- **oidc-core-5.1-b** MUST: a `picture` claim's URL refers to an image file.
- **oidc-core-5.1-c** SHOULD: a `picture` claim's URL refers to a profile photo of the End-User.
- **oidc-core-5.1-d** SHOULD: a `website` claim's page holds information published by or about the End-User.
  out-of-scope: the claim is not released: claims come from the fixed claim table alone (`name`, `picture`, `email`, `email_verified`, `groups`; `oidc`'s card).
- **oidc-core-5.1-e** MUST: an `email` claim conforms to RFC 5322's addr-spec syntax.
- **oidc-core-5.1-f** SHOULD: a `phone_number` claim is in E.164 format.
  out-of-scope: the claim is not released: claims come from the fixed claim table alone (`name`, `picture`, `email`, `email_verified`, `groups`; `oidc`'s card).
- **oidc-core-5.1-g** SHOULD: a `phone_number` claim's extension is in RFC 3966's extension syntax.
  out-of-scope: the claim is not released: claims come from the fixed claim table alone (`name`, `picture`, `email`, `email_verified`, `groups`; `oidc`'s card).
- **oidc-core-5.1-h** MUST: where `phone_number_verified` is true, `phone_number` is in E.164 format.
  out-of-scope: the claim is not released: claims come from the fixed claim table alone (`name`, `picture`, `email`, `email_verified`, `groups`; `oidc`'s card).
- **oidc-core-5.1-i** MUST: where `phone_number_verified` is true, a `phone_number` extension is in RFC 3966 format.
  out-of-scope: the claim is not released: claims come from the fixed claim table alone (`name`, `picture`, `email`, `email_verified`, `groups`; `oidc`'s card).

## 5.1.1 Address Claim

- **oidc-core-5.1.1-a** SHOULD: an `address` claim returned both formatted and in sub-fields represents one address.
  out-of-scope: the claim is not released: claims come from the fixed claim table alone (`name`, `picture`, `email`, `email_verified`, `groups`; `oidc`'s card).

## 5.1.2 Additional Claims

- **oidc-core-5.1.2-a** SHOULD: a claim the OP releases beyond the standard ones has a collision-resistant name, or a private name where a conflict is unlikely.

## 5.2 Claims Languages and Scripts

- **oidc-core-5.2-a** SHOULD: a language tag in a claim name is spelled in the character case it is registered with in the IANA Language Subtag Registry.
  out-of-scope: the OP writes no language tag: the fixed claim table holds untagged claims (`oidc`'s card).
- **oidc-core-5.2-b** SHOULD: the OP reads language tags case-insensitively.
- **oidc-core-5.2-c** SHOULD: a claim's language tag is only as specific as needed.
  out-of-scope: the OP writes no language tag: the fixed claim table holds untagged claims (`oidc`'s card).
- **oidc-core-5.2-d** SHOULD: where possible, the OP matches the claim locales asked with the claims it has.
  out-of-scope: the OP has no claim in more than one language or script to match with: the fixed claim table holds untagged claims (`oidc`'s card).
- **oidc-core-5.2-e** SHOULD NOT: `claims_locales` naming locales the OP does not support makes the request an error.
- **oidc-core-5.2-f** SHOULD: where the OP determines, by `claims_locales` or otherwise, that the End-User and client ask for claims in one set of languages and scripts, claims in that language and script are returned without language tags.
- **oidc-core-5.2-g** SHOULD: upstream-client's id-token reader can handle and use claims that carry language tags.
  role: rp

## 5.3 UserInfo Endpoint

- **oidc-core-5.3-a** MUST: the UserInfo endpoint takes requests by `GET` and by `POST`.
- **oidc-core-5.3-b** MUST: the UserInfo endpoint accepts access tokens as RFC 6750 bearer tokens.
- **oidc-core-5.3-c** SHOULD: the UserInfo endpoint supports CORS or another way for browser-based clients to reach it.

## 5.3.1 UserInfo Request

- **oidc-core-5.3.1-a** SHOULD: a UserInfo request o3co's RP sends to an upstream uses `GET` and sends the access token in the `Authorization` header.
  role: rp

## 5.3.2 Successful UserInfo Response

- **oidc-core-5.3.2-a** MUST: a UserInfo answer returns its claims as the members of a JSON object, unless a signed or encrypted answer was asked.
- **oidc-core-5.3.2-b** SHOULD: a claim not returned is left out of the UserInfo answer.
- **oidc-core-5.3.2-c** SHOULD NOT: a claim of a UserInfo answer is present with a null or empty string value.
- **oidc-core-5.3.2-d** MUST: a UserInfo answer always carries `sub`.
- **oidc-core-5.3.2-e** MUST: the UserInfo endpoint returns the JSON serialization unless the client registered for a signed or encrypted answer.
- **oidc-core-5.3.2-f** MUST: a UserInfo answer carries a content type naming its format.
- **oidc-core-5.3.2-g** MUST: a UserInfo answer whose body is a JSON object has the content type `application/json`.
- **oidc-core-5.3.2-h** SHOULD: a JSON UserInfo answer is encoded in UTF-8.
- **oidc-core-5.3.2-i** MUST: a signed or encrypted UserInfo answer has the content type `application/jwt`.
  out-of-scope: signed and encrypted userinfo answers are not offered: `userinfo` publishes `userinfo_endpoint` alone and answers JSON (`userinfo`'s card), with no `userinfo_signing_alg_values_supported` or `userinfo_encryption_alg_values_supported`.
- **oidc-core-5.3.2-j** MUST: a UserInfo answer both signed and encrypted is signed first, then encrypted, as a nested JWT.
  out-of-scope: signed and encrypted userinfo answers are not offered: `userinfo` publishes `userinfo_endpoint` alone and answers JSON (`userinfo`'s card), with no `userinfo_signing_alg_values_supported` or `userinfo_encryption_alg_values_supported`.
- **oidc-core-5.3.2-k** MUST: a signed UserInfo answer carries `iss` and `aud`.
  out-of-scope: signed and encrypted userinfo answers are not offered: `userinfo` publishes `userinfo_endpoint` alone and answers JSON (`userinfo`'s card), with no `userinfo_signing_alg_values_supported` or `userinfo_encryption_alg_values_supported`.
- **oidc-core-5.3.2-l** MUST: a signed UserInfo answer's `iss` is the OP's issuer identifier.
  out-of-scope: signed and encrypted userinfo answers are not offered: `userinfo` publishes `userinfo_endpoint` alone and answers JSON (`userinfo`'s card), with no `userinfo_signing_alg_values_supported` or `userinfo_encryption_alg_values_supported`.
- **oidc-core-5.3.2-m** MUST: a signed UserInfo answer's `aud` is or includes the client's ID.
  out-of-scope: signed and encrypted userinfo answers are not offered: `userinfo` publishes `userinfo_endpoint` alone and answers JSON (`userinfo`'s card), with no `userinfo_signing_alg_values_supported` or `userinfo_encryption_alg_values_supported`.
- **oidc-core-5.3.2-n** MUST: o3co's RP checks that a UserInfo answer's `sub` exactly matches the id_token's `sub`, and uses none of the answer's values where they differ.
  role: rp

## 5.3.4 UserInfo Response Validation

- **oidc-core-5.3.4-a** MUST: o3co's RP validates an upstream's UserInfo answer: a TLS server certificate check that the intended OP answered; decryption with the registered keys is owed only where `userinfo_encrypted_response_alg` was registered, which o3co never registers.
  role: rp
- **oidc-core-5.3.4-b** SHOULD: o3co's RP validates a signed UserInfo answer's signature by JWS.
  role: rp
  out-of-scope: o3co's RP registers neither `userinfo_signed_response_alg` nor `userinfo_encrypted_response_alg`, and takes a JSON UserInfo answer alone (idp-oidc's `src/userinfo/` and upstream-client's id_token reader).

## 5.5 Requesting Claims using the "claims" Request Parameter

- **oidc-core-5.5-a** SHOULD: an OP that does not support the `claims` parameter returns the claims it believes useful where a client uses it.
- **oidc-core-5.5-b** MUST: the OP ignores members of a `claims` request it does not understand.
- **oidc-core-5.5-c** MUST: an authorization request of o3co's RP whose `claims` uses the `userinfo` member also uses a `response_type` that issues an access token for the UserInfo endpoint.
  role: rp
  out-of-scope: o3co's RP sends no `claims` parameter (upstream-client's authorization URL).

## 5.5.1 Individual Claims Requests

- **oidc-core-5.5.1-a** MUST NOT: claims requested but not returned, essential or voluntary, make the OP return an error, unless a claim's own description says otherwise.
- **oidc-core-5.5.1-b** MUST: a requested `sub` value that does not match fails the authentication.
- **oidc-core-5.5.1-c** MUST: the OP ignores members of an individual claim request it does not understand.
- **oidc-core-5.5.1-d** MUST: each member value of a `claims` request's `userinfo` and `id_token` that o3co's RP sends is `null` or a JSON object.
  role: rp
  out-of-scope: o3co's RP sends no `claims` parameter (upstream-client's authorization URL).
- **oidc-core-5.5.1-e** MUST: a `value` member, and every entry of a `values` member, of a `claims` request o3co's RP sends is a valid value for the claim asked.
  role: rp
  out-of-scope: o3co's RP sends no `claims` parameter (upstream-client's authorization URL).

## 5.5.1.1 Requesting the "acr" Claim

- **oidc-core-5.5.1.1-a** MUST: where the OP supports the `claims` parameter and `acr` is requested for the ID token as essential with `value` or `values`, the OP returns an `acr` matching one of them.
- **oidc-core-5.5.1.1-b** MUST: where such an essential `acr` request for the ID token cannot be met, the OP treats it as a failed authentication.
- **oidc-core-5.5.1.1-c** SHOULD: where a voluntary `acr` value asked cannot be provided, the OP returns the session's current `acr`.

## 5.5.2 Languages and Scripts for Individual Claims

- **oidc-core-5.5.2-a** SHOULD: a claim returned in another language or script than the one asked uses a language tag in its name.

## 5.6 Claim Types

- **oidc-core-5.6-a** MUST: the OP supports normal claims.

## 5.6.2 Aggregated and Distributed Claims

- **oidc-core-5.6.2-a** MUST: an aggregated claim's source carries a `JWT` member.
  out-of-scope: aggregated and distributed claims are not offered: claims are released from the fixed claim table alone (`oidc`'s card).
- **oidc-core-5.6.2-b** MUST: an aggregated claim's JWT carries every claim in `_claim_names` that refers to it.
  out-of-scope: aggregated and distributed claims are not offered: claims are released from the fixed claim table alone (`oidc`'s card).
- **oidc-core-5.6.2-c** SHOULD NOT: an aggregated claim's JWT carries a `sub` that does not identify the End-User at that claims provider.
  out-of-scope: aggregated and distributed claims are not offered: claims are released from the fixed claim table alone (`oidc`'s card).
- **oidc-core-5.6.2-d** MUST: a distributed claim's source carries `endpoint`.
  out-of-scope: aggregated and distributed claims are not offered: claims are released from the fixed claim table alone (`oidc`'s card).
- **oidc-core-5.6.2-e** MUST: a distributed claim's endpoint returns the claim as a JWT.
  out-of-scope: aggregated and distributed claims are not offered: claims are released from the fixed claim table alone (`oidc`'s card).
- **oidc-core-5.6.2-f** MUST: a claims provider takes the access token in the `Authorization` header.
  out-of-scope: aggregated and distributed claims are not offered, and no endpoint of o3co's is a claims provider's: claims come from the fixed claim table alone (`oidc`'s card) and userinfo answers JSON, not a JWT (`userinfo`'s card).
- **oidc-core-5.6.2-g** SHOULD NOT: a claims provider returns a `sub` that does not identify the End-User at that provider.
  out-of-scope: aggregated and distributed claims are not offered, and no endpoint of o3co's is a claims provider's: claims come from the fixed claim table alone (`oidc`'s card) and userinfo answers JSON, not a JWT (`userinfo`'s card).
- **oidc-core-5.6.2-h** SHOULD: a JWT a claims provider issues carries `iss`.
  out-of-scope: aggregated and distributed claims are not offered, and no endpoint of o3co's is a claims provider's: claims come from the fixed claim table alone (`oidc`'s card) and userinfo answers JSON, not a JWT (`userinfo`'s card).
- **oidc-core-5.6.2-i** MUST: where o3co's RP reads an upstream's aggregated claim, it ignores members of its source it does not understand.
  role: rp
  out-of-scope: o3co's RP reads no aggregated or distributed claims: upstream-client's id-token reader reads `email`, `email_verified`, `name` and `picture` alone.
- **oidc-core-5.6.2-j** SHOULD: o3co's RP fetches a distributed claim with its access token in the `Authorization` header.
  role: rp
  out-of-scope: o3co's RP reads no aggregated or distributed claims: upstream-client's id-token reader reads `email`, `email_verified`, `name` and `picture` alone.
- **oidc-core-5.6.2-k** MUST: o3co's RP handles claims listed in `_claim_sources` that the claims provider does not return, not treating them as an error.
  role: rp
  out-of-scope: o3co's RP reads no aggregated or distributed claims: upstream-client's id-token reader reads `email`, `email_verified`, `name` and `picture` alone.
- **oidc-core-5.6.2-l** SHOULD: o3co's RP treats a claim from `_claim_sources` that is not returned like any other requested claim not returned.
  role: rp
  out-of-scope: o3co's RP reads no aggregated or distributed claims: upstream-client's id-token reader reads `email`, `email_verified`, `name` and `picture` alone.

## 5.7 Claim Stability and Uniqueness

- **oidc-core-5.7-a** MUST: `sub` is locally unique and never reassigned within the issuer for an End-User.
- **oidc-core-5.7-b** MUST NOT: federation uses `email`, `phone_number`, `preferred_username`, `name` or any claim but `iss` with `sub`, from the id_token or from UserInfo, as a unique identifier of the End-User.
  role: rp

## 6 Passing Request Parameters as JWTs

- **oidc-core-6-a** MUST: a `request_uri` uses the `https` scheme, unless its request object is signed in a way the OP can verify.
  out-of-scope: request objects are not offered: a request carrying `request` or `request_uri` is refused, and `request_uri_parameter_supported` is false (`authorize`'s card).
- **oidc-core-6-b** MUST NOT: the OP takes a request carrying both `request` and `request_uri`.
  out-of-scope: request objects are not offered: a request carrying `request` or `request_uri` is refused, and `request_uri_parameter_supported` is false (`authorize`'s card).

## 6.1 Passing a Request Object by Value

- **oidc-core-6.1-a** MUST: an OP that does not support the `request` parameter returns `request_not_supported` where a client uses it.
- **oidc-core-6.1-b** MUST: with `request`, the OP refuses a request whose `response_type` or `client_id` is not given as an OAuth 2.0 parameter.
  out-of-scope: request objects are not offered: a request carrying `request` or `request_uri` is refused, and `request_uri_parameter_supported` is false (`authorize`'s card).
- **oidc-core-6.1-c** MUST: with `request`, the OP refuses a request whose `response_type` or `client_id` differs from the request object's.
  out-of-scope: request objects are not offered: a request carrying `request` or `request_uri` is refused, and `request_uri_parameter_supported` is false (`authorize`'s card).
- **oidc-core-6.1-d** MUST: with `request`, the OP refuses a request whose OAuth 2.0 `scope` does not hold `openid`.
  out-of-scope: request objects are not offered: a request carrying `request` or `request_uri` is refused, and `request_uri_parameter_supported` is false (`authorize`'s card).
- **oidc-core-6.1-e** MUST NOT: a request object the OP takes holds `request` or `request_uri`.
  out-of-scope: request objects are not offered: a request carrying `request` or `request_uri` is refused, and `request_uri_parameter_supported` is false (`authorize`'s card).
- **oidc-core-6.1-f** MUST: the OP takes a request object both signed and encrypted only where it was signed first, then encrypted.
  out-of-scope: request objects are not offered: a request carrying `request` or `request_uri` is refused, and `request_uri_parameter_supported` is false (`authorize`'s card).
- **oidc-core-6.1-g** SHOULD: a signed request object o3co's RP sends carries `iss` (its client ID, unless another party signed it) and `aud` (the upstream's issuer identifier, or a list including it).
  role: rp
  out-of-scope: o3co's RP sends no request object, by value or by reference: upstream-client's authorization URL carries `response_type=code`, `client_id`, `redirect_uri`, `scope`, `state` and PKCE, and the IdP types add only `nonce`, `prompt`, `max_age`, `access_type`, `response_mode=form_post` and a delegation's `resource` (upstream-client's and the IdP types' cards).

## 6.2 Passing a Request Object by Reference

- **oidc-core-6.2-a** MUST: an OP that does not support the `request_uri` parameter returns `request_uri_not_supported` where a client uses it.
- **oidc-core-6.2-b** MUST: with `request_uri`, the OP refuses a request whose `response_type` or `client_id` is not given as an OAuth 2.0 parameter.
  out-of-scope: request objects are not offered: a request carrying `request` or `request_uri` is refused, and `request_uri_parameter_supported` is false (`authorize`'s card).
- **oidc-core-6.2-c** MUST: with `request_uri`, the OP refuses a request whose `response_type` or `client_id` differs from the request object's.
  out-of-scope: request objects are not offered: a request carrying `request` or `request_uri` is refused, and `request_uri_parameter_supported` is false (`authorize`'s card).
- **oidc-core-6.2-d** MUST: with `request_uri`, the OP refuses a request whose OAuth 2.0 `scope` does not hold `openid`.
  out-of-scope: request objects are not offered: a request carrying `request` or `request_uri` is refused, and `request_uri_parameter_supported` is false (`authorize`'s card).
- **oidc-core-6.2-e** MUST: the OP takes a request object at a `request_uri` only where what is there is a request object.
  out-of-scope: request objects are not offered: a request carrying `request` or `request_uri` is refused, and `request_uri_parameter_supported` is false (`authorize`'s card).
- **oidc-core-6.2-f** SHOULD: a `request_uri` of o3co's RP whose content could change carries the base64url SHA-256 of that content as its fragment.
  role: rp
  out-of-scope: o3co's RP sends no request object, by value or by reference: upstream-client's authorization URL carries `response_type=code`, `client_id`, `redirect_uri`, `scope`, `state` and PKCE, and the IdP types add only `nonce`, `prompt`, `max_age`, `access_type`, `response_mode=form_post` and a delegation's `resource` (upstream-client's and the IdP types' cards).
- **oidc-core-6.2-g** SHOULD NOT: a `request_uri` o3co's RP sends is longer than 512 ASCII characters.
  role: rp
  out-of-scope: o3co's RP sends no request object, by value or by reference: upstream-client's authorization URL carries `response_type=code`, `client_id`, `redirect_uri`, `scope`, `state` and PKCE, and the IdP types add only `nonce`, `prompt`, `max_age`, `access_type`, `response_mode=form_post` and a delegation's `resource` (upstream-client's and the IdP types' cards).
- **oidc-core-6.2-h** MUST: a `request_uri` o3co's RP sends is reachable by the upstream authorization server.
  role: rp
  out-of-scope: o3co's RP sends no request object, by value or by reference: upstream-client's authorization URL carries `response_type=code`, `client_id`, `redirect_uri`, `scope`, `state` and PKCE, and the IdP types add only `nonce`, `prompt`, `max_age`, `access_type`, `response_mode=form_post` and a delegation's `resource` (upstream-client's and the IdP types' cards).
- **oidc-core-6.2-i** SHOULD: a `request_uri` o3co's RP sends is reachable by o3co.
  role: rp
  out-of-scope: o3co's RP sends no request object, by value or by reference: upstream-client's authorization URL carries `response_type=code`, `client_id`, `redirect_uri`, `scope`, `state` and PKCE, and the IdP types add only `nonce`, `prompt`, `max_age`, `access_type`, `response_mode=form_post` and a delegation's `resource` (upstream-client's and the IdP types' cards).

## 6.2.1 URI Referencing the Request Object

- **oidc-core-6.2.1-a** MUST NOT: a request object of o3co's RP with requested claim values is revealed to anyone but the authorization server.
  role: rp
  out-of-scope: o3co's RP sends no request object, by value or by reference: upstream-client's authorization URL carries `response_type=code`, `client_id`, `redirect_uri`, `scope`, `state` and PKCE, and the IdP types add only `nonce`, `prompt`, `max_age`, `access_type`, `response_mode=form_post` and a delegation's `resource` (upstream-client's and the IdP types' cards).
- **oidc-core-6.2.1-b** MUST: a `request_uri` o3co's RP sends has enough entropy for its lifetime.
  role: rp
  out-of-scope: o3co's RP sends no request object, by value or by reference: upstream-client's authorization URL carries `response_type=code`, `client_id`, `redirect_uri`, `scope`, `state` and PKCE, and the IdP types add only `nonce`, `prompt`, `max_age`, `access_type`, `response_mode=form_post` and a delegation's `resource` (upstream-client's and the IdP types' cards).
- **oidc-core-6.2.1-c** SHOULD: o3co's RP removes a `request_uri` once it is known not to be used again, or after a reasonable timeout, unless access control is in place.
  role: rp
  out-of-scope: o3co's RP sends no request object, by value or by reference: upstream-client's authorization URL carries `response_type=code`, `client_id`, `redirect_uri`, `scope`, `state` and PKCE, and the IdP types add only `nonce`, `prompt`, `max_age`, `access_type`, `response_mode=form_post` and a delegation's `resource` (upstream-client's and the IdP types' cards).

## 6.2.3 Authorization Server Fetches Request Object

- **oidc-core-6.2.3-a** MUST: the OP retrieves the request object at a `request_uri` by `GET`, unless it already holds it cached, and parses it to recreate the request's parameters.
  out-of-scope: request objects are not offered: a request carrying `request` or `request_uri` is refused, and `request_uri_parameter_supported` is false (`authorize`'s card).
- **oidc-core-6.2.3-b** SHOULD: o3co's RP uses a unique `request_uri` for each request with distinct parameters, or otherwise keeps the authorization server from caching it.
  role: rp
  out-of-scope: o3co's RP sends no request object, by value or by reference: upstream-client's authorization URL carries `response_type=code`, `client_id`, `redirect_uri`, `scope`, `state` and PKCE, and the IdP types add only `nonce`, `prompt`, `max_age`, `access_type`, `response_mode=form_post` and a delegation's `resource` (upstream-client's and the IdP types' cards).

## 6.3.1 Encrypted Request Object

- **oidc-core-6.3.1-a** MUST: the OP decrypts an encrypted request object by JWE.
  out-of-scope: request objects are not offered: a request carrying `request` or `request_uri` is refused, and `request_uri_parameter_supported` is false (`authorize`'s card).
- **oidc-core-6.3.1-b** MUST: the OP validates the signature of a request object that is signed inside its encryption.
  out-of-scope: request objects are not offered: a request carrying `request` or `request_uri` is refused, and `request_uri_parameter_supported` is false (`authorize`'s card).
- **oidc-core-6.3.1-c** MUST: the OP returns an error where a request object cannot be decrypted.
  out-of-scope: request objects are not offered: a request carrying `request` or `request_uri` is refused, and `request_uri_parameter_supported` is false (`authorize`'s card).

## 6.3.2 Signed Request Object

- **oidc-core-6.3.2-a** MUST: a signed request object's `alg` matches the `request_object_signing_alg` the client registered, or one pre-registered by other means.
  out-of-scope: request objects are not offered: a request carrying `request` or `request_uri` is refused, and `request_uri_parameter_supported` is false (`authorize`'s card).
- **oidc-core-6.3.2-b** MUST: a request object's signature is validated against the client's key for that algorithm.
  out-of-scope: request objects are not offered: a request carrying `request` or `request_uri` is refused, and `request_uri_parameter_supported` is false (`authorize`'s card).
- **oidc-core-6.3.2-c** MUST: the OP returns an error where a request object's signature does not validate.
  out-of-scope: request objects are not offered: a request carrying `request` or `request_uri` is refused, and `request_uri_parameter_supported` is false (`authorize`'s card).

## 6.3.3 Request Parameter Assembly and Validation

- **oidc-core-6.3.3-a** MUST: the OP assembles the request's parameters from the request object and the OAuth 2.0 parameters, the request object's taking precedence.
  out-of-scope: request objects are not offered: a request carrying `request` or `request_uri` is refused, and `request_uri_parameter_supported` is false (`authorize`'s card).

## 7.2.1 Providing Information with the "registration" Request Parameter

- **oidc-core-7.2.1-a** SHOULD NOT: idp-oidc, idp-google or idp-apple sends the `registration` parameter to an upstream that is not a Self-Issued OP.
  role: rp

## 7.3 Self-Issued OpenID Provider Request

- **oidc-core-7.3-a** MUST: a Self-Issued OP refuses a request without `scope`, `response_type` or `client_id`.
  out-of-scope: a Self-Issued OpenID Provider is not offered.

## 7.4 Self-Issued OpenID Provider Response

- **oidc-core-7.4-a** MUST: a Self-Issued OP's ID token carries `sub_jwk`.
  out-of-scope: a Self-Issued OpenID Provider is not offered.
- **oidc-core-7.4-b** SHOULD NOT: an OP that is not self-issued puts `sub_jwk` in its ID tokens.
- **oidc-core-7.4-c** MUST: a Self-Issued OP returns every claim in the ID token.
  out-of-scope: a Self-Issued OpenID Provider is not offered.

## 8 Subject Identifier Types

- **oidc-core-8-a** MUST: the discovery document lists the subject identifier types the OP supports in `subject_types_supported`.

## 8.1 Pairwise Identifier Algorithm

- **oidc-core-8.1-a** MUST: with pairwise identifiers, the OP calculates a distinct `sub` for each sector identifier.
  out-of-scope: pairwise subject identifiers are not offered: `subject_types_supported` is `public` alone (`oidc`'s card).
- **oidc-core-8.1-b** MUST NOT: a pairwise subject identifier is reversible by a party other than the OP.
  out-of-scope: pairwise subject identifiers are not offered: `subject_types_supported` is `public` alone (`oidc`'s card).
- **oidc-core-8.1-c** MUST: distinct sector identifiers give distinct pairwise subject identifiers.
  out-of-scope: pairwise subject identifiers are not offered: `subject_types_supported` is `public` alone (`oidc`'s card).
- **oidc-core-8.1-d** MUST: the pairwise calculation is deterministic.
  out-of-scope: pairwise subject identifiers are not offered: `subject_types_supported` is `public` alone (`oidc`'s card).
- **oidc-core-8.1-e** SHOULD: an OP that uses pairwise subject identifiers and supports Dynamic Client Registration uses the `sector_identifier_uri` parameter.
  out-of-scope: pairwise subject identifiers are not offered: `subject_types_supported` is `public` alone (`oidc`'s card).
- **oidc-core-8.1-f** MUST: the OP refuses a pairwise client whose `redirect_uris` span several hosts without a `sector_identifier_uri`.
  out-of-scope: pairwise subject identifiers are not offered: `subject_types_supported` is `public` alone (`oidc`'s card).
- **oidc-core-8.1-g** MUST: a `sector_identifier_uri` uses the `https` scheme.
  out-of-scope: pairwise subject identifiers are not offered: `subject_types_supported` is `public` alone (`oidc`'s card).
- **oidc-core-8.1-h** MUST: the OP takes a client's `redirect_uris` only where each is in the JSON array at its `sector_identifier_uri`.
  out-of-scope: pairwise subject identifiers are not offered: `subject_types_supported` is `public` alone (`oidc`'s card).

## 9 Client Authentication

- **oidc-core-9-a** MUST: with `client_secret_jwt`, the OP takes only a JWT whose `iss` is the client's `client_id`.
  out-of-scope: `client_secret_jwt` client authentication is not offered: the methods are `client_secret_basic`, `client_secret_post`, `none` and `private_key_jwt` (`clients`' and `client-assertion`'s cards).
- **oidc-core-9-b** MUST: with `client_secret_jwt`, the OP takes only a JWT whose `sub` is the client's `client_id`.
  out-of-scope: `client_secret_jwt` client authentication is not offered: the methods are `client_secret_basic`, `client_secret_post`, `none` and `private_key_jwt` (`clients`' and `client-assertion`'s cards).
- **oidc-core-9-c** MUST: with `client_secret_jwt`, the OP checks that it is an intended audience of the JWT.
  out-of-scope: `client_secret_jwt` client authentication is not offered: the methods are `client_secret_basic`, `client_secret_post`, `none` and `private_key_jwt` (`clients`' and `client-assertion`'s cards).
- **oidc-core-9-d** SHOULD: with `client_secret_jwt`, the OP takes its token endpoint's URL as the JWT's audience.
  out-of-scope: `client_secret_jwt` client authentication is not offered: the methods are `client_secret_basic`, `client_secret_post`, `none` and `private_key_jwt` (`clients`' and `client-assertion`'s cards).
- **oidc-core-9-e** MUST: with `client_secret_jwt`, the OP takes a JWT once only, by its `jti`, unless reuse was negotiated with the client.
  out-of-scope: `client_secret_jwt` client authentication is not offered: the methods are `client_secret_basic`, `client_secret_post`, `none` and `private_key_jwt` (`clients`' and `client-assertion`'s cards).
- **oidc-core-9-f** MUST NOT: with `client_secret_jwt`, the OP takes a JWT on or after its `exp`.
  out-of-scope: `client_secret_jwt` client authentication is not offered: the methods are `client_secret_basic`, `client_secret_post`, `none` and `private_key_jwt` (`clients`' and `client-assertion`'s cards).
- **oidc-core-9-g** MUST: with `client_secret_jwt`, the OP refuses a JWT without `iss`, `sub`, `aud`, `jti` or `exp`.
  out-of-scope: `client_secret_jwt` client authentication is not offered: the methods are `client_secret_basic`, `client_secret_post`, `none` and `private_key_jwt` (`clients`' and `client-assertion`'s cards).
- **oidc-core-9-h** MUST: with `private_key_jwt`, the OP takes only a JWT whose `iss` is the client's `client_id`.
- **oidc-core-9-i** MUST: with `private_key_jwt`, the OP takes only a JWT whose `sub` is the client's `client_id`.
- **oidc-core-9-j** MUST: with `private_key_jwt`, the OP checks that it is an intended audience of the JWT.
- **oidc-core-9-k** SHOULD: with `private_key_jwt`, the OP takes its token endpoint's URL as the JWT's audience.
  deviates: D-1
- **oidc-core-9-l** MUST: with `private_key_jwt`, the OP takes a JWT once only, by its `jti`, unless reuse was negotiated with the client.
- **oidc-core-9-m** MUST NOT: with `private_key_jwt`, the OP takes a JWT on or after its `exp`.
- **oidc-core-9-n** MUST: with `private_key_jwt`, the OP refuses a JWT without `iss`, `sub`, `aud`, `jti` or `exp`.
- **oidc-core-9-o** MUST: the OP ignores claims of a client authentication JWT it does not understand.
- **oidc-core-9-p** MUST: the OP takes the client authentication JWT from `client_assertion` alone.
- **oidc-core-9-q** MUST: the OP takes a client authentication JWT only with `client_assertion_type` `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`.

## 10 Signatures and Encryption

- **oidc-core-10-a** MUST: a message the OP both signs and encrypts is signed first, then encrypted, as a nested JWT.
  out-of-scope: the OP encrypts nothing: ID tokens are signed alone, with no `id_token_encryption_alg_values_supported` (`oidc`'s card), and userinfo answers JSON (`userinfo`'s card).

## 10.1 Signing

- **oidc-core-10.1-a** MUST: the OP chooses a signature algorithm among those the recipient supports.
- **oidc-core-10.1-b** MUST: a JWS the OP makes with an RSA or ECDSA signature names that algorithm in `alg`.
- **oidc-core-10.1-c** MUST: the private key the OP signs with belongs to a public key in the JWK Set at its `jwks_uri`.
- **oidc-core-10.1-d** MUST: where the OP's JWK Set holds several keys, the JWS header carries `kid`.
- **oidc-core-10.1-e** MUST: the key the OP signs with is one whose usage supports signing.
- **oidc-core-10.1-f** MUST: a JWS the OP makes with a MAC names a MAC algorithm in `alg`.
  out-of-scope: symmetric signing of ID tokens is not offered: `oidc` refuses boot unless `keys` signs with an asymmetric key (`oidc`'s card).
- **oidc-core-10.1-g** MUST NOT: the OP takes a symmetric signature from a public client.
  out-of-scope: a client secret is never a key: `client_secret_jwt` and symmetric encryption are not offered (`clients`' and `client-assertion`'s cards).

## 10.1.1 Rotation of Asymmetric Signing Keys

- **oidc-core-10.1.1-a** SHOULD: the JWK Set at `jwks_uri` keeps recently retired signing keys for a reasonable period.

## 10.2 Encryption

- **oidc-core-10.2-a** MUST: the OP chooses an encryption algorithm among those the recipient supports.
  out-of-scope: ID tokens are signed, never encrypted: `oidc` publishes `id_token_signing_alg_values_supported` alone and no `id_token_encryption_alg_values_supported` (`oidc`'s card).
- **oidc-core-10.2-b** MUST: with RSA, the OP encrypts to an encryption key the recipient publishes in its JWK Set.
  out-of-scope: ID tokens are signed, never encrypted: `oidc` publishes `id_token_signing_alg_values_supported` alone and no `id_token_encryption_alg_values_supported` (`oidc`'s card).
- **oidc-core-10.2-c** MUST: where the recipient's JWK Set holds several keys, the JWE header carries `kid`.
  out-of-scope: ID tokens are signed, never encrypted: `oidc` publishes `id_token_signing_alg_values_supported` alone and no `id_token_encryption_alg_values_supported` (`oidc`'s card).
- **oidc-core-10.2-d** MUST: the key the OP encrypts to is one whose usage includes encryption.
  out-of-scope: ID tokens are signed, never encrypted: `oidc` publishes `id_token_signing_alg_values_supported` alone and no `id_token_encryption_alg_values_supported` (`oidc`'s card).
- **oidc-core-10.2-e** MUST: with ECDH-ES, the other public key is one the recipient publishes in its JWK Set.
  out-of-scope: ID tokens are signed, never encrypted: `oidc` publishes `id_token_signing_alg_values_supported` alone and no `id_token_encryption_alg_values_supported` (`oidc`'s card).
- **oidc-core-10.2-f** MUST: with symmetric encryption, the key is derived from `client_secret` and its hash truncated to the key's length.
  out-of-scope: ID tokens are signed, never encrypted: `oidc` publishes `id_token_signing_alg_values_supported` alone and no `id_token_encryption_alg_values_supported` (`oidc`'s card).
- **oidc-core-10.2-g** MUST NOT: the OP encrypts symmetrically to a public client.
  out-of-scope: ID tokens are signed, never encrypted: `oidc` publishes `id_token_signing_alg_values_supported` alone and no `id_token_encryption_alg_values_supported` (`oidc`'s card).

## 10.2.1 Rotation of Asymmetric Encryption Keys

- **oidc-core-10.2.1-a** SHOULD: the answer at `jwks_uri` carries `Cache-Control` with a `max-age`.
- **oidc-core-10.2.1-b** SHOULD: the OP removes a retired encryption key from the JWK Set at its `jwks_uri`, but keeps it to decrypt with for a period coordinated with the cache time.
  out-of-scope: the JWK Set holds signing keys alone: nothing is encrypted to the OP (`keys`' key set, `use` `sig`).
- **oidc-core-10.2.1-c** SHOULD: the JWK Set's cache time is coordinated with the issuance of new signing keys.

## 11 Offline Access

- **oidc-core-11-a** MUST: the OP always obtains consent before returning a refresh token that allows offline access.
  out-of-scope: `offline_access` is not offered: `scopes_supported` holds no `offline_access`, and clients carry no `application_type` (`oidc`'s and `clients`' cards).
- **oidc-core-11-b** MUST: where `offline_access` is asked, the OP ensures `prompt` holds `consent`, unless other conditions permit offline access.
  out-of-scope: `offline_access` is not offered: `scopes_supported` holds no `offline_access`, and clients carry no `application_type` (`oidc`'s and `clients`' cards).
- **oidc-core-11-c** MUST: the OP ignores an `offline_access` request where neither `prompt=consent` nor other permitting conditions hold.
- **oidc-core-11-d** MUST: the OP ignores an `offline_access` request unless the response type returns an authorization code.
- **oidc-core-11-e** MUST: the OP receives or has consent for offline access where the client's `application_type` is `web`.
  out-of-scope: `offline_access` is not offered: `scopes_supported` holds no `offline_access`, and clients carry no `application_type` (`oidc`'s and `clients`' cards).
- **oidc-core-11-f** SHOULD: the OP receives or has consent for offline access where the client's `application_type` is `native`.
  out-of-scope: `offline_access` is not offered: `scopes_supported` holds no `offline_access`, and clients carry no `application_type` (`oidc`'s and `clients`' cards).
- **oidc-core-11-g** MUST: where idp-oidc asks an upstream for offline access (`offline_access`), its `prompt` holds `consent`, unless other conditions for processing the request permit offline access to the requested resources.
  role: rp

## 12.1 Refresh Request

- **oidc-core-12.1-a** MUST: on a refresh request, the OP authenticates the client by the method it registered.
- **oidc-core-12.1-b** MUST: on a refresh request, the OP validates the refresh token.
- **oidc-core-12.1-c** MUST: on a refresh request, the OP checks that the refresh token was issued to the client.

## 12.2 Successful Refresh Response

- **oidc-core-12.2-a** MUST: an ID token from a refresh carries the original ID token's `iss`.
  out-of-scope: a refresh returns no ID token, which Section 12.2 allows: the refresh grant's answer carries none (refresh/src/grant).
- **oidc-core-12.2-b** MUST: an ID token from a refresh carries the original ID token's `sub`.
  out-of-scope: a refresh returns no ID token, which Section 12.2 allows: the refresh grant's answer carries none (refresh/src/grant).
- **oidc-core-12.2-c** MUST: an ID token from a refresh carries an `iat` of its own issuance.
  out-of-scope: a refresh returns no ID token, which Section 12.2 allows: the refresh grant's answer carries none (refresh/src/grant).
- **oidc-core-12.2-d** MUST: an ID token from a refresh carries the original ID token's `aud`.
  out-of-scope: a refresh returns no ID token, which Section 12.2 allows: the refresh grant's answer carries none (refresh/src/grant).
- **oidc-core-12.2-e** MUST: an ID token from a refresh carries the original authentication's `auth_time`, where it carries one.
  out-of-scope: a refresh returns no ID token, which Section 12.2 allows: the refresh grant's answer carries none (refresh/src/grant).
- **oidc-core-12.2-f** MUST: where an extension that puts `azp` in ID tokens says so, an ID token from a refresh carries the original ID token's `azp`.
  out-of-scope: a refresh returns no ID token, which Section 12.2 allows: the refresh grant's answer carries none (refresh/src/grant).
- **oidc-core-12.2-g** MUST NOT: where an extension that puts `azp` in ID tokens says so, an ID token from a refresh carries `azp` where the original carried none.
  out-of-scope: a refresh returns no ID token, which Section 12.2 allows: the refresh grant's answer carries none (refresh/src/grant).
- **oidc-core-12.2-h** SHOULD NOT: an ID token from a refresh carries `nonce`.
  out-of-scope: a refresh returns no ID token, which Section 12.2 allows: the refresh grant's answer carries none (refresh/src/grant).
- **oidc-core-12.2-i** MUST: an ID token from a refresh that carries `nonce` carries the original's.
  out-of-scope: a refresh returns no ID token, which Section 12.2 allows: the refresh grant's answer carries none (refresh/src/grant).

## 13.3 JSON Serialization

- **oidc-core-13.3-a** SHOULD: a JSON object the OP writes leaves out parameters with no value rather than giving them `null`, unless said otherwise.

## 14 String Operations

- **oidc-core-14-a** MUST: the OP compares a JSON string with another string after removing JSON escaping, as arrays of Unicode code points.
- **oidc-core-14-b** MUST NOT: the OP applies Unicode normalization to a string it compares.
- **oidc-core-14-c** MUST: the OP compares two strings code point by code point.
- **oidc-core-14-d** MUST: a space-delimited list of this specification's has one ASCII space between its strings, as the OP writes it, and the OP splits such a list it reads on that space alone.

## 15.1 Mandatory to Implement Features for All OpenID Providers

- **oidc-core-15.1-a** MUST: the OP can sign ID tokens with RSA SHA-256 (`RS256`), unless it returns ID tokens from the token endpoint alone and lets clients register only `none` as their ID token signing algorithm.
- **oidc-core-15.1-b** MUST: the OP supports the `prompt` parameter, `none` and `login` included.
- **oidc-core-15.1-c** MUST: the OP supports the `display` parameter, at least by taking it without an error.
- **oidc-core-15.1-d** MUST: the OP supports requests for preferred languages and scripts, at least by taking them without an error.
- **oidc-core-15.1-e** MUST: the OP can return the time the End-User authenticated (`auth_time`).
- **oidc-core-15.1-f** MUST: the OP enforces a maximum authentication age asked by `max_age`.
- **oidc-core-15.1-g** MUST: the OP supports requests for specific authentication context class references (`acr_values`), at least by taking them without an error.

## 15.2 Mandatory to Implement Features for Dynamic OpenID Providers

- **oidc-core-15.2-a** MUST: a dynamic OP supports the `id_token` response type.
- **oidc-core-15.2-b** MUST: a dynamic OP that is not self-issued supports the `code` and `id_token token` response types.
- **oidc-core-15.2-c** MUST: a dynamic OP supports Discovery.
- **oidc-core-15.2-d** MUST: a dynamic OP supports Dynamic Client Registration.
- **oidc-core-15.2-e** MUST: a dynamic OP that issues access tokens supports the UserInfo endpoint.
- **oidc-core-15.2-f** MUST: a dynamic OP publishes its public keys as bare JWKs.
- **oidc-core-15.2-g** MUST: a dynamic OP supports request objects retrieved by `request_uri`.

## 15.3 Discovery and Registration

- **oidc-core-15.3-a** SHOULD: an OP meeting RPs without a pre-configured relationship does so by Discovery and Dynamic Client Registration.

## 16.3 Token Manufacture/Modification

- **oidc-core-16.3-a** SHOULD: idp-oidc, idp-google and idp-apple validate the signature of what an upstream signs (the id_token, through upstream-client's id-token reader and external-jwt), to verify that a legitimate OP issued it and that it is intact.
  role: rp

## 16.4 Access Token Disclosure

- **oidc-core-16.4-a** MUST NOT: an access token is exposed to an unauthorized party.

## 16.7 Request Repudiation

- **oidc-core-16.7-a** SHOULD: the OP validates the signature of a request a client signed, to check it came from that client.

## 16.8 Access Token Redirect

- **oidc-core-16.8-a** SHOULD: an access token is restricted in audience and scope.

## 16.9 Token Reuse

- **oidc-core-16.9-a** SHOULD: a one-time-use token, such as an authorization code, carries a timestamp and a short lifetime, or the OP records its use.

## 16.11 Token Substitution

- **oidc-core-16.11-a** MUST NOT: upstream-client logs a user in through the implicit flow without extra mechanisms that let o3co tell the id_token and access token were issued for its use.
  role: rp

## 16.12 Timing Attack

- **oidc-core-16.12-a** SHOULD NOT: the OP stops a signature's or a decryption's validation at the first error found.
- **oidc-core-16.12-b** SHOULD: the OP runs a signature's or a decryption's validation over every octet before answering.

## 16.15 Issuer Identifier

- **oidc-core-16.15-a** MUST: the issuer discovery returns exactly matches `iss` in the ID token.
- **oidc-core-16.15-b** SHOULD: one host serves a single issuer, unless the host serves several tenants.

## 16.17 TLS Requirements

- **oidc-core-16.17-a** MUST: the TLS connections the OP makes check the server's certificate (RFC 6125).
- **oidc-core-16.17-b** SHOULD: the TLS connections the OP makes follow BCP 195.
- **oidc-core-16.17-c** MUST: the OP's outbound requests are protected by TLS with a ciphersuite giving confidentiality and integrity.

## 16.18 Lifetimes of Access Tokens and Refresh Tokens

- **oidc-core-16.18-a** SHOULD: access tokens are single-use or very short-lived.
- **oidc-core-16.18-b** SHOULD: the OP clearly identifies long-term grants to the user during authorization.
- **oidc-core-16.18-c** SHOULD: the OP offers the End-User a way to revoke access tokens and refresh tokens granted to a client.

## 16.19 Symmetric Key Entropy

- **oidc-core-16.19-a** MUST: a client secret used as a key holds enough entropy to make a cryptographically strong key.
  out-of-scope: a client secret is never a key: `client_secret_jwt` and symmetric encryption are not offered (`clients`' and `client-assertion`'s cards).
- **oidc-core-16.19-b** MUST: a client secret used as a key holds at least the octets its MAC algorithm needs.
  out-of-scope: a client secret is never a key: `client_secret_jwt` and symmetric encryption are not offered (`clients`' and `client-assertion`'s cards).
- **oidc-core-16.19-c** MUST: a client secret used as an `HS256` key holds at least 32 octets.
  out-of-scope: a client secret is never a key: `client_secret_jwt` and symmetric encryption are not offered (`clients`' and `client-assertion`'s cards).
- **oidc-core-16.19-d** SHOULD: a client secret used as a key holds more octets than the minimum.
  out-of-scope: a client secret is never a key: `client_secret_jwt` and symmetric encryption are not offered (`clients`' and `client-assertion`'s cards).

## 16.22 HTTP 307 Redirects

- **oidc-core-16.22-a** MUST NOT: the OP redirects to the redirection URI by HTTP 307.

## 17.1 Personally Identifiable Information

- **oidc-core-17.1-a** SHOULD: UserInfo data o3co's RP keeps is associated with its purpose-of-use statement.
  role: rp
  out-of-scope: o3co's RP fetches no UserInfo: idp-oidc, idp-google and idp-apple take the profile from the checked id_token alone (their cards).

## 17.2 Data Access Monitoring

- **oidc-core-17.2-a** SHOULD: the End-User can see the access log of their UserInfo.

## 17.3 Correlation

- **oidc-core-17.3-a** SHOULD: pairwise pseudonymous identifiers are considered as `sub`.
