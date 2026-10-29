# OpenID Connect Discovery 1.0

## 2 OpenID Provider Issuer Discovery

- **oidc-discovery-2-a** MUST: WebFinger communication with the OP uses TLS.
  out-of-scope: issuer discovery by WebFinger is not offered (no `/.well-known/webfinger` route in docs/routes.md).
- **oidc-discovery-2-b** SHOULD: the WebFinger endpoint supports CORS or another way for browser-based clients to reach it.
  out-of-scope: issuer discovery by WebFinger is not offered (no `/.well-known/webfinger` route in docs/routes.md).
- **oidc-discovery-2-c** MUST: the WebFinger response gives the issuer location as the `href` of its link.
  out-of-scope: issuer discovery by WebFinger is not offered (no `/.well-known/webfinger` route in docs/routes.md).
- **oidc-discovery-2-d** MUST: the issuer location WebFinger returns is a URI with a host and no query or fragment.
  out-of-scope: issuer discovery by WebFinger is not offered (no `/.well-known/webfinger` route in docs/routes.md).
- **oidc-discovery-2-e** MUST: the issuer location WebFinger returns uses the `https` scheme.
  out-of-scope: issuer discovery by WebFinger is not offered (no `/.well-known/webfinger` route in docs/routes.md).
- **oidc-discovery-2-f** MUST: a Web form where the End-User gives o3co's RP an identifier for issuer discovery uses CSRF prevention.
  role: rp
  out-of-scope: o3co's RP never discovers an issuer from a user's identifier: each upstream's issuer is the operator's setting or fixed, and no module speaks WebFinger.
- **oidc-discovery-2-g** SHOULD: o3co's RP's WebFinger request carries `rel` `http://openid.net/specs/connect/1.0/issuer`.
  role: rp
  out-of-scope: o3co's RP never discovers an issuer from a user's identifier: each upstream's issuer is the operator's setting or fixed, and no module speaks WebFinger.

## 2.1 Identifier Normalization

- **oidc-discovery-2.1-a** SHOULD: the user input identifier o3co's RP normalizes is a URL or URI relative reference (RFC 3986).
  role: rp
  out-of-scope: o3co's RP never discovers an issuer from a user's identifier: each upstream's issuer is the operator's setting or fixed, and no module speaks WebFinger.
- **oidc-discovery-2.1-b** MUST: the user input identifier o3co's RP normalizes includes the authority component.
  role: rp
  out-of-scope: o3co's RP never discovers an issuer from a user's identifier: each upstream's issuer is the operator's setting or fixed, and no module speaks WebFinger.

## 2.1.1 User Input Identifier Types

- **oidc-discovery-2.1.1-a** MUST: o3co's RP treats a user input identifier that does not start with an XRI global context symbol as a URI in one of the forms this section lists.
  role: rp
  out-of-scope: o3co's RP never discovers an issuer from a user's identifier: each upstream's issuer is the operator's setting or fixed, and no module speaks WebFinger.

## 2.1.2 Normalization Steps

- **oidc-discovery-2.1.2-a** MUST: o3co's RP strips a fragment, with its `#`, from the normalized URI.
  role: rp
  out-of-scope: o3co's RP never discovers an issuer from a user's identifier: each upstream's issuer is the operator's setting or fixed, and no module speaks WebFinger.

## 3 OpenID Provider Metadata

- **oidc-discovery-3-a** MUST: the discovery document carries `issuer`, an `https` URL with no query or fragment.
  note: N-https
- **oidc-discovery-3-b** MUST: where issuer discovery by WebFinger is supported, `issuer` is identical to the issuer WebFinger returns.
  out-of-scope: issuer discovery by WebFinger is not offered (no `/.well-known/webfinger` route in docs/routes.md).
- **oidc-discovery-3-c** MUST: `issuer` is identical to the `iss` of the ID tokens the OP issues.
- **oidc-discovery-3-d** MUST: the discovery document carries `authorization_endpoint`.
- **oidc-discovery-3-e** MUST: `authorization_endpoint` uses the `https` scheme.
  note: N-https
- **oidc-discovery-3-f** MUST: the discovery document carries `token_endpoint`, unless only the implicit flow is used.
- **oidc-discovery-3-g** MUST: `token_endpoint` uses the `https` scheme.
  note: N-https
- **oidc-discovery-3-h** SHOULD: the discovery document carries `userinfo_endpoint`.
- **oidc-discovery-3-i** MUST: `userinfo_endpoint` uses the `https` scheme.
  note: N-https
- **oidc-discovery-3-j** MUST: the discovery document carries `jwks_uri`.
- **oidc-discovery-3-k** MUST: `jwks_uri` uses the `https` scheme.
  note: N-https
- **oidc-discovery-3-l** MUST: where the JWK Set holds both signing and encryption keys, every key carries `use`.
  out-of-scope: the JWK Set holds signing keys alone (`keys`' key set, `use` `sig`).
- **oidc-discovery-3-m** SHOULD NOT: one key is used both to sign and to encrypt.
  out-of-scope: the JWK Set holds signing keys alone (`keys`' key set, `use` `sig`).
- **oidc-discovery-3-n** MUST: a key given with `x5c` still carries its bare key values.
  out-of-scope: the JWK Set carries no `x5c` (`keys`' key set).
- **oidc-discovery-3-o** MUST: a key's bare values match those in its `x5c` certificate.
  out-of-scope: the JWK Set carries no `x5c` (`keys`' key set).
- **oidc-discovery-3-p** MUST NOT: the JWK Set holds private or symmetric key values.
- **oidc-discovery-3-q** SHOULD: the discovery document carries `registration_endpoint`.
  out-of-scope: the provider is no dynamic OpenID Provider: clients are registered by the operator or come by Client ID Metadata Documents, with no dynamic registration, and `code` is the only response type.
- **oidc-discovery-3-r** MUST: `registration_endpoint` uses the `https` scheme.
  out-of-scope: dynamic client registration is not offered: no route takes a registration and the metadata carries no `registration_endpoint`.
- **oidc-discovery-3-s** SHOULD: the discovery document carries `scopes_supported`.
- **oidc-discovery-3-t** MUST: the OP supports the `openid` scope.
- **oidc-discovery-3-u** SHOULD: `scopes_supported` lists the scopes OpenID Connect Core defines that the OP supports.
- **oidc-discovery-3-v** MUST: the discovery document carries `response_types_supported`.
- **oidc-discovery-3-w** MUST: a Dynamic OpenID Provider supports the response types `code`, `id_token` and `id_token token`.
  out-of-scope: the provider is no dynamic OpenID Provider: clients are registered by the operator or come by Client ID Metadata Documents, with no dynamic registration, and `code` is the only response type.
- **oidc-discovery-3-x** MUST: a Dynamic OpenID Provider supports the grant types `authorization_code` and `implicit`.
  out-of-scope: the provider is no dynamic OpenID Provider: clients are registered by the operator or come by Client ID Metadata Documents, with no dynamic registration, and `code` is the only response type.
- **oidc-discovery-3-y** MUST: the discovery document carries `subject_types_supported`.
- **oidc-discovery-3-z** MUST: the discovery document carries `id_token_signing_alg_values_supported`.
- **oidc-discovery-3-aa** MUST: `id_token_signing_alg_values_supported` includes `RS256`.
- **oidc-discovery-3-ab** MUST NOT: the OP signs an ID token with `none` where the response type returns an ID token from the authorization endpoint.
  out-of-scope: no ID token comes back from the authorization endpoint (`response_types_supported` is `code`; `authorize`'s card).
- **oidc-discovery-3-ac** SHOULD: the OP supports `none` and `RS256` for request objects.
  out-of-scope: request objects are not offered: `authorize` refuses a request carrying `request` or `request_uri`, and publishes `request_uri_parameter_supported` false (`authorize`'s card).
- **oidc-discovery-3-ad** SHOULD: the algorithms the token endpoint takes for the JWT a client authenticates with (`private_key_jwt`, `client_secret_jwt`) include `RS256`.
- **oidc-discovery-3-ae** MUST NOT: the OP takes a client authentication JWT signed with `none`.
- **oidc-discovery-3-af** SHOULD: the discovery document carries `claims_supported`.
- **oidc-discovery-3-ag** MUST: where `require_request_uri_registration` is true, the OP takes only `request_uri` values registered beforehand.
  out-of-scope: request objects are not offered: `authorize` refuses a request carrying `request` or `request_uri`, and publishes `request_uri_parameter_supported` false (`authorize`'s card).
- **oidc-discovery-3-ah** SHOULD: the registration process shows `op_policy_uri`, where given, to whoever registers a client.
  out-of-scope: no `op_policy_uri` is published: no module contributes it to `issuer`'s metadata items, and `issuer`'s section holds none.
- **oidc-discovery-3-ai** SHOULD: the registration process shows `op_tos_uri`, where given, to whoever registers a client.
  out-of-scope: no `op_tos_uri` is published: no module contributes it to `issuer`'s metadata items, and `issuer`'s section holds none.
- **oidc-discovery-3-aj** SHOULD: endpoints clients reach directly support CORS or another way for browser-based clients to reach them.
- **oidc-discovery-3-ak** SHOULD NOT: the authorization endpoint answers CORS requests.

## 4 Obtaining OpenID Provider Configuration Information

- **oidc-discovery-4-a** MUST: an OP that supports Discovery serves its configuration at the issuer followed by `/.well-known/openid-configuration`.
- **oidc-discovery-4-b** MUST: the configuration is a JSON document as this specification describes.
- **oidc-discovery-4-c** MUST: the configuration is served with the content type `application/json`.
- **oidc-discovery-4-d** SHOULD: the configuration endpoint supports CORS or another way for browser-based clients to reach it.

## 4.1 OpenID Provider Configuration Request

- **oidc-discovery-4.1-a** MUST: the configuration is answered to a `GET`.
- **oidc-discovery-4.1-b** MUST: idp-oidc fetches an upstream's configuration by `GET`.
  role: rp
- **oidc-discovery-4.1-c** MUST: idp-oidc, where the issuer has a path component, removes a terminating `/` before appending `/.well-known/openid-configuration`.
  role: rp

## 4.2 OpenID Provider Configuration Response

- **oidc-discovery-4.2-a** MUST: a successful configuration response is `200 OK` with a JSON object of the content type `application/json`.
- **oidc-discovery-4.2-b** MUST: a metadata value with no elements is left out of the configuration.

## 4.3 OpenID Provider Configuration Validation

- **oidc-discovery-4.3-a** MUST: the `issuer` the configuration returns is identical to the issuer URL its location was formed from.
- **oidc-discovery-4.3-b** MUST: idp-oidc aborts any operation that needs information which failed a validation this specification defines.
  role: rp
- **oidc-discovery-4.3-c** MUST NOT: idp-oidc uses information that failed a validation this specification defines.
  role: rp

## 5 String Operations

- **oidc-discovery-5-a** MUST: idp-oidc, idp-google and idp-apple, comparing a value of an OpenID Connect message with another Unicode string, first remove its JSON escaping to get an array of code points.
  role: rp
- **oidc-discovery-5-b** MUST NOT: idp-oidc, idp-google and idp-apple apply Unicode Normalization to either string of such a comparison.
  role: rp
- **oidc-discovery-5-c** MUST: idp-oidc, idp-google and idp-apple compare the two strings of such a comparison code point by code point for equality.
  role: rp

## 7.1 TLS Requirements

- **oidc-discovery-7.1-a** MUST: the TLS connections the OP makes check the server's certificate (RFC 6125).
- **oidc-discovery-7.1-b** MUST: idp-oidc's requests to an upstream (its configuration, key set and token endpoint, through outbound) are protected by TLS with a cipher suite giving confidentiality and integrity.
  role: rp
- **oidc-discovery-7.1-c** SHOULD: idp-oidc's TLS connections to an upstream follow BCP 195.
  role: rp
- **oidc-discovery-7.1-d** MUST: idp-oidc, through outbound, checks an upstream's TLS server certificate (RFC 6125) whenever it uses TLS, its configuration request among them.
  role: rp

## 7.2 Impersonation Attacks

- **oidc-discovery-7.2-a** MUST: idp-oidc, with discovery, ensures the issuer URL it fetches the description under exactly matches the description's `issuer`, and that this exactly matches the `iss` of the id_tokens meant to be from that issuer.
  role: rp
