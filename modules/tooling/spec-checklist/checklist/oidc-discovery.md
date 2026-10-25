# OpenID Connect Discovery 1.0

## 2 OpenID Provider Issuer Discovery

- **oidc-discovery-2-a** MUST: WebFinger communication with the OP uses TLS.
  out-of-scope: issuer discovery by WebFinger is not offered (no `/.well-known/webfinger` route in docs/routes.md).
- **oidc-discovery-2-b** SHOULD: the WebFinger endpoint supports CORS or another way for browser-based clients to reach it.
  out-of-scope: issuer discovery by WebFinger is not offered (no `/.well-known/webfinger` route in docs/routes.md).
- **oidc-discovery-2-c** MUST: the WebFinger response gives the issuer location as the `href` of its link.
  out-of-scope: issuer discovery by WebFinger is not offered (no `/.well-known/webfinger` route in docs/routes.md).
- **oidc-discovery-2-d** MUST: the issuer location WebFinger returns is a URI with a host.
  out-of-scope: issuer discovery by WebFinger is not offered (no `/.well-known/webfinger` route in docs/routes.md).
- **oidc-discovery-2-e** MUST: the issuer location WebFinger returns uses the `https` scheme.
  out-of-scope: issuer discovery by WebFinger is not offered (no `/.well-known/webfinger` route in docs/routes.md).

## 3 OpenID Provider Metadata

- **oidc-discovery-3-a** MUST: the discovery document carries `issuer`, an `https` URL with no query or fragment.
- **oidc-discovery-3-b** MUST: `issuer` is identical to the issuer WebFinger returns.
  out-of-scope: issuer discovery by WebFinger is not offered (no `/.well-known/webfinger` route in docs/routes.md).
- **oidc-discovery-3-c** MUST: `issuer` is identical to the `iss` of the ID tokens the OP issues.
- **oidc-discovery-3-d** MUST: the discovery document carries `authorization_endpoint`.
- **oidc-discovery-3-e** MUST: `authorization_endpoint` uses the `https` scheme.
- **oidc-discovery-3-f** MUST: the discovery document carries `token_endpoint`, as more than the implicit flow is offered.
- **oidc-discovery-3-g** MUST: `token_endpoint` uses the `https` scheme.
- **oidc-discovery-3-h** SHOULD: the discovery document carries `userinfo_endpoint`.
- **oidc-discovery-3-i** MUST: `userinfo_endpoint` uses the `https` scheme.
- **oidc-discovery-3-j** MUST: the discovery document carries `jwks_uri`.
- **oidc-discovery-3-k** MUST: `jwks_uri` uses the `https` scheme.
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
  out-of-scope: dynamic client registration is not offered (no `registration_endpoint`; clients are the operator's configuration).
- **oidc-discovery-3-r** MUST: `registration_endpoint` uses the `https` scheme.
  out-of-scope: dynamic client registration is not offered (no `registration_endpoint`; clients are the operator's configuration).
- **oidc-discovery-3-s** SHOULD: the discovery document carries `scopes_supported`.
- **oidc-discovery-3-t** MUST: the OP supports the `openid` scope.
- **oidc-discovery-3-u** SHOULD: `scopes_supported` lists the scopes OpenID Connect Core defines that the OP supports.
- **oidc-discovery-3-v** MUST: the discovery document carries `response_types_supported`.
- **oidc-discovery-3-w** MUST: a Dynamic OpenID Provider supports the response types `code`, `id_token` and `id_token token`.
  out-of-scope: not a Dynamic OpenID Provider: dynamic client registration is not offered.
- **oidc-discovery-3-x** MUST: a Dynamic OpenID Provider supports the grant types `authorization_code` and `implicit`.
  out-of-scope: not a Dynamic OpenID Provider: dynamic client registration is not offered.
- **oidc-discovery-3-y** MUST: the discovery document carries `subject_types_supported`.
- **oidc-discovery-3-z** MUST: the discovery document carries `id_token_signing_alg_values_supported`.
- **oidc-discovery-3-aa** MUST: `id_token_signing_alg_values_supported` includes `RS256`.
- **oidc-discovery-3-ab** MUST NOT: the OP signs an ID token with `none` where the response type returns an ID token from the authorization endpoint.
  out-of-scope: no ID token comes back from the authorization endpoint (`response_types_supported` is `code`; `authorize`'s card).
- **oidc-discovery-3-ac** SHOULD: the OP supports `none` and `RS256` for request objects.
  out-of-scope: request objects are not offered (no `request_parameter_supported` or `request_uri_parameter_supported`).
- **oidc-discovery-3-ad** SHOULD: the OP supports `RS256` for `private_key_jwt` and `client_secret_jwt` client authentication.
- **oidc-discovery-3-ae** MUST NOT: the OP takes a client authentication JWT signed with `none`.
- **oidc-discovery-3-af** SHOULD: the discovery document carries `claims_supported`.
- **oidc-discovery-3-ag** MUST: a client must pre-register its `request_uri` values where `require_request_uri_registration` is true.
  out-of-scope: request objects are not offered (no `request_parameter_supported` or `request_uri_parameter_supported`).
- **oidc-discovery-3-ah** SHOULD: the registration process shows `op_policy_uri`, where given, to whoever registers a client.
  out-of-scope: dynamic client registration is not offered (no `registration_endpoint`; clients are the operator's configuration).
- **oidc-discovery-3-ai** SHOULD: the registration process shows `op_tos_uri`, where given, to whoever registers a client.
  out-of-scope: dynamic client registration is not offered (no `registration_endpoint`; clients are the operator's configuration).
- **oidc-discovery-3-aj** SHOULD: endpoints clients reach directly support CORS or another way for browser-based clients to reach them.
- **oidc-discovery-3-ak** SHOULD NOT: the authorization endpoint answers CORS requests.

## 4 Obtaining OpenID Provider Configuration Information

- **oidc-discovery-4-a** MUST: the OP serves its configuration at the issuer followed by `/.well-known/openid-configuration`.
- **oidc-discovery-4-b** MUST: the configuration is a JSON document as this specification describes.
- **oidc-discovery-4-c** MUST: the configuration is served with the content type `application/json`.
- **oidc-discovery-4-d** SHOULD: the configuration endpoint supports CORS or another way for browser-based clients to reach it.

## 4.1 OpenID Provider Configuration Request

- **oidc-discovery-4.1-a** MUST: the configuration is answered to a `GET`.

## 4.2 OpenID Provider Configuration Response

- **oidc-discovery-4.2-a** MUST: a successful configuration response is `200 OK` with a JSON object of the content type `application/json`.
- **oidc-discovery-4.2-b** MUST: a metadata value with no elements is left out of the configuration.

## 4.3 OpenID Provider Configuration Validation

- **oidc-discovery-4.3-a** MUST: the `issuer` the configuration returns is identical to the issuer URL its location was formed from.

## 7.1 TLS Requirements

- **oidc-discovery-7.1-a** MUST: the TLS connections the OP makes check the server's certificate (RFC 6125).
