# OpenID Connect Back-Channel Logout 1.0

## 2.1 Indicating OP Support for Back-Channel Logout

- **oidc-bcl-2.1-a** SHOULD: an OP that declares `backchannel_logout_supported` also declares `backchannel_logout_session_supported`.

## 2.2 Indicating RP Support for Back-Channel Logout

- **oidc-bcl-2.2-a** MUST: the OP refuses a client's `backchannel_logout_uri` that is not an absolute URI.
- **oidc-bcl-2.2-b** MUST: the OP keeps the query of a `backchannel_logout_uri` when it adds parameters to it.
- **oidc-bcl-2.2-c** MUST NOT: the OP takes a client's `backchannel_logout_uri` that has a fragment.

## 2.4 Logout Token

- **oidc-bcl-2.4-a** MUST: a logout token carries `iss`.
- **oidc-bcl-2.4-b** MUST: a logout token carries `aud`.
- **oidc-bcl-2.4-c** MUST: a logout token carries `iat`.
- **oidc-bcl-2.4-d** MUST: a logout token carries `exp`.
- **oidc-bcl-2.4-e** MUST: a logout token carries `jti`.
- **oidc-bcl-2.4-f** MUST: a logout token carries `events` naming `http://schemas.openid.net/event/backchannel-logout`.
- **oidc-bcl-2.4-g** MUST: the back-channel logout event's value is a JSON object.
- **oidc-bcl-2.4-h** SHOULD: the back-channel logout event's value is the empty JSON object.
- **oidc-bcl-2.4-i** MUST: a logout token carries `sub`, `sid`, or both.
- **oidc-bcl-2.4-j** MUST NOT: a logout token carries `nonce`.
- **oidc-bcl-2.4-k** MUST: a logout token is signed.
- **oidc-bcl-2.4-l** SHOULD: an encrypted logout token repeats `iss` in its JWT header.
  out-of-scope: logout tokens are signed, never encrypted (`rp-logout`'s card: signed by `keys` under `logout+jwt`).
- **oidc-bcl-2.4-m** SHOULD: a logout token is explicitly typed (`typ` `logout+jwt`).

## 2.5 Back-Channel Logout Request

- **oidc-bcl-2.5-a** SHOULD: where a logout request may not have reached the RP, the OP waits an appropriate time before sending it again.
- **oidc-bcl-2.5-b** SHOULD NOT: the OP sends a back-channel logout request again where nothing suggests it failed to reach the RP.

## 2.6 Logout Token Validation

- **oidc-bcl-2.6-a** MUST NOT: a logout token is signed with `alg` `none`.
- **oidc-bcl-2.6-b** SHOULD: a logout token is signed with the algorithm the client's ID tokens are signed with (`id_token_signing_alg_values_supported`, the client's `id_token_signed_response_alg`), else `RS256`.

## 2.7 Back-Channel Logout Actions

- **oidc-bcl-2.7-a** SHOULD: refresh tokens issued without `offline_access` to a session that is logged out are revoked.
- **oidc-bcl-2.7-b** SHOULD NOT: a refresh token issued with `offline_access` is revoked because its session is logged out.
