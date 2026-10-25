# OpenID Connect Back-Channel Logout 1.0

## 2.1 Indicating OP Support for Back-Channel Logout

- **oidc-bcl-2.1-a** SHOULD: an OP that declares `backchannel_logout_supported` also declares `backchannel_logout_session_supported`.

## 2.2 Indicating RP Support for Back-Channel Logout

- **oidc-bcl-2.2-a** MUST: the OP refuses a client's `backchannel_logout_uri` that is not an absolute URI.
- **oidc-bcl-2.2-b** MUST: the OP keeps the query of a `backchannel_logout_uri` when it adds parameters to it.
- **oidc-bcl-2.2-c** MUST NOT: the OP takes a client's `backchannel_logout_uri` that has a fragment.
- **oidc-bcl-2.2-d** SHOULD: the OP takes as a client's `backchannel_logout_uri` only an `https` URL, or an `http` one for a confidential client where the OP allows `http`.
- **oidc-bcl-2.2-e** SHOULD: where o3co's RP registers a `backchannel_logout_uri` at an upstream by dynamic registration, it also registers `backchannel_logout_session_required`.
  role: rp
  out-of-scope: o3co's RP takes no logout token: no upstream-login module offers a back-channel logout URI, and o3co registers nothing at an upstream (upstream-client's settings).

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
- **oidc-bcl-2.4-n** MUST: o3co's RP ignores claims it does not understand in a logout token.
  role: rp
  out-of-scope: o3co's RP takes no logout token: no upstream-login module offers a back-channel logout URI, and o3co registers nothing at an upstream (upstream-client's settings).

## 2.5 Back-Channel Logout Request

- **oidc-bcl-2.5-a** SHOULD: where the OP suspects an earlier back-channel logout request failed through a potentially recoverable error (a network outage, a temporary service interruption at the OP or the RP), it waits an appropriate time before sending it again.
- **oidc-bcl-2.5-b** SHOULD NOT: the OP sends a back-channel logout request again other than where it suspects an earlier one failed through a potentially recoverable error.
- **oidc-bcl-2.5-c** MUST: o3co's RP ignores values it does not understand in a back-channel logout request's body.
  role: rp
  out-of-scope: o3co's RP takes no logout token: no upstream-login module offers a back-channel logout URI, and o3co registers nothing at an upstream (upstream-client's settings).

## 2.6 Logout Token Validation

- **oidc-bcl-2.6-a** MUST NOT: a logout token is signed with `alg` `none`.
- **oidc-bcl-2.6-b** SHOULD: where neither `id_token_signing_alg_values_supported` nor the client's `id_token_signed_response_alg` is used, a logout token is signed with `RS256`.
- **oidc-bcl-2.6-c** MUST: o3co's RP validates a logout token it receives by this section's steps.
  role: rp
  out-of-scope: o3co's RP takes no logout token: no upstream-login module offers a back-channel logout URI, and o3co registers nothing at an upstream (upstream-client's settings).
- **oidc-bcl-2.6-d** SHOULD: where ID token encryption was negotiated with the upstream at registration, o3co's RP rejects a logout token that is not encrypted.
  role: rp
  out-of-scope: o3co's RP takes no logout token: no upstream-login module offers a back-channel logout URI, and o3co registers nothing at an upstream (upstream-client's settings).

## 2.7 Back-Channel Logout Actions

- **oidc-bcl-2.7-a** SHOULD: refresh tokens issued without `offline_access` to a session that is logged out are revoked.
- **oidc-bcl-2.7-b** SHOULD NOT: a refresh token issued with `offline_access` is, as a rule, revoked because its session is logged out.

## 2.8 Back-Channel Logout Response

- **oidc-bcl-2.8-a** MUST: o3co's RP answers a back-channel logout request whose logout succeeded with `200 OK`.
  role: rp
  out-of-scope: o3co's RP takes no logout token: no upstream-login module offers a back-channel logout URI, and o3co registers nothing at an upstream (upstream-client's settings).
- **oidc-bcl-2.8-b** MUST: o3co's RP answers an invalid back-channel logout request, or one whose logout failed, with `400 Bad Request`.
  role: rp
  out-of-scope: o3co's RP takes no logout token: no upstream-login module offers a back-channel logout URI, and o3co registers nothing at an upstream (upstream-client's settings).
- **oidc-bcl-2.8-c** MUST: where o3co's RP's back-channel logout response has a body, it carries `error`.
  role: rp
  out-of-scope: o3co's RP takes no logout token: no upstream-login module offers a back-channel logout URI, and o3co registers nothing at an upstream (upstream-client's settings).
- **oidc-bcl-2.8-d** SHOULD: o3co's RP's back-channel logout response carries `Cache-Control: no-store`.
  role: rp
  out-of-scope: o3co's RP takes no logout token: no upstream-login module offers a back-channel logout URI, and o3co registers nothing at an upstream (upstream-client's settings).
