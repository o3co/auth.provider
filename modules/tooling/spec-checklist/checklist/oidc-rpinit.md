# OpenID Connect RP-Initiated Logout 1.0

## 2 RP-Initiated Logout

- **oidc-rpinit-2-a** MUST: where a logout request carries both `client_id` and `id_token_hint`, the OP checks that the client identifier is the one the ID token was issued to.
- **oidc-rpinit-2-b** MUST: the OP takes a `post_logout_redirect_uri` only where the client registered it before.
- **oidc-rpinit-2-c** SHOULD NOT: `ui_locales` naming locales the OP does not support makes the request an error.
- **oidc-rpinit-2-d** MUST: the logout endpoint takes the request by `GET` and by `POST`.
- **oidc-rpinit-2-e** MUST: where `id_token_hint` is present, the OP checks that it issued the ID token.
- **oidc-rpinit-2-f** SHOULD: the OP takes an ID token hint whose `exp` has passed where the client it names holds a current or recent session at the OP.
- **oidc-rpinit-2-g** SHOULD: an `id_token_hint` whose `sid` matches neither the client's current session at the OP nor a recent one makes the OP treat the request as suspect; the OP may then decline to act on it.
- **oidc-rpinit-2-h** SHOULD: the OP asks the End-User whether to log out of the OP too.
- **oidc-rpinit-2-i** MUST: the OP asks the End-User whether to log out where no `id_token_hint` was given, or where the ID token it gives does not belong to the OP's current session with the client, or to the End-User logged in.
- **oidc-rpinit-2-j** MUST: once the End-User agrees, the OP logs the End-User out.
- **oidc-rpinit-2-k** SHOULD: a `post_logout_redirect_uri` uses `https`; it may instead use `http` for a confidential client where the OP allows `http`, or an alternate scheme, such as one identifying a callback into a native application.
- **oidc-rpinit-2-l** SHOULD: federation-tokens passes the id_token the upstream issued at the login as `id_token_hint` in the logout request it sends to that upstream's end-session endpoint.
  role: rp
- **oidc-rpinit-2-m** SHOULD: where federation-tokens' logout request to an upstream carries `post_logout_redirect_uri`, it also carries `id_token_hint`.
  role: rp

## 2.1 OpenID Provider Discovery Metadata

- **oidc-rpinit-2.1-a** MUST: with RP-Initiated Logout and Discovery both offered, the discovery document names `end_session_endpoint`.
- **oidc-rpinit-2.1-b** MUST: `end_session_endpoint` is an `https` URL.

## 3 Redirection to RP After Logout

- **oidc-rpinit-3-a** MUST NOT: without an `id_token_hint`, the OP redirects to a `post_logout_redirect_uri` it cannot otherwise confirm is legitimate.
- **oidc-rpinit-3-b** MUST NOT: the OP redirects to a `post_logout_redirect_uri` that is not exactly one the client registered.

## 3.1 Post Logout Redirect URIs Registration

- **oidc-rpinit-3.1-a** SHOULD: a client's registered `post_logout_redirect_uris` use `https`; they may instead use `http` for a confidential client where the OP allows `http`, or, as Section 2 allows the parameter, an alternate scheme such as one identifying a callback into a native application.

## 4 Validation

- **oidc-rpinit-4-a** MUST: an operation needing information that failed validation is aborted.
- **oidc-rpinit-4-b** MUST NOT: information that failed validation is used.
- **oidc-rpinit-4-c** MUST: where the logout request has errors, the OP does not redirect to the RP.
