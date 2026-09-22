# Offline access, provider by provider

What each IdP needs before it will issue the refresh token a federation grant
runs on (#593, D19; acceptance criterion 10). Every statement here is marked
by how it is known:

- **code** — verified in this repository, with the file named;
- **provider docs** — quoted from the provider's own documentation, with the
  page named. The quote is the fact; what this guide adds is how it meets the
  code;
- **unverified** — not checked on a live tenant or project. Do it before
  telling users a connection works.

## What every connection gets from the adapter (code)

Only the generic OIDC adapter (`@o3co/auth-provider-federation-oidc`) carries
the delegated capability; the Google, Apple and GitHub adapters do not (D17 —
GitHub OAuth Apps issue no refresh token at all). So a grant connection names
a `federations.<name>` entry of `type = "oidc"`, whatever the IdP, and the
authorization request it builds is fixed (`packages/federation-oidc/src/oidc.mts`,
`buildDelegatedAuthorizationUrl`):

- the intent's scopes, which must include `openid`; PKCE `S256`; `state`;
  a required `nonce`; the connection's `resource` (RFC 8707), sent again at
  the token endpoint and on every refresh;
- `prompt=consent` **when `offline_access` is among the scopes and the
  operator set no `prompt`** (OIDC Core §11: `offline_access` is ignored
  unless the user is prompted for consent). An operator's own
  `authorizationParams.prompt` wins;
- the connection's `authorizationParams`, which may not name a parameter the
  adapter owns: `client_id`, `response_type`, `redirect_uri`, `state`,
  `code_challenge`, `code_challenge_method`, `nonce`, `scope`, `resource`,
  `request`, `request_uri`, `response_mode`. Everything else — `access_type`,
  `audience`, a vendor's own — goes through as written.

And what the callback holds the answer to (`packages/federation-grants/README.md`,
"The callback"):

- a refresh token must be present, or the grant never leaves `pending`
  (`refresh_token_absent`);
- the access token must have a finite lifetime within the connection's
  `maxAccessTokenLifetime`, and be a bearer token;
- the scopes the upstream **reports** must be within what the user was shown,
  compared exactly, on the names the connection configures. The adapter
  normalizes nothing: configure the names the IdP reports, including any it
  adds by itself. An omitted `scope` in the answer means "as requested";
- on a **refresh**, a rotated refresh token is persisted even out of an
  answer the library could not otherwise parse (D5, D12). The connect
  callback's exchange has no such salvage: an acquisition whose answer could
  not be verified has no grant to keep a token under, and fails whole;
- the grant's own lifetime is an upper bound on the local authorization, not
  a promise that the upstream's refresh token lasts that long. A structured
  `invalid_grant` or `invalid_token` answer to a refresh makes the grant read
  `reauthorization_required` with reason `upstream_invalid_grant`, and deletes
  its stored credentials. A structured `interaction_required`,
  `login_required`, `consent_required` or `account_selection_required` answer
  — the IdP wants the user, not a new token — also makes it read
  `reauthorization_required`, with reason `upstream_` followed by that code,
  but keeps the credentials (#616). `/token` then answers 410 with no
  `Retry-After` and no cached token, until a reauthorization activates; pause
  the worker and send the user through `/reauthorize` — elapsed time alone
  resumes nothing. Other refresh failures follow the outage, rate-limit and
  refusal rules and their backoff. An error's message alone establishes none
  of this; only the code the IdP put on the error does.

## Microsoft Entra ID

**Recipe** (code + the ADR's D19):

```hocon
federations.entra-files {
  enabled = true
  type = "oidc"
  issuer = "https://login.microsoftonline.com/<tenant-id>/v2.0"
  clientId = "<the grants app registration>"      # its own, not the login one
  clientSecret = ${ENTRA_FILES_CLIENT_SECRET}
  callbackURL = "https://auth.example/session/oauth/federation/entra-files/callback"
}
federationGrants.connections.files {
  federation = "entra-files"
  scopes = ["openid", "profile", "offline_access", "https://graph.microsoft.com/Files.Read"]
  allowScopeSubsets = false
  boundary = "production"
  maxAccessTokenLifetime = 3600
  callbackURL = "https://auth.example/session/federation-grants/callback/files"
  identityClaims = ["oid", "tid"]
}
```

**Provider docs** ([Scopes and permissions in the Microsoft identity platform](https://learn.microsoft.com/en-us/entra/identity-platform/scopes-oidc),
[Refresh tokens](https://learn.microsoft.com/en-us/entra/identity-platform/refresh-tokens),
[ID token claims reference](https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference)):

- "On the Microsoft identity platform (requests made to the v2.0 endpoint),
  your app must explicitly request the `offline_access` scope, to receive
  refresh tokens." The adapter then adds `prompt=consent` by itself.
- `profile` "gives the app access to a large amount of information about the
  user. The information it can access includes, but not limited to, the
  user's given name, surname, preferred username, and object ID." It is in
  the scopes above because `oid` — the object ID — is what `identityClaims`
  hands the Store (D7 check 5, #611): `sub` is pairwise per app registration,
  `oid` is the same for a user across the tenant's apps.
- "Refresh tokens replace themselves with a fresh token upon every use." and
  "The Microsoft identity platform doesn't revoke old refresh tokens when used
  to fetch new access tokens." — a replacement on use, not single-use
  rotation. The callback persists the replacement.
- Default lifetime: "**90 days for** all other scenarios" (24 hours for
  single-page applications). "Refresh tokens are bound to a combination of
  user and client, but aren't tied to a resource or tenant."
- Revocation: "The server can revoke refresh tokens because of a change in
  credentials, user action, or admin action." A password *expiring* leaves
  them alive; an admin's or user's revocation ends them. "Refresh tokens are
  not revoked for B2B users in their resource tenant. The token needs to be
  revoked in the home tenant."

**One registration per scope set, and not the login's** (D19). **Provider
docs** ([Resources and scopes, MSAL.js](https://learn.microsoft.com/en-us/entra/msal/javascript/browser/resources-and-scopes),
"Consent lifetime"): "In Microsoft Entra ID, consent lives beyond the lifetime
of the application." — "when you request an **Access Token** for a resource,
all the scopes you have previously consented to for that resource will be
returned, regardless of what scope was requested at the time." So two grants
with different scope subsets on one registration broaden each other: the
narrower one's token comes back carrying the wider one's scopes, and the
provider withholds it — the callback refuses such an authorization, and a
refresh that returns one leaves the grant `upstream_token_ineligible` with
reason `scope_exceeded`, a stored token that still serves being served
meanwhile (D5).

To keep the same grant, call `POST /oauth/federation-grants/:grantId/reauthorize`
for a scope set that covers what the registration now returns — within the
connection's configured set — and have the user consent to it:
`scope_exceeded` is the one ineligibility that admits a renewal (#616), since
a wider consent is exactly its remedy. Lodging the renewal leaves the old
authorization, credential and marker in place; only the callback's activation
replaces them and clears the marker. Asking again for the narrower set undoes
no accumulated consent and fails the same way.

If the user should not consent to the wider set, revoke the grant and lodge a
new one on a connection with an app registration of its own and the intended
fixed scope set; a renewal never moves a grant to another connection. The rule is one connection per fixed scope set with
`allowScopeSubsets = false`, each on an app registration of its own, separate
from the login registration (whose `profile` and `email` consent accumulates
just the same). **Unverified**: that the same accumulation applies to the
token a *refresh* returns — D19 records it as the working assumption, and the
procedure at the end is how to check it on your tenant. On-behalf-of is not
supported: an OBO assertion has to be an access token issued for the
middle-tier API, which nothing here holds.

**The Store** (#611): with `identityLookup = "required"`, the Store must
declare it covers the `entra-files` registration with claims `oid` and `tid`,
and resolve `(tid, oid)` to a local user from a directory it owns, provisioned
from Entra — Graph's user `id` is the `oid`. A Store that learns identities
only from logins cannot: the grants registration's `sub` is one no login saw.
A person the directory was never given is `identity_not_resolvable`, not
`unlinked`.

**Unverified**: that `oid` and `tid` are issued in the id_token for the
account types you serve (a guest carries the resource tenant's `tid`); the
exact scope names Entra reports at the exchange and on refresh with `profile`
in the set (the consented names must match the connection's, or check 7
refuses); the accumulation behaviour on your tenant. Run the procedure at the
end.

## Google, through the generic OIDC adapter

Use `type = "oidc"` with `issuer = "https://accounts.google.com"`, not the
dedicated `federation-google` adapter, which has no delegated capability.

**Provider docs** ([Using OAuth 2.0 for Web Server Applications](https://developers.google.com/identity/protocols/oauth2/web-server),
[Using OAuth 2.0 to Access Google APIs](https://developers.google.com/identity/protocols/oauth2)):

- Offline access is a request parameter, not a scope: `access_type` — "Set
  the value to `offline` if your application needs to refresh access tokens
  when the user is not present at the browser." No `offline_access` scope is
  documented, so do not list one; set the parameter:

  ```hocon
  authorizationParams { access_type = "offline", prompt = "consent" }
  ```

- "The `refresh_token` is only returned on the first authorization." and, of
  `prompt`, "If you don't specify this parameter, the user will be prompted
  only the first time your project requests access." — so `prompt = "consent"`
  is set explicitly above: without `offline_access` in the scopes the adapter
  adds none, and a user who authorized before would get no refresh token and
  the callback would answer `refresh_token_absent`.
- Do **not** set `include_granted_scopes=true`: "the new access token will
  also cover any scopes to which the user previously granted the
  application access", which is exactly what check 7 (scope containment)
  refuses.
- "A Google Cloud Platform project with an OAuth consent screen configured
  for an external user type and a publishing status of 'Testing' is issued a
  refresh token expiring in 7 days, unless the only OAuth scopes requested
  are a subset of name, email address, and user profile". A paused grant on
  such a project dies in a week, whatever its own lifetime.
- Refresh tokens also stop working when "The refresh token has not been used
  for six months.", when "The user changed passwords and the refresh token
  contains Gmail scopes.", and "There is currently a limit of 100 refresh
  tokens per Google Account per OAuth 2.0 client ID. If the limit is reached,
  creating a new refresh token automatically invalidates the oldest refresh
  token without warning."

**Unverified**: the scope names Google reports in the token response for the
APIs you connect (Google reports full URLs — `https://www.googleapis.com/auth/…`
— and the connection's `scopes` must be spelled as reported); whether Google
adds scopes of its own to the reported set.

## Okta

**Provider docs** ([Refresh access tokens](https://developer.okta.com/docs/guides/refresh-tokens/main/)):

- The app must allow the grant: "If you're using the Admin Console to create
  an app, select **Refresh Token** as a **Grant type** in the **General
  Settings** section."
- "The `offline_access` scope must be requested as part of the code request
  to the `/authorize` endpoint, not the request sent to the `/token`
  endpoint." — list `offline_access` in the connection's scopes; the adapter
  sends it at `/authorize` and adds `prompt=consent`.
- Rotation is per app type by default: "SPAs use refresh token rotation as
  the default behavior. Mobile apps and web apps use persistent refresh token
  behavior as the default." Either works with the callback, which persists a
  rotated token. With rotation on, "Okta offers a grace period" — "The default
  number of seconds for the **Grace period for token rotation** is set to 30
  seconds" — and reuse is detected: "Okta immediately invalidates the most
  recently issued refresh token and all access tokens issued since the user
  authenticated." A grant whose refresh token is reused elsewhere therefore
  ends on the next refresh, as `reauthorization_required`.
- Lifetime: "The default value for the refresh token lifetime
  (`refreshTokenLifetimeMinutes`) in the actions object is **Unlimited**." but
  "The refresh token lifetime does expire every seven days if it hasn't been
  used." — a grant paused longer than that is `reauthorization_required`.

**Unverified**: which authorization server (org or custom) issues for your
resource, and the scope names it reports; consent accumulation (not claimed
either way).

## Auth0

**Provider docs** ([Get refresh tokens](https://auth0.com/docs/secure/tokens/refresh-tokens/get-refresh-tokens),
[API settings](https://auth0.com/docs/get-started/apis/api-settings),
[Configure refresh token rotation](https://auth0.com/docs/secure/tokens/refresh-tokens/configure-refresh-token-rotation)):

- "To get a refresh token, you must include the `offline_access` scope when
  you initiate an authentication request through the `/authorize` endpoint."
  — list it in the connection's scopes.
- On the API: "**Allow Offline Access**: Enable this setting to allow
  applications to ask for refresh tokens for the API."
- The API is named by `audience` in the authorization request (the
  documented example is `audience={API_AUDIENCE}&scope=offline_access&…`).
  `audience` is not a parameter the adapter owns, so pass it as
  `authorizationParams { audience = "https://api.example/" }`. It is Auth0's
  API identifier, not RFC 8707 `resource`; leave the connection's `resource`
  unset unless Auth0 documents it for your tenant.
- Rotation is an application setting: "Under **Refresh Token Rotation**,
  enable **Allow Refresh Token Rotation**." — "only supported for
  OIDC-conformant applications with the Refresh Token grant type enabled."
  The "Rotation Overlap Period" (`leeway`) lets "the same refresh token to be
  used within the time period to account for potential network concurrency
  issues"; reuse otherwise ends the family: "If a previously invalidated token
  is used, the entire set of refresh tokens issued since that invalidated
  token was issued will immediately be revoked along with the grant, requiring
  the user to re-authenticate."
- With rotation, "The default refresh token expiration period … is 30 days
  (2,592,000 seconds)", configurable "up to 1 year", and "**The lifetime does
  not extend when tokens are rotated.**" — size the grant's `expires_in` to
  the shorter of the two.

**Unverified**: the scope names Auth0 reports for your API; consent
accumulation (not claimed either way).

## Keycloak

**Provider docs** ([Server Administration Guide — Offline access](https://www.keycloak.org/docs/latest/server_admin/#_offline-access),
[Session and token timeouts](https://www.keycloak.org/docs/latest/server_admin/#_timeouts)):

- "Clients can request an offline token by adding the parameter
  `scope=offline_access` when sending their authorization request" — list
  `offline_access` in the connection's scopes.
- "To issue an offline token, users must have the role mapping for the
  realm-level `offline_access` role. Clients must also have that role in their
  scope. Clients must add an `offline_access` client scope as an `Optional
  client scope` to the role, which is done by default."
- An offline token is what comes back as the refresh token, and it outlives
  the session: "an offline token never expires and is not subject to the
  `SSO Session Idle` timeout and `SSO Session Max` lifespan." and "The offline
  token is valid after a user logout." — which is what a grant needs.
- It still has to be used: "You must use the offline token for a refresh token
  action at least once per thirty days or for the value of the Offline Session
  Idle." With **Offline Session Max Limited** enabled, "offline tokens expire
  after 60 days even if you use the offline token for a refresh token action.
  You can change this value, Offline Session Max, in the Admin Console." A
  grant paused past either is `reauthorization_required`.
- With **Revoke Refresh Token** enabled, "you can use each offline token once
  only. After refresh, you must store the new offline token from the refresh
  response instead of the previous one." The callback does.
- Operators can end them: "Administrators can revoke offline tokens for
  individual users in the Admin Console in the `Consents` tab."

**Unverified**: the scope names your realm reports (client scopes may add
some); consent accumulation (not claimed either way).

## Before you tell users a connection works

For any provider, and especially for the unverified items above, run one
grant end to end on the real tenant and record — never the token values —

1. the scopes **requested** and the scopes **reported** in the token
   response, at the exchange and on the first refresh: the reported names are
   what the connection's `scopes` must spell, or check 7 answers
   `scope_exceeded` / `upstream_token_ineligible`;
2. whether a refresh token was present, and whether a **replacement** came
   back on refresh;
3. the `expires_in` reported, against `maxAccessTokenLifetime`;
4. for an IdP that may accumulate consent: acquire a narrow grant, consent to a
   wider set on the same registration, refresh the narrow grant. The wider
   answer **must** be refused (`upstream_token_ineligible`) — if it is, the
   registration must be split, never the containment loosened.

The audit events (`federation.grant.authorized`, `.refreshed`,
`.refresh_failed` with its reason) carry the scopes and the outcome and none of
the secrets, so a test run leaves its evidence in the audit trail.
