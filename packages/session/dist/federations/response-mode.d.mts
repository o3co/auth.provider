import type { FederationProvider } from "./types.mjs";
/**
 * How an upstream IdP delivers the authorization response (OAuth 2 Form Post
 * Response Mode / OIDC Core §3.1.2.5 `response_mode`).
 *
 * - `"query"` — the IdP redirects the browser back with the parameters in the
 *   query string. Every federation this package shipped before Sign in with
 *   Apple used this, and it stays the default so nothing has to opt out.
 * - `"form_post"` — the IdP makes the browser POST an
 *   `application/x-www-form-urlencoded` body to the callback. Apple requires
 *   this whenever the requested `scope` includes `name` or `email`, because
 *   the first-authorization `user` field does not fit a redirect URL.
 *
 * A `form_post` callback is a **cross-site POST** from the IdP's origin, and a
 * `SameSite=Lax` cookie — the deployment default, and the right default — is
 * not sent on one. That is a fact about the mode, and the router answers it by
 * giving the flow a cookie of its own rather than by changing the session's:
 * the ephemeral state moves into a federation transaction (an opaque id in a
 * short-lived, path-scoped, `SameSite=None; Secure; HttpOnly` cookie, with the
 * envelope in a store record keyed by it — `federations/transaction.mts`).
 *
 * The application session cookie keeps the attributes the deployment
 * configured, on every session, whether or not it ever started a `form_post`
 * federation. It has to: `GET /oauth/federation/:name` requires no
 * authentication, a `SameSite=Lax` cookie IS sent on a top-level GET, and
 * express-session serialises `req.session.cookie` into the store and rebuilds
 * it from there on every later request — so a start leg that wrote to that
 * cookie handed any third party a permanent, unauthenticated downgrade of a
 * victim's session (#494).
 */
export type FederationResponseMode = "query" | "form_post";
/** The modes the route layer understands, in declaration order. */
export declare const FEDERATION_RESPONSE_MODES: readonly ["query", "form_post"];
/**
 * The mode assumed for a provider that declares none — i.e. every federation
 * written against the pre-Apple contract.
 */
export declare const DEFAULT_FEDERATION_RESPONSE_MODE: FederationResponseMode;
/**
 * Read a provider's declared response mode, falling back to
 * {@link DEFAULT_FEDERATION_RESPONSE_MODE}.
 *
 * An unrecognised value is treated as the default rather than forwarded. A
 * federation adapter is a third-party extension point reached across an
 * untyped boundary (the same reasoning `mergeFederatedClaims` applies to
 * `mapClaims`), so a provider compiled against a different version of this
 * contract must not be able to push an arbitrary token into the upstream
 * authorization request, nor to unlock the POST callback by naming a mode this
 * router has no handler for.
 */
export declare const resolveFederationResponseMode: (provider: Pick<FederationProvider, "responseMode">) => FederationResponseMode;
//# sourceMappingURL=response-mode.d.mts.map