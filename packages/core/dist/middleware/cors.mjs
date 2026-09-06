/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import { resolveJwksPath } from "../jwks/path.mjs";
import { checkSerializedOrigin, describeSerializedOriginRejection } from "../net/origin.mjs";
/**
 * The request headers a preflight is answered with.
 *
 * `content-type` because the token endpoint takes
 * `application/x-www-form-urlencoded` (which is CORS-safelisted only for a
 * narrow set of values, so it still has to be named), `authorization` because
 * userinfo and revocation take a bearer token, and `dpop` because a
 * sender-constrained public client carries a proof on every one of these
 * calls. Nothing else: an allowlist of request headers is cheap to widen later
 * and impossible to narrow once a client depends on it.
 */
const ALLOWED_REQUEST_HEADERS = "content-type, authorization, dpop";
/**
 * Response headers a matched origin may read, beyond the CORS-safelisted set
 * (`Cache-Control`, `Content-Language`, `Content-Length`, `Content-Type`,
 * `Expires`, `Last-Modified`, `Pragma`).
 *
 * Both are diagnostics the caller cannot act on otherwise: without
 * `Retry-After` a throttled SPA sees an opaque `429` and has nothing to back
 * off by, and without `WWW-Authenticate` a `401` from userinfo does not say
 * which scheme or realm it wanted. Neither reveals anything to an origin that
 * is already permitted to read the whole body.
 */
const EXPOSED_RESPONSE_HEADERS = "WWW-Authenticate, Retry-After";
/**
 * How long a browser may cache a preflight, in seconds. Ten minutes: long
 * enough that a chatty SPA is not preflighting every call, short enough that
 * removing an origin from the allowlist takes effect within a deploy rather
 * than within a browser's maximum (which Chrome caps at 2 hours anyway).
 */
const PREFLIGHT_MAX_AGE_SECONDS = 600;
/**
 * The endpoints CORS is enabled on, for a given config.
 *
 * **On the list**, because a browser has a legitimate reason to call each one
 * from a page served by another origin:
 *
 *   - `POST /oauth/token` — the PKCE code exchange and refresh. Without this
 *     one nothing else matters; it is the call an SPA cannot avoid.
 *   - `GET|POST /oauth/userinfo` — OIDC Core §5.3 defines both methods.
 *   - `POST /oauth/revoke` — RFC 7009 §2.1 lets a public client revoke its own
 *     tokens, which is exactly what an SPA does on sign-out.
 *   - `GET /.well-known/openid-configuration` and the JWKS document — public,
 *     unauthenticated, cacheable metadata that a browser-based client library
 *     fetches to discover the endpoints above. The JWKS path is resolved
 *     through {@link resolveJwksPath}, the same single source the route
 *     registration and the advertised `jwks_uri` use, so the three cannot
 *     drift.
 *
 * **Deliberately off the list:**
 *
 *   - `POST /oauth/introspect` is server-to-server. RFC 7662 §2.1 requires the
 *     caller to authenticate, and this provider already refuses public
 *     clients there, so a browser could never use it — enabling CORS on it
 *     would only advertise a surface no legitimate browser client has.
 *   - `GET /oauth/authorize` is a top-level navigation, not a `fetch`. CORS
 *     has no bearing on where a browser is allowed to navigate, so a header
 *     there would grant nothing and imply something false about the endpoint.
 *   - `/session/*` is cookie-backed by construction and covered by the CSRF
 *     policy at `session.csrf.trustedOrigins`, which answers the different
 *     question ("may this origin make me change state") that #272 split apart
 *     from this one.
 *
 * NOTE: the `/oauth/*` paths are coupled to the bundled `oauthModule`'s
 * mountPath, the same coupling the `/oauth/token` middleware mounts in
 * `boot/assemble-app.mts` already carry. A downstream that re-mounts the OAuth
 * router elsewhere must build its own table.
 */
export function browserFacingCorsRoutes(config) {
    return [
        { path: "/oauth/token", methods: ["POST"] },
        { path: "/oauth/userinfo", methods: ["GET", "POST"] },
        { path: "/oauth/revoke", methods: ["POST"] },
        { path: "/.well-known/openid-configuration", methods: ["GET"] },
        { path: resolveJwksPath(config), methods: ["GET"] },
    ];
}
/**
 * Normalise a request path for comparison against the table: lowercased,
 * because Express routers are case-insensitive by default and so a request to
 * `/OAuth/Token` does reach the handler; and with one trailing slash removed,
 * because Express's non-strict routing (the default) treats `/oauth/token/` as
 * the same route. Matching more loosely than the router does would put headers
 * on a path that 404s; matching more tightly would leave a reachable endpoint
 * uncovered.
 */
function normalizePath(path) {
    const lowered = path.toLowerCase();
    return lowered.length > 1 && lowered.endsWith("/") ? lowered.slice(0, -1) : lowered;
}
/**
 * Build the CORS middleware, or `null` when there is nothing to do — an empty
 * (or entirely invalid) allowlist means CORS is off and no middleware should
 * be mounted at all, so that a deployment which has not opted in cannot even
 * gain a `Vary` header it did not have before.
 *
 * The re-check of `allowedOrigins` mirrors what `resolveJwksPath` does for
 * `oauth.jwt.jwksPath`: the config schema already refuses a malformed entry at
 * boot, and this repeats the check because a hand-built `AppConfig` — which
 * this codebase supports and `resolveOAuthOptions` documents — never passed
 * that schema. A dropped entry is warned about by name rather than ignored,
 * because a silently-narrowed allowlist is the same class of failure as the
 * silently-absent one this middleware exists to fix.
 */
export function corsMw(options) {
    const logger = options.logger;
    const origins = new Set();
    for (const entry of options.allowedOrigins) {
        const rejection = typeof entry === "string" ? checkSerializedOrigin(entry) : { reason: "unparsable" };
        if (rejection === null) {
            origins.add(entry);
            continue;
        }
        logger?.warn(`cors: ignoring cors.allowedOrigins entry ${JSON.stringify(entry)} — ${describeSerializedOriginRejection(rejection)}`);
    }
    if (origins.size === 0)
        return null;
    const byPath = new Map();
    for (const route of options.routes) {
        byPath.set(normalizePath(route.path), route);
    }
    return (req, res, next) => {
        const route = byPath.get(normalizePath(req.path));
        if (route === undefined) {
            next();
            return;
        }
        // On EVERY response from a CORS-enabled route, including the ones that
        // carry no `Access-Control-Allow-Origin`: the response body and headers
        // depend on the request's Origin, so a cache that did not know that
        // could hand an allowed origin's response to a disallowed one.
        res.vary("Origin");
        const origin = req.headers.origin;
        const isPreflight = req.method === "OPTIONS" && req.headers["access-control-request-method"] !== undefined;
        if (typeof origin !== "string" || !origins.has(origin)) {
            // An unlisted (or absent) origin gets no CORS headers at all. A
            // preflight still ends here rather than falling through: the routes
            // above answer POST or GET, so the OPTIONS would 404, and a 404 tells
            // the operator reading their logs that the path is wrong when the
            // actual answer is that the origin is not on the list. The browser
            // refuses the request either way — the absent header is what decides
            // it, not the status.
            if (isPreflight) {
                res.status(204).end();
                return;
            }
            next();
            return;
        }
        // The matched entry, echoed exactly. Never `*`, and never an origin
        // that was not on the list.
        res.setHeader("Access-Control-Allow-Origin", origin);
        // `Access-Control-Allow-Credentials` is deliberately absent — see this
        // module's header. Without it a browser sends no cookie and reads no
        // `Set-Cookie`, which is what keeps the cookie-backed `session` grant
        // out of reach of an allowlisted origin.
        res.setHeader("Access-Control-Expose-Headers", EXPOSED_RESPONSE_HEADERS);
        if (isPreflight) {
            res.setHeader("Access-Control-Allow-Methods", route.methods.join(", "));
            res.setHeader("Access-Control-Allow-Headers", ALLOWED_REQUEST_HEADERS);
            res.setHeader("Access-Control-Max-Age", String(PREFLIGHT_MAX_AGE_SECONDS));
            res.status(204).end();
            return;
        }
        next();
    };
}
