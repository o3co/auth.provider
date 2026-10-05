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

/**
 * CORS for `cors.allowedOrigins`, on the endpoints a browser legitimately
 * calls cross-origin ({@link browserFacingCorsRoutes}).
 *
 * - Exact-match allowlist: the matched entry is echoed. An arbitrary origin is
 *   never reflected and `*` is never emitted, even on public documents, so no
 *   code path exists that could emit it on a response carrying a token.
 * - An empty list means CORS is off (the default): nothing is mounted.
 * - Never `Access-Control-Allow-Credentials`. A cross-origin SPA is a public
 *   PKCE client and needs no cookie of ours; allowing credentials would let
 *   every allowlisted origin use the cookie-backed `session` grant to mint
 *   tokens for whoever is signed in.
 * - `Vary: Origin` on every response from a CORS-enabled route, so a shared
 *   cache keyed on the URL cannot serve one origin's response to another.
 */

import type { NextFunction, Request, RequestHandler, Response } from "express";
import { discoveryPathsFor } from "../discovery/wellKnownPaths.mjs";
import type { Logger } from "../logging/Logger.mjs";
import { checkSerializedOrigin, describeSerializedOriginRejection } from "../net/origin.mjs";

/** One CORS-enabled endpoint: an exact path and the methods it answers. */
export interface CorsRoute {
	/** Absolute path, exactly as mounted. Matched case-insensitively. */
	readonly path: string;
	/** Methods advertised on a preflight. `OPTIONS` is implicit. */
	readonly methods: readonly string[];
}

/**
 * Request headers a preflight allows: `content-type` (the token endpoint's
 * form body still has to be named; the safelist covers only narrow values),
 * `authorization` (bearer tokens at userinfo and revocation) and `dpop`
 * (sender-constrained public clients). Nothing else: an allowlist of request
 * headers is cheap to widen and impossible to narrow once clients depend on it.
 */
const ALLOWED_REQUEST_HEADERS = "content-type, authorization, dpop";

/**
 * Response headers a matched origin may read beyond the CORS-safelisted set.
 * Each is needed to act on an answer: `Retry-After` to back off a `429`,
 * `WWW-Authenticate` for a `401`'s scheme and realm, `DPoP-Nonce` to retry a
 * `use_dpop_nonce` refusal (RFC 9449 §8). None reveals anything to an origin
 * already allowed to read the body.
 */
const EXPOSED_RESPONSE_HEADERS = "WWW-Authenticate, Retry-After, DPoP-Nonce";

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
 * On the list, as a browser has reason to call each from another origin:
 *   - `POST /oauth/token`: the PKCE code exchange and refresh.
 *   - `GET|POST /oauth/userinfo`: OIDC Core §5.3 defines both methods.
 *   - `POST /oauth/revoke`: RFC 7009 §2.1 lets a public client revoke its own
 *     tokens (SPA sign-out).
 *   - the discovery documents ({@link discoveryPathsFor}) and the JWKS path
 *     the caller names (`options.jwksPath`: `assembleApp` passes the path the
 *     jwks module's route serves, and none without the module): public
 *     metadata, with paths from the same sources as the route registration
 *     and `jwks_uri`, so none can drift.
 *
 * Off the list:
 *   - `POST /oauth/introspect`: server-to-server; RFC 7662 §2.1 requires
 *     client authentication, and public clients are refused there.
 *   - `GET /oauth/authorize`: a top-level navigation, which CORS does not
 *     govern.
 *   - `/session/*`: cookie-backed, governed by the CSRF policy
 *     (`session.csrf.trustedOrigins`).
 *
 * The `/oauth/*` paths assume the bundled `oauthEndpointsModule`'s mountPath; a
 * downstream that re-mounts the OAuth router must build its own table.
 */
export function browserFacingCorsRoutes(
	config: {
		oauth?: { jwt?: { issuer?: unknown } };
	},
	options: {
		/**
		 * The issuer the discovery paths derive from, when the caller holds it
		 * apart from the config (`assembleApp` passes the `oauthTokenSettings`
		 * slot's, so table and discovery route name one issuer).
		 * `oauth.jwt.issuer` otherwise.
		 */
		readonly issuer?: string;
		/** The path a JWKS route serves; the table lists no JWKS path without one. */
		readonly jwksPath?: string;
	} = {},
): readonly CorsRoute[] {
	const issuer = options.issuer ?? config.oauth?.jwt?.issuer;
	const discovery = discoveryPathsFor(typeof issuer === "string" ? issuer : undefined);
	return [
		{ path: "/oauth/token", methods: ["POST"] },
		{ path: "/oauth/userinfo", methods: ["GET", "POST"] },
		{ path: "/oauth/revoke", methods: ["POST"] },
		...[...discovery.oidc, ...discovery.oauth].map((path) => ({ path, methods: ["GET"] })),
		...(options.jwksPath === undefined ? [] : [{ path: options.jwksPath, methods: ["GET"] }]),
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
function normalizePath(path: string): string {
	const lowered = path.toLowerCase();
	return lowered.length > 1 && lowered.endsWith("/") ? lowered.slice(0, -1) : lowered;
}

export interface CorsMiddlewareOptions {
	/** `cors.allowedOrigins`. Entries are re-checked; invalid ones are dropped with a warning. */
	readonly allowedOrigins: readonly string[];
	/** The CORS-enabled endpoints — normally {@link browserFacingCorsRoutes}. */
	readonly routes: readonly CorsRoute[];
	readonly logger?: Logger;
}

/**
 * Build the CORS middleware, or `null` when the allowlist is empty (or
 * entirely invalid): CORS is off and nothing is mounted, not even `Vary`.
 *
 * `allowedOrigins` is re-checked because a hand-built `httpSettings` never
 * passed a schema. A dropped entry is warned about by name: a silently
 * narrowed allowlist is as hard to diagnose as a silently absent one.
 */
export function corsMw(options: CorsMiddlewareOptions): RequestHandler | null {
	const logger = options.logger;
	const origins = new Set<string>();
	for (const entry of options.allowedOrigins) {
		const rejection =
			typeof entry === "string" ? checkSerializedOrigin(entry) : { reason: "unparsable" as const };
		if (rejection === null) {
			origins.add(entry);
			continue;
		}
		logger?.warn(
			`cors: ignoring cors.allowedOrigins entry ${JSON.stringify(entry)} — ${describeSerializedOriginRejection(rejection)}`,
		);
	}
	if (origins.size === 0) return null;

	const byPath = new Map<string, CorsRoute>();
	for (const route of options.routes) {
		byPath.set(normalizePath(route.path), route);
	}

	return (req: Request, res: Response, next: NextFunction): void => {
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
		const isPreflight =
			req.method === "OPTIONS" && req.headers["access-control-request-method"] !== undefined;

		if (typeof origin !== "string" || !origins.has(origin)) {
			// An unlisted or absent origin gets no CORS headers. A preflight still
			// ends here: falling through would 404 and point the operator at the
			// path rather than the allowlist. The absent header is what makes the
			// browser refuse.
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
