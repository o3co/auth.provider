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
 * What the session package owns of the browser session that other packages
 * use, as three slots whose contracts are core's (#728): the login page a
 * browser that is not signed in is sent to (`loginEntry`), the one policy
 * for whether a browser's request may change state (`csrfGuard`, #710),
 * and the session cookie's attributes (`cookiePolicy`). The session package
 * owns the configuration behind them; another package requires the slot
 * rather than reading that configuration or rebuilding the policy from it.
 *
 * The contract suites and test doubles are published on
 * `@o3co/auth-provider-core/testing`. Types only.
 */

import type { Request, RequestHandler, Response } from "express";

/**
 * The deployment's login page, and how a browser is sent there to come
 * back: a consumer that meets a browser which is not signed in — `/authorize`,
 * the federation-grants connect flow — redirects it to `urlFor(returnTo)`.
 */
export interface LoginEntry {
	/** The login page: a path or an absolute URL, which may carry a query of its own. */
	readonly url: string;
	/**
	 * The login page with `redirect_to` naming `returnTo` — where the browser
	 * comes back once signed in — added to the page's own query, the target
	 * encoded whole so that nothing of it reads as the page's query or
	 * fragment. The caller chooses `returnTo` (a URL on the issuer's origin);
	 * the login route holds what comes back to its allowlist.
	 */
	urlFor(returnTo: string): string;
}

/** Whether a browser's request may change state, and why not. */
export type CsrfVerdict =
	| { readonly outcome: "accepted" }
	| {
			readonly outcome: "refused";
			readonly reason: "foreign_origin" | "token_absent" | "token_invalid";
	  };

/** Whether a navigation may start a flow that will change state, and why not. */
export type NavigationVerdict =
	| { readonly outcome: "accepted" }
	| {
			readonly outcome: "refused";
			readonly reason: "cross_site" | "foreign_origin" | "origin_absent";
	  };

/**
 * The one policy for whether a browser may change state (#272; #710, C4),
 * in its two forms.
 *
 * - **A request that changes state** (`check`, `middleware`) — a login, a
 *   logout, device verification, an MFA route, the federation-grants
 *   consent answer. A request whose `Origin` — or, without one, `Referer` —
 *   names another origin is refused whatever else it carries; one that
 *   names this origin or a trusted one is accepted; with neither, a signed
 *   double-submit token decides: the value of the `cookieName` cookie,
 *   echoed in the `headerName` header or in the `bodyField` of a parsed
 *   form body.
 * - **A navigation that starts such a flow** (`checkNavigation`) — the
 *   account-link start, a GET a page navigates to, which carries no token
 *   and often no `Origin`. `Sec-Fetch-Site` answers first where the browser
 *   sends it: `same-origin` and `none` (a typed URL, a bookmark) are
 *   accepted, `cross-site` is refused; otherwise — `same-site`, which a
 *   sibling subdomain sends too, an unknown value, or none — the `Origin`
 *   or `Referer` the request names is held to this origin and the trusted
 *   ones, and a request that names neither is refused.
 *
 * Open (#728): the token's signing key is derived from the session
 * cookie's secret, which the session store's module owns, while the
 * session module provides the guard; how the key reaches the guard's
 * provider is decided with the provider.
 */
export interface CsrfGuard {
	/** The cookie the double-submit token is set in; script reads it. */
	readonly cookieName: string;
	/** The request header the token is echoed in. */
	readonly headerName: string;
	/**
	 * The field of a parsed form body the token may be echoed in instead of
	 * the header; absent when the guard reads the header alone.
	 */
	readonly bodyField?: string;
	/**
	 * The request policy's verdict on `req`, for a route that answers a
	 * refusal in its own vocabulary. Reads the request alone — its headers,
	 * its cookies and, for `bodyField`, its parsed body — and never throws.
	 */
	check(req: Request): CsrfVerdict;
	/** The navigation policy's verdict on `req`. Reads its headers alone; never throws, never reads a token. */
	checkNavigation(req: Request): NavigationVerdict;
	/**
	 * The request policy as middleware: hands the request on when `check`
	 * accepts it; otherwise answers `403 access_denied` itself, and the
	 * route never runs.
	 */
	readonly middleware: RequestHandler;
	/**
	 * Sets a fresh token on `res` — in the `cookieName` cookie, readable by
	 * script, on path `/`, secure, same-site and scoped as the session
	 * cookie is — and answers it.
	 */
	issue(res: Response): string;
}

/**
 * The session cookie's attributes: what a module that sets a cookie of its
 * own beside the session's — or that sizes what must outlive a session —
 * needs of them.
 */
export interface SessionCookiePolicy {
	/** The session cookie's name. A cookie named from it inherits its prefix (`__Host-`). */
	readonly name: string;
	readonly secure: boolean;
	readonly sameSite: "lax" | "strict" | "none";
	/** The cookie's `Domain`; `undefined` for a host-only cookie. */
	readonly domain: string | undefined;
	/** The session's lifetime, in milliseconds: the cookie's `Max-Age`, and how long a session record lives. */
	readonly maxAgeMs: number;
}

// ---------------------------------------------------------------------------
// ComponentMap declaration-merge
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		/** The login page and the `redirect_to` protocol (#728): provided by the session module. */
		readonly loginEntry?: LoginEntry;
		/** The one browser-origin / CSRF policy (#728, #710): provided by the session module. */
		readonly csrfGuard?: CsrfGuard;
		/** The session cookie's attributes (#728): provided by the module that owns the session cookie. */
		readonly cookiePolicy?: SessionCookiePolicy;
	}
}
