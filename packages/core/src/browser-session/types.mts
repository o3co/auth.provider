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
 * use, as slots whose contracts are core's: the login page (`loginEntry`),
 * the one policy for whether a browser's request may change state
 * (`csrfGuard`), the session cookie's attributes (`sessionCookiePolicy`), and
 * the CSRF token's signature (`csrfTokenSigner`). Another package requires
 * the slot rather than reading the session configuration or rebuilding the
 * policy from it. Contract suites and test doubles are published on
 * `@o3co/auth-provider-core/testing`. Types only.
 */

import type { Request, RequestHandler, Response } from "express";

/**
 * The deployment's login page, and how a browser is sent there to come
 * back: a consumer that meets a browser which is not signed in — `/authorize`,
 * the federation-grants connect flow — redirects it to `urlFor(returnTo)`.
 */
export interface LoginEntry {
	/**
	 * The login page: a path or an absolute URL, which may carry a query and a
	 * fragment of its own, but not `redirect_to` — `urlFor` adds it.
	 */
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
 * The one policy for whether a browser may change state, in two forms:
 *
 * - **A request that changes state** (`check`, `middleware`): a login, a
 *   logout, device verification, an MFA route, the federation-grants consent
 *   answer. An `Origin` (or, without one, `Referer`) naming another origin is
 *   refused whatever else the request carries; one naming this origin or a
 *   trusted one is accepted; with neither, a signed double-submit token
 *   decides: the `cookieName` cookie's value, echoed in the `headerName`
 *   header or the `bodyField` of a parsed form body.
 * - **A navigation that starts such a flow** (`checkNavigation`): the
 *   account-link start, a GET that carries no token and often no `Origin`.
 *   `Sec-Fetch-Site` answers first where sent: `same-origin` and `none` (a
 *   typed URL, a bookmark) are accepted, `cross-site` is refused. Otherwise
 *   (`same-site`, which a sibling subdomain also sends, an unknown value, or
 *   none) the `Origin` or `Referer` is held to this origin and the trusted
 *   ones, and a request naming neither is refused.
 *
 * The token's signing key is derived from the session cookie's secret, which
 * the session store's module owns, while the session module provides the
 * guard: the guard's provider signs and checks the token through
 * `csrfTokenSigner`, and never holds the secret or the key.
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
 * The CSRF token's signature: what the `csrfGuard` provider signs and checks
 * a double-submit token with, without holding the key.
 *
 * The key's one owner, the module owning the session cookie's secret
 * (`session.secret`, the session store's), derives it from that secret for
 * this purpose alone, so a token's signature is never a session cookie's nor
 * an oracle for one. The derivation is the owner's: providers that derive it
 * differently do not verify each other's tokens (switching invalidates the
 * short-lived outstanding ones), and a provider that must keep verifying an
 * earlier one's tokens pins that derivation in its own tests. Neither the
 * secret nor the key leaves the signer: a frozen plain object (prototype
 * `Object.prototype` or `null`) carrying `sign` and `verify` alone, own or
 * inherited.
 */
export interface CsrfTokenSigner {
	/**
	 * The signature of `payload` under this signer's key: a non-empty
	 * base64url string without padding — it sits between a token's `.`
	 * separators — and the same one for the same payload.
	 */
	sign(payload: string): string;
	/**
	 * Whether `signature` is what `sign(payload)` answers. Compared in
	 * constant time, so how much of a guess was right does not show in how
	 * long the answer takes; never throws — an empty, non-base64url or
	 * wrong-length signature, or a value that is not a string, is `false`.
	 */
	verify(payload: string, signature: string): boolean;
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
		/** The login page and the `redirect_to` protocol: provided by the session module. */
		readonly loginEntry?: LoginEntry;
		/** The one browser-origin / CSRF policy: provided by the session module. */
		readonly csrfGuard?: CsrfGuard;
		/**
		 * The CSRF token's signature: provided by the module that owns the
		 * session cookie's secret (the session store's), read by the `csrfGuard`
		 * provider.
		 */
		readonly csrfTokenSigner?: CsrfTokenSigner;
		/** The session cookie's attributes: provided by the session store's module, which owns the session cookie. */
		readonly sessionCookiePolicy?: SessionCookiePolicy;
	}
}
