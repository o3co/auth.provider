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
 * CSRF protection for the state-changing session routes (#272).
 *
 * Before this module the defence was one `Origin` comparison that called
 * `next()` whenever the header was absent — so any caller able to omit
 * `Origin` walked past it — and the list it compared against was
 * `cors.allowedOrigins`, a resource-sharing policy pressed into service as a
 * trust policy. There was no token to fall back on.
 *
 * Two independent arms replace it:
 *
 * 1. **A signed double-submit token.** The value lives in a JS-readable cookie
 *    and must be echoed back in a header (or a form field). A cross-site
 *    attacker can neither write the victim's cookie for this origin nor set a
 *    custom header on a cross-site request without a CORS preflight the
 *    provider never grants, so holding a matching pair is evidence the request
 *    was composed by same-site code.
 *
 *    The token is *signed* rather than an opaque random string. A plain
 *    double-submit trusts whatever is in the cookie, which a sibling subdomain
 *    that can write a parent-domain cookie can supply. An HMAC over the value
 *    means only this provider can mint one that verifies. It is stateless on
 *    purpose: `POST /session/login` is reached *before* there is a session to
 *    bind to, and with `saveUninitialized: false` an anonymous visitor has no
 *    stable session id to key against either.
 *
 * 2. **A strict same-origin `Origin` / `Referer` check** with its own trust
 *    list (`session.csrf.trustedOrigins`), independent of the CORS list.
 *
 * The composed rule is in {@link createCsrfGuard}.
 */

import { createHash, createHmac, hkdfSync, randomBytes, timingSafeEqual } from "node:crypto";
import { consoleLogger, errorEnvelope, type Logger } from "@o3co/auth-provider-core";
import type { CookieOptions, NextFunction, Request, RequestHandler, Response } from "express";

/** Default cookie carrying the double-submit value. */
export const DEFAULT_CSRF_COOKIE_NAME = "auth.csrf";
/** Default header the client echoes the cookie value back in. */
export const DEFAULT_CSRF_HEADER_NAME = "x-csrf-token";
/** Default body field for form posts that cannot set a header. */
export const DEFAULT_CSRF_BODY_FIELD = "csrf_token";
/** Default token lifetime. Two hours: long enough to outlive a login form. */
export const DEFAULT_CSRF_TTL_SECONDS = 7200;

/**
 * HKDF `info` string. The signing key is derived from the session secret
 * rather than being the session secret, so a token signature can never be
 * confused with — or used as an oracle against — a session cookie signature.
 * The version suffix is what a future format change bumps to invalidate every
 * token in flight in one move.
 */
const CSRF_KEY_INFO = "o3co.auth.provider/session-csrf/v1";

/** Bounds what a rejected request can write into the log. */
const MAX_LOGGED_ORIGIN_LENGTH = 256;

/**
 * What the token arm concluded.
 *
 * `absent` and `invalid` are kept apart deliberately: absence is the ordinary
 * state of a browser request that is relying on the origin arm, while
 * `invalid` means material was presented and did not check out.
 */
export type CsrfTokenVerdict = "valid" | "absent" | "invalid";

/** What the origin arm concluded. */
export type CsrfOriginVerdict = "same-origin" | "trusted" | "foreign" | "absent";

/** Transport attributes for the CSRF cookie — mirror the session cookie's. */
export interface CsrfCookieAttributes {
	readonly secure: boolean;
	readonly sameSite: "lax" | "strict" | "none";
	readonly domain?: string | undefined;
}

export interface CsrfProtectionOptions {
	/**
	 * Secret the signing key is derived from. Pass `session.secret`; the key
	 * itself is an HKDF expansion of it, never the secret.
	 */
	readonly secret: string;
	readonly cookieName?: string;
	readonly headerName?: string;
	readonly bodyField?: string;
	readonly ttlSeconds?: number;
	readonly cookie?: CsrfCookieAttributes;
	/** Clock seam for tests. */
	readonly now?: () => number;
}

export interface CsrfProtection {
	readonly cookieName: string;
	readonly headerName: string;
	readonly bodyField: string;
	readonly ttlSeconds: number;
	/** Mint a signed token without touching the response. */
	mint(): string;
	/** Mint a token and set the paired cookie on `res`. Returns the token. */
	issue(res: Response): string;
	/** Check the double-submit pair carried by `req`. */
	verify(req: Request): CsrfTokenVerdict;
}

const deriveSigningKey = (secret: string): Buffer =>
	Buffer.from(hkdfSync("sha256", secret, "", CSRF_KEY_INFO, 32));

const sign = (key: Buffer, payload: string): string =>
	createHmac("sha256", key).update(payload, "utf8").digest("base64url");

/**
 * Length-independent constant-time comparison.
 *
 * `timingSafeEqual` throws on differing lengths, and guarding that with a
 * length check leaks the length. Comparing fixed-width digests of the inputs
 * sidesteps both.
 */
const constantTimeEquals = (a: string, b: string): boolean =>
	timingSafeEqual(
		createHash("sha256").update(a, "utf8").digest(),
		createHash("sha256").update(b, "utf8").digest(),
	);

/** `<expiry-seconds>.<nonce>.<signature>` */
const TOKEN_SHAPE = /^(\d{1,15})\.([A-Za-z0-9_-]{16,})\.([A-Za-z0-9_-]{16,})$/;

const readCookie = (req: Request, name: string): string | undefined => {
	// cookie-parser is not a dependency of this package, but a composition root
	// is free to mount it; prefer its output when present.
	const parsed = (req as { cookies?: unknown }).cookies;
	if (parsed !== null && typeof parsed === "object") {
		const value = (parsed as Record<string, unknown>)[name];
		if (typeof value === "string" && value.length > 0) return value;
	}
	const header = req.headers?.cookie;
	if (typeof header !== "string") return undefined;
	for (const pair of header.split(";")) {
		const eq = pair.indexOf("=");
		if (eq === -1) continue;
		if (pair.slice(0, eq).trim() !== name) continue;
		const raw = pair.slice(eq + 1).trim();
		try {
			return decodeURIComponent(raw);
		} catch {
			// A cookie value that is not valid percent-encoding is not one we
			// issued. Hand back the raw text and let signature verification
			// reject it, rather than throwing out of a request guard.
			return raw;
		}
	}
	return undefined;
};

export const createCsrfProtection = (options: CsrfProtectionOptions): CsrfProtection => {
	const cookieName = options.cookieName ?? DEFAULT_CSRF_COOKIE_NAME;
	const headerName = (options.headerName ?? DEFAULT_CSRF_HEADER_NAME).toLowerCase();
	const bodyField = options.bodyField ?? DEFAULT_CSRF_BODY_FIELD;
	const ttlSeconds = options.ttlSeconds ?? DEFAULT_CSRF_TTL_SECONDS;
	const cookie = options.cookie ?? { secure: true, sameSite: "lax" as const };
	const now = options.now ?? Date.now;
	const key = deriveSigningKey(options.secret);

	const mint = (): string => {
		const expires = Math.floor(now() / 1000) + ttlSeconds;
		const nonce = randomBytes(24).toString("base64url");
		return `${expires}.${nonce}.${sign(key, `${expires}.${nonce}`)}`;
	};

	const isWellSigned = (token: string): boolean => {
		const match = TOKEN_SHAPE.exec(token);
		if (!match) return false;
		const [, expires, nonce, signature] = match;
		if (!constantTimeEquals(signature ?? "", sign(key, `${expires}.${nonce}`))) return false;
		return Number(expires) * 1000 > now();
	};

	const readSubmitted = (req: Request): string | undefined => {
		const raw = req.headers?.[headerName];
		const fromHeader = Array.isArray(raw) ? raw[0] : raw;
		if (typeof fromHeader === "string" && fromHeader.length > 0) return fromHeader;
		const body = (req as { body?: unknown }).body;
		if (body === null || typeof body !== "object") return undefined;
		const fromBody = (body as Record<string, unknown>)[bodyField];
		return typeof fromBody === "string" && fromBody.length > 0 ? fromBody : undefined;
	};

	return {
		cookieName,
		headerName,
		bodyField,
		ttlSeconds,
		mint,
		issue(res: Response): string {
			const token = mint();
			const cookieOptions: CookieOptions = {
				// Readable by script on purpose: the client's whole job is to copy
				// this value into a header. It is not a credential — possessing it
				// proves nothing except that same-site code read the cookie, which
				// is exactly the claim being made.
				httpOnly: false,
				path: "/",
				secure: cookie.secure,
				sameSite: cookie.sameSite,
				maxAge: ttlSeconds * 1000,
				...(cookie.domain ? { domain: cookie.domain } : {}),
			};
			res.cookie(cookieName, token, cookieOptions);
			return token;
		},
		verify(req: Request): CsrfTokenVerdict {
			const fromCookie = readCookie(req, cookieName);
			const submitted = readSubmitted(req);
			if (fromCookie === undefined && submitted === undefined) return "absent";
			if (fromCookie === undefined || submitted === undefined) return "invalid";
			if (!constantTimeEquals(fromCookie, submitted)) return "invalid";
			return isWellSigned(fromCookie) ? "valid" : "invalid";
		},
	};
};

const normalizeOrigin = (raw: string): string | undefined => {
	try {
		return new URL(raw).origin;
	} catch {
		return undefined;
	}
};

/**
 * Classify a request's `Origin` — falling back to `Referer` — against the
 * server's own origin and an explicit trust list.
 *
 * Behind a reverse proxy the server origin is only correct when the app sets
 * `trust proxy`; `req.protocol` and `req.host` then read the forwarded values,
 * which is what the browser actually put in `Origin`.
 *
 * A header that is present but does not parse — `Origin: null` from a
 * sandboxed frame, a relative `Referer` — is `foreign`, not `absent`. Absent
 * means the request carried no origin signal at all; a signal that fails to
 * name this origin is not the same thing.
 */
export const checkRequestOrigin = (
	req: Request,
	trustedOrigins: readonly string[] = [],
): CsrfOriginVerdict => {
	const rawOrigin = req.headers?.origin;
	const origin = Array.isArray(rawOrigin) ? rawOrigin[0] : rawOrigin;
	const rawReferer = req.headers?.referer;
	const referer = Array.isArray(rawReferer) ? rawReferer[0] : rawReferer;

	const claimed = origin && origin.length > 0 ? origin : referer;
	if (claimed === undefined || claimed.length === 0) return "absent";

	const candidate = normalizeOrigin(claimed);
	if (candidate === undefined) return "foreign";

	const host = req.host || req.headers?.host;
	const server = host ? normalizeOrigin(`${req.protocol}://${host}`) : undefined;
	if (server !== undefined && candidate === server) return "same-origin";

	for (const trusted of trustedOrigins) {
		if (normalizeOrigin(trusted) === candidate) return "trusted";
	}
	return "foreign";
};

export interface CsrfGuardOptions {
	readonly csrf: CsrfProtection;
	/**
	 * Origins other than the server's own that may satisfy the origin arm.
	 *
	 * Deliberately **not** `cors.allowedOrigins`: "this origin may read my
	 * responses" and "this origin may make me change state" are two decisions,
	 * and #272 was filed because one list was answering both.
	 */
	readonly trustedOrigins?: readonly string[];
	readonly logger?: Logger;
}

/**
 * The acceptance rule.
 *
 * - A **foreign** `Origin` / `Referer` is rejected outright, token or no token.
 *   A foreign origin is positive evidence that a browser made this request from
 *   another site; the pre-#272 guard already rejected it and a security fix must
 *   not hand that back. A legitimate non-browser client simply sends no
 *   `Origin`, so nothing that worked before is lost.
 * - A **same-origin or trusted** signal is accepted on its own. This is what
 *   keeps the ordinary browser login form working with no client change.
 * - When **no** origin signal is present — the header-less API client, and the
 *   exact case the old code waved through — a valid double-submit token is
 *   required.
 *
 * So the two arms are alternatives for *presence*, and the origin arm is
 * authoritative when it is present. Rejection happens when both are missing, or
 * when either positively contradicts the request.
 */
export const createCsrfGuard = ({
	csrf,
	trustedOrigins = [],
	logger = consoleLogger,
}: CsrfGuardOptions): RequestHandler => {
	return (req: Request, res: Response, next: NextFunction): void => {
		const originVerdict = checkRequestOrigin(req, trustedOrigins);
		if (originVerdict === "foreign") {
			const rawOrigin = req.headers?.origin;
			const origin = Array.isArray(rawOrigin) ? rawOrigin[0] : rawOrigin;
			logger.warn(
				{ origin: (origin ?? "").slice(0, MAX_LOGGED_ORIGIN_LENGTH), path: req.path },
				"csrf_origin_rejected",
			);
			res.status(403).json(errorEnvelope("access_denied", "CSRF origin check failed"));
			return;
		}
		if (originVerdict === "absent") {
			const tokenVerdict = csrf.verify(req);
			if (tokenVerdict !== "valid") {
				logger.warn({ verdict: tokenVerdict, path: req.path }, "csrf_token_rejected");
				res
					.status(403)
					.json(
						errorEnvelope(
							"access_denied",
							`CSRF check failed: send a same-origin Origin or Referer header, or a double-submit CSRF token (the ${csrf.cookieName} cookie echoed in the ${csrf.headerName} header)`,
						),
					);
				return;
			}
		}
		next();
	};
};

/**
 * Handler for the endpoint that hands a browser its first token.
 *
 * The endpoint is unauthenticated and stateless, so an attacker can fetch a
 * token of their own — which buys them nothing. Forging a request still
 * requires writing the victim's cookie for this origin, which is what the
 * same-site cookie boundary denies them.
 */
export const createCsrfIssueHandler = (csrf: CsrfProtection): RequestHandler => {
	return (_req: Request, res: Response): void => {
		const token = csrf.issue(res);
		// A cached token would be handed to a second user along with the first
		// user's cookie, and the pair would no longer match.
		res.set("Cache-Control", "no-store");
		res.status(200).json({
			csrf_token: token,
			cookie_name: csrf.cookieName,
			header_name: csrf.headerName,
			body_field: csrf.bodyField,
			expires_in: csrf.ttlSeconds,
		});
	};
};

/**
 * The `session.*` slice this module reads. Declared structurally so the helper
 * can be called with a partial config in tests without an `AppConfig` cast.
 */
export interface SessionCsrfConfigSlice {
	readonly secret: string;
	readonly name: string;
	readonly secure: boolean;
	readonly sameSite: "lax" | "strict" | "none";
	readonly domain: string | null;
	readonly csrf?:
		| {
				readonly trustedOrigins?: readonly string[];
				readonly ttlSeconds?: number;
		  }
		| undefined;
}

/**
 * Build the protection from the `session` config slice.
 *
 * The cookie name is derived as `<session.name>.csrf` rather than configured
 * separately, so it inherits whatever prefix the session cookie already
 * carries. That matters for `__Host-`: the boot guard in `sessionStoreModule`
 * already refuses a `__Host-` session name unless `secure` is on and no domain
 * is set, and deriving from it means the CSRF cookie can never disagree with
 * that verdict — a `__Host-` cookie the browser silently drops would look
 * exactly like a client that forgot to send the token.
 */
export const createCsrfProtectionFromConfig = (
	session: SessionCsrfConfigSlice,
	overrides: Partial<CsrfProtectionOptions> = {},
): CsrfProtection =>
	createCsrfProtection({
		secret: session.secret,
		cookieName: `${session.name}.csrf`,
		ttlSeconds: session.csrf?.ttlSeconds ?? DEFAULT_CSRF_TTL_SECONDS,
		cookie: {
			secure: session.secure,
			sameSite: session.sameSite,
			...(session.domain ? { domain: session.domain } : {}),
		},
		...overrides,
	});
