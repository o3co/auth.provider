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
 * CSRF protection for the state-changing session routes: two independent arms
 * (README, "CSRF on the state-changing routes").
 *
 * 1. **A signed double-submit token.** The value lives in a JS-readable cookie
 *    and must be echoed back in a header (or a form field). A cross-site
 *    attacker can neither write the victim's cookie for this origin nor set a
 *    custom header without a CORS preflight the provider never grants, so a
 *    matching pair is evidence the request was composed by same-site code.
 *    The signature means only the holder of the session secret can mint a
 *    token that verifies; a plain double-submit would trust whatever a sibling
 *    subdomain able to write a parent-domain cookie put there. The signature
 *    is the `csrfTokenSigner` slot's (`./csrf-token-signer.mts`), so nothing
 *    here holds the secret or the key. It is stateless because
 *    `POST /session/login` runs before there is a session to bind to, and with
 *    `saveUninitialized: false` an anonymous visitor has no stable session id.
 * 2. **A strict same-origin `Origin` / `Referer` check** with its own trust
 *    list (`session.csrf.trustedOrigins`), independent of the CORS list.
 *
 * {@link createCsrfGuard} composes them. {@link createSessionCsrfGuard} is the
 * same rule as core's `CsrfGuard`, beside the navigation rule a flow's start is
 * held to ({@link checkNavigationOrigin}).
 */

import { randomBytes } from "node:crypto";
import {
	auditErrorText,
	type CsrfGuard,
	type CsrfTokenSigner,
	type CsrfVerdict,
	consoleLogger,
	errorEnvelope,
	type Logger,
	type NavigationVerdict,
} from "@o3co/auth-provider-core";
import type { CookieOptions, NextFunction, Request, RequestHandler, Response } from "express";
import { constantTimeEquals } from "./internal/constantTimeEquals.mjs";
import { readCookie } from "./internal/cookies.mjs";

/** Default cookie carrying the double-submit value. */
export const DEFAULT_CSRF_COOKIE_NAME = "auth.csrf";
/** Default header the client echoes the cookie value back in. */
export const DEFAULT_CSRF_HEADER_NAME = "x-csrf-token";
/** Default body field for form posts that cannot set a header. */
export const DEFAULT_CSRF_BODY_FIELD = "csrf_token";
/** Default token lifetime. Two hours: long enough to outlive a login form. */
export const DEFAULT_CSRF_TTL_SECONDS = 7200;
/**
 * Ceiling on the token lifetime, in seconds (24 hours). A policy bound: past a
 * day the token stops outliving a login form and becomes a long-lived bearer
 * value in a JS-readable cookie. `reference.conf` and the
 * `session.csrf.ttlSeconds` schema restate this number (`session` depends on
 * `core`, not the reverse); a test in this package pins the schema to it.
 */
export const MAX_CSRF_TTL_SECONDS = 86_400;

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
	 * What signs and verifies a token's `<expiry>.<nonce>`: the
	 * `csrfTokenSigner` slot's signer, which the session store's module
	 * provides from `session.secret` (`createSessionCsrfTokenSigner`). The
	 * protection holds neither the secret nor the key.
	 */
	readonly signer: CsrfTokenSigner;
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

/** `<expiry-seconds>.<nonce>.<signature>` */
const TOKEN_SHAPE = /^(\d{1,15})\.([A-Za-z0-9_-]{16,})\.([A-Za-z0-9_-]{16,})$/;

/**
 * How far a token's expiry may lie past the latest one `issue` mints
 * (now + `ttlSeconds`): the clock skew between the replicas that mint and
 * check. A well-signed token expiring later was not minted by `issue`, and is
 * refused, so the signer is no oracle for a token that outlives the policy.
 */
const EXPIRY_SKEW_SECONDS = 60;

/** A signature the token can carry: base64url without padding, of a length a cookie holds. */
const SIGNATURE_SHAPE = /^[A-Za-z0-9_-]{16,512}$/;

/** What the signer is asked to sign when a protection is built over it. */
const PROBE_PAYLOADS = ["csrf-token-signer.probe.a", "csrf-token-signer.probe.b"] as const;

/** What a refusal of the signer tells the composition to pass instead. */
const PASS_A_SIGNER =
	"pass the csrfTokenSigner slot's signer, or createSessionCsrfTokenSigner(secret)";

/**
 * Reject a `ttlSeconds` that would silently disable the token arm.
 *
 * The value is stringified into the token's expiry field. A decimal mints an
 * expiry {@link TOKEN_SHAPE} rejects, so every token is unverifiable the
 * instant it is issued; a zero or negative value mints tokens already expired.
 * Either locks out every header-less client with nothing in the configuration
 * visibly wrong. Zero is the one to worry about: HOCON substitutes an empty
 * `SESSION_CSRF_TTL_SECONDS` as `""` and coercion turns that into `0`.
 *
 * The `session.csrf.ttlSeconds` schema enforces the same bounds; this guard
 * covers config that never meets it (a hand-built `AppConfig` from a test or
 * an embedder). It throws rather than rounding or clamping so that a typo in
 * security configuration is not hidden.
 */
const assertValidTtlSeconds = (ttlSeconds: number): void => {
	if (!Number.isInteger(ttlSeconds) || ttlSeconds <= 0 || ttlSeconds > MAX_CSRF_TTL_SECONDS) {
		throw new Error(
			`csrf: ttlSeconds must be an integer between 1 and ${MAX_CSRF_TTL_SECONDS} seconds, received ${String(ttlSeconds)}`,
		);
	}
};

/**
 * Whether `signature` is the signer's for `payload`: `verify` answering
 * `true`, and nothing else. A promise, a truthy value that is not `true`, or
 * a throw is a refusal, so a signer outside the contract cannot pass a forged
 * token and the check never throws.
 */
const verifies = (signer: CsrfTokenSigner, payload: string, signature: string): boolean => {
	try {
		return signer.verify(payload, signature) === true;
	} catch {
		return false;
	}
};

/** `signature` with its first character changed: every bit of it is signature, never padding. */
const tamperedSignature = (signature: string): string =>
	`${signature.startsWith("A") ? "B" : "A"}${signature.slice(1)}`;

/**
 * How `signer` breaks what a token needs of the `csrfTokenSigner` contract,
 * found by signing two payloads and checking the signatures; `undefined` when
 * it keeps it.
 */
const signerBreach = (signer: CsrfTokenSigner): string | undefined => {
	const [a, b] = PROBE_PAYLOADS;
	let signed: readonly unknown[];
	try {
		signed = [signer.sign(a), signer.sign(b)];
	} catch {
		return "sign threw";
	}
	const [forA, forB] = signed;
	if (typeof forA !== "string" || typeof forB !== "string") {
		return "sign does not answer a string";
	}
	if (!SIGNATURE_SHAPE.test(forA) || !SIGNATURE_SHAPE.test(forB)) {
		return "sign does not answer base64url without padding, 16 to 512 characters";
	}
	if (forA === forB) return "sign answers one signature for two payloads";
	if (!verifies(signer, a, forA)) return "verify does not answer true for sign's own signature";
	if (verifies(signer, a, tamperedSignature(forA))) return "verify accepts a changed signature";
	if (verifies(signer, b, forA)) return "verify accepts another payload's signature";
	return undefined;
};

/**
 * Reject a protection with nothing to sign with, or with a signer that breaks
 * the contract. A caller passing a `secret` in a signer's place, or a signer
 * whose `verify` answers a promise, would otherwise build a protection that
 * fails on its first request — or accepts a forged token — instead of refusing
 * at boot.
 */
const assertSigner: (signer: unknown) => asserts signer is CsrfTokenSigner = (signer) => {
	const candidate = signer as Partial<CsrfTokenSigner> | null | undefined;
	if (typeof candidate?.sign !== "function" || typeof candidate.verify !== "function") {
		throw new Error(`csrf: signer is required: ${PASS_A_SIGNER}`);
	}
	const breach = signerBreach(candidate as CsrfTokenSigner);
	if (breach !== undefined) {
		throw new Error(
			`csrf: the signer does not keep the csrfTokenSigner contract (${breach}): ${PASS_A_SIGNER}`,
		);
	}
};

export const createCsrfProtection = (options: CsrfProtectionOptions): CsrfProtection => {
	assertSigner(options.signer);
	const cookieName = options.cookieName ?? DEFAULT_CSRF_COOKIE_NAME;
	const headerName = (options.headerName ?? DEFAULT_CSRF_HEADER_NAME).toLowerCase();
	const bodyField = options.bodyField ?? DEFAULT_CSRF_BODY_FIELD;
	const ttlSeconds = options.ttlSeconds ?? DEFAULT_CSRF_TTL_SECONDS;
	assertValidTtlSeconds(ttlSeconds);
	const cookie = options.cookie ?? { secure: true, sameSite: "lax" as const };
	const now = options.now ?? Date.now;
	const { signer } = options;

	const mint = (): string => {
		const expires = Math.floor(now() / 1000) + ttlSeconds;
		const nonce = randomBytes(24).toString("base64url");
		return `${expires}.${nonce}.${signer.sign(`${expires}.${nonce}`)}`;
	};

	const isWellSigned = (token: string): boolean => {
		const match = TOKEN_SHAPE.exec(token);
		if (!match) return false;
		const [, expires, nonce, signature] = match;
		if (!verifies(signer, `${expires}.${nonce}`, signature ?? "")) return false;
		const expiresMs = Number(expires) * 1000;
		const current = now();
		return expiresMs > current && expiresMs <= current + (ttlSeconds + EXPIRY_SKEW_SECONDS) * 1000;
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
 * `trust proxy`, so that `req.protocol` and `req.host` read the forwarded
 * values the browser put in `Origin`.
 *
 * A header that is present but does not parse (`Origin: null` from a sandboxed
 * frame, a relative `Referer`) is `foreign`, not `absent`: absent means the
 * request carried no origin signal at all.
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
	 * Deliberately **not** `cors.allowedOrigins`: "this origin may read my
	 * responses" and "this origin may make me change state" are two decisions.
	 */
	readonly trustedOrigins?: readonly string[];
	readonly logger?: Logger;
}

/**
 * The acceptance rule.
 *
 * - A **foreign** `Origin` / `Referer` is rejected outright, token or no token:
 *   it is positive evidence that a browser made this request from another
 *   site. A legitimate non-browser client sends no `Origin`.
 * - A **same-origin or trusted** signal is accepted on its own, so the
 *   ordinary browser login form needs no client change.
 * - When **no** origin signal is present (the header-less API client), a valid
 *   double-submit token is required.
 *
 * So the two arms are alternatives for *presence*, and the origin arm is
 * authoritative when it is present.
 */
export const createCsrfGuard = ({
	csrf,
	trustedOrigins = [],
	logger = consoleLogger,
}: CsrfGuardOptions): RequestHandler => {
	return (req: Request, res: Response, next: NextFunction): void => {
		const verdict = judgeRequest(req, csrf, trustedOrigins);
		if (verdict.outcome === "refused" && verdict.reason === "foreign_origin") {
			const rawOrigin = req.headers?.origin;
			const origin = Array.isArray(rawOrigin) ? rawOrigin[0] : rawOrigin;
			// Both are the caller's: sanitised and capped (`auditErrorText`).
			logger.warn(
				{ origin: auditErrorText(origin ?? ""), path: auditErrorText(req.path) },
				"csrf_origin_rejected",
			);
			res.status(403).json(errorEnvelope("access_denied", "CSRF origin check failed"));
			return;
		}
		if (verdict.outcome === "refused") {
			logger.warn(
				{
					verdict: verdict.reason === "token_absent" ? "absent" : "invalid",
					path: auditErrorText(req.path),
				},
				"csrf_token_rejected",
			);
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
		next();
	};
};

/**
 * The acceptance rule of {@link createCsrfGuard} as a verdict: a foreign
 * origin refused, this origin or a trusted one accepted, and with neither the
 * double-submit token deciding. Reads the request alone and never throws.
 */
const judgeRequest = (
	req: Request,
	csrf: Pick<CsrfProtection, "verify">,
	trustedOrigins: readonly string[],
): CsrfVerdict => {
	const origin = checkRequestOrigin(req, trustedOrigins);
	if (origin === "foreign") return { outcome: "refused", reason: "foreign_origin" };
	if (origin !== "absent") return { outcome: "accepted" };
	const token = csrf.verify(req);
	if (token === "valid") return { outcome: "accepted" };
	return { outcome: "refused", reason: token === "absent" ? "token_absent" : "token_invalid" };
};

/**
 * Whether a navigation that starts a state-changing flow — the account-link
 * start, a GET a page navigates to — carries positive evidence that the user
 * asked for it on this deployment's own pages.
 *
 * Fetch Metadata answers first where the browser sends it: `same-origin` (a
 * page of this origin) and `none` (a typed URL or a bookmark) are accepted,
 * `cross-site` is refused. `same-site` is not enough: it is the registrable
 * domain, so a user-controlled sibling such as `blog.example.com` sends it too.
 * That, an absent header (a browser predating Fetch Metadata still carries the
 * SameSite=Lax cookie on a cross-site navigation) and an unknown value fall to
 * the origin the request names, which must be this origin or one on
 * `trustedOrigins`. A GET
 * navigation sends no `Origin`, so that is the `Referer`, and a missing one is
 * refused because the navigating page chooses its own referrer policy. A token
 * never counts: a navigation carries none.
 */
export const checkNavigationOrigin = (
	req: Request,
	trustedOrigins: readonly string[] = [],
): NavigationVerdict => {
	const site = req.get("sec-fetch-site");
	if (site === "same-origin" || site === "none") return { outcome: "accepted" };
	if (site === "cross-site") return { outcome: "refused", reason: "cross_site" };
	const verdict = checkRequestOrigin(req, trustedOrigins);
	if (verdict === "absent") return { outcome: "refused", reason: "origin_absent" };
	if (verdict === "foreign") return { outcome: "refused", reason: "foreign_origin" };
	return { outcome: "accepted" };
};

/**
 * The session package's CSRF policy as core's `CsrfGuard` — the `csrfGuard`
 * slot the session module provides, so that device verification and every
 * other state-changing browser route outside this package runs the one policy
 * `/session/login` runs instead of rebuilding it from the session config.
 *
 * - `check` is {@link createCsrfGuard}'s rule as a verdict, and `middleware`
 *   is {@link createCsrfGuard} itself (same `403 access_denied`, same
 *   `csrf_origin_rejected` / `csrf_token_rejected` warn line on `logger`).
 * - `checkNavigation` is {@link checkNavigationOrigin} over the same trust
 *   list: the rule the account-link start is held to.
 * - `issue` sets a fresh token in `csrf`'s cookie, which the session module
 *   names from the session cookie and gives its attributes.
 *
 * `csrf` signs through the `csrfTokenSigner` slot, which the session store's
 * module fills from `session.secret`: the session module builds it with
 * {@link createCsrfProtectionFromConfig}, as the session routes build theirs,
 * so a token either issues passes the other's check.
 */
export const createSessionCsrfGuard = ({
	csrf,
	trustedOrigins = [],
	logger = consoleLogger,
}: CsrfGuardOptions): CsrfGuard => {
	const trusted = Object.freeze([...trustedOrigins]);
	return Object.freeze({
		cookieName: csrf.cookieName,
		headerName: csrf.headerName,
		bodyField: csrf.bodyField,
		check: (req: Request): CsrfVerdict => judgeRequest(req, csrf, trusted),
		checkNavigation: (req: Request): NavigationVerdict => checkNavigationOrigin(req, trusted),
		middleware: createCsrfGuard({ csrf, trustedOrigins: trusted, logger }),
		issue: (res: Response): string => csrf.issue(res),
	});
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
 * Build the protection from the `session` config slice, signing through
 * `options.signer` (the `csrfTokenSigner` slot's signer). The slice carries no
 * secret: this reads the cookie's name and attributes and the token's lifetime.
 *
 * The cookie name is derived as `<session.name>.csrf`, so it inherits the
 * session cookie's prefix. For `__Host-` that means the CSRF cookie cannot
 * disagree with `sessionStoreModule`'s boot guard (`secure` on, no domain): a
 * `__Host-` cookie the browser silently drops would look exactly like a client
 * that forgot to send the token.
 */
export const createCsrfProtectionFromConfig = (
	session: SessionCsrfConfigSlice,
	options: Pick<CsrfProtectionOptions, "signer"> & Partial<CsrfProtectionOptions>,
): CsrfProtection =>
	createCsrfProtection({
		cookieName: `${session.name}.csrf`,
		ttlSeconds: session.csrf?.ttlSeconds ?? DEFAULT_CSRF_TTL_SECONDS,
		cookie: {
			secure: session.secure,
			sameSite: session.sameSite,
			...(session.domain ? { domain: session.domain } : {}),
		},
		...options,
	});
