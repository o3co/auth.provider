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
 * The contract suite of the `csrfGuard` slot (#728, #710) and its test
 * double.
 *
 * `csrfGuardContract(input)` drives a guard over the fake requests of
 * `fake-http.mts`, served on one origin, and holds it to the session
 * package's rules.
 *
 * - **A request** (`check`, `middleware`, #272): an `Origin` — or, without
 *   one, a `Referer` — that names another origin (`null`, another scheme,
 *   another host) is refused whatever the request carries, a valid token
 *   included; one that names this origin, or the trusted origin the input
 *   names, is accepted without a token; with neither, the token decides.
 *   Absent is refused. The one `issue` set is accepted, echoed in
 *   `headerName` or in `bodyField` when the guard names one. One that does
 *   not match its cookie, one with no cookie beside it, one with a
 *   character of its middle or its end changed (sent as cookie and header
 *   alike: an unsigned token passes a comparison of the two), and one the
 *   guard did not sign are refused; with `withClock`, so is one past its
 *   lifetime — the suite moves the clock 400 days on, past any lifetime a
 *   session keeps. `check` never throws on a malformed cookie, `Origin` or
 *   `Referer`; the middleware runs the route exactly when `check` accepts,
 *   answering `403 access_denied` otherwise.
 * - **A navigation** (`checkNavigation`, the link start): `Sec-Fetch-Site`
 *   `same-origin` or `none` is accepted, `cross-site` refused whatever the
 *   `Referer`; otherwise the `Origin` or `Referer` decides as above, and a
 *   navigation that names neither is refused — a token never counts.
 * - **The token's cookie** (`issue`): named `cookieName`, readable by
 *   script, on path `/`; secure and host-only under a `__Host-` name,
 *   secure under `__Secure-`; and with `sessionCookie`, secure, same-site
 *   and scoped as the session cookie is.
 * - **The guard** is frozen.
 *
 * Without `withClock` the suite does not check a token's expiry: a clock
 * cannot be set in a provider that does not take one.
 *
 * `createTestCsrfGuard` keeps these rules with a signing key of its own,
 * drawn when it is built, beside the session cookie it is given (the
 * fixture's by default). Published on `@o3co/auth-provider-core/testing`.
 */

import assert from "node:assert/strict";
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { Request, RequestHandler, Response } from "express";
import type {
	CsrfGuard,
	CsrfVerdict,
	NavigationVerdict,
	SessionCookiePolicy,
} from "../../browser-session/types.mjs";
import type { ContractCase } from "../../session-admission/testing/requirement.contract.mjs";
import { createTestSessionCookiePolicy } from "./cookiePolicy.mjs";
import {
	CONTRACT_ORIGIN,
	type FakeResponseRecord,
	fakeRequest,
	fakeResponse,
	runMiddleware,
} from "./fake-http.mjs";

export interface CsrfGuardContractInput {
	/** A fresh guard for each case, serving `https://idp.contract.test`. */
	readonly build: () => CsrfGuard;
	/** An origin the guard was built to trust beside its own, when it trusts one: accepted without a token. */
	readonly trustedOrigin?: string;
	/**
	 * The guard over a clock the suite sets (epoch milliseconds), when the
	 * provider takes one: a token past its lifetime must be refused. Absent,
	 * expiry is not checked.
	 */
	readonly withClock?: (now: () => number) => CsrfGuard;
	/** The session cookie the guard was built beside: the token's cookie is secure, same-site and scoped as it is. */
	readonly sessionCookie?: SessionCookiePolicy;
}

const FOREIGN_ORIGINS: readonly string[] = [
	"https://attacker.contract.test",
	"null",
	"http://idp.contract.test",
	"https://idp.contract.test.attacker.test",
];

/** Far past any lifetime a session keeps: the suite's clock moves this far on. */
const PAST_ANY_LIFETIME_MS = 400 * 86_400_000;

/** A request carrying `headers` (and `body`), and nothing else a browser would add. */
const requestWith = (
	headers: Record<string, string>,
	body?: Readonly<Record<string, unknown>>,
): Request => fakeRequest({ headers, ...(body === undefined ? {} : { body }) }).req;

/** A navigation carrying `headers`: a GET, as a link start is. */
const navigationWith = (headers: Record<string, string>): Request =>
	fakeRequest({ method: "GET", path: "/contract/start?link=1", headers }).req;

/** The one cookie named `name` the response was given. */
function tokenCookie(record: FakeResponseRecord, name: string) {
	const set = record.cookies.filter((c) => c.name === name);
	assert.equal(set.length, 1, `issue set ${set.length} cookies named ${name}, not one`);
	return set[0] as FakeResponseRecord["cookies"][number];
}

/** A token `guard` issued, and the headers that echo it: its cookie, and the header. */
function issued(guard: CsrfGuard): {
	readonly token: string;
	readonly cookie: string;
	readonly headers: Record<string, string>;
} {
	const { res, record } = fakeResponse();
	const token = guard.issue(res);
	const cookie = `${guard.cookieName}=${encodeURIComponent(tokenCookie(record, guard.cookieName).value)}`;
	return { token, cookie, headers: { cookie, [guard.headerName]: token } };
}

/**
 * `token` with one letter or digit changed for another of its class — the
 * first found from `from` in the direction `step` — so the token keeps its
 * shape and loses its signature.
 */
function tampered(token: string, from: number, step: 1 | -1): string {
	for (let i = from; i >= 0 && i < token.length; i += step) {
		const c = token.charAt(i);
		const swapped = /[0-9]/.test(c)
			? c === "0"
				? "1"
				: "0"
			: /[a-z]/.test(c)
				? c === "a"
					? "b"
					: "a"
				: /[A-Z]/.test(c)
					? c === "A"
						? "B"
						: "A"
					: undefined;
		if (swapped !== undefined) return `${token.slice(0, i)}${swapped}${token.slice(i + 1)}`;
	}
	throw new Error(`the token ${token} has no letter or digit to change`);
}

const refusedFor = (
	verdict: CsrfVerdict | NavigationVerdict,
	reason: string,
	what: string,
): void => {
	assert.deepEqual(verdict, { outcome: "refused", reason }, `${what} must be refused (${reason})`);
};

const acceptedFor = (verdict: CsrfVerdict | NavigationVerdict, what: string): void => {
	assert.deepEqual(verdict, { outcome: "accepted" }, `${what} must be accepted`);
};

/** Throws naming `what` when `run` throws, else answers what it answered. */
const withoutThrowing = <T,>(run: () => T, what: string): T => {
	try {
		return run();
	} catch (err) {
		throw new assert.AssertionError({
			message: `the guard threw on ${what}: ${err instanceof Error ? err.message : String(err)}`,
		});
	}
};

/** The cases of the `csrfGuard` contract over the guard `input` builds. */
export function csrfGuardContract(input: CsrfGuardContractInput): readonly ContractCase[] {
	const { build, trustedOrigin, withClock, sessionCookie } = input;
	const cases: ContractCase[] = [
		{
			name: "a request from this origin is accepted without a token, by its Origin or, without one, by its Referer",
			run: async () => {
				const guard = build();
				acceptedFor(guard.check(requestWith({ origin: CONTRACT_ORIGIN })), "a same-origin Origin");
				acceptedFor(
					guard.check(requestWith({ referer: `${CONTRACT_ORIGIN}/login?x=1` })),
					"a same-origin Referer with no Origin",
				);
			},
		},
		{
			name: "a foreign origin is refused whatever the request carries, a valid token included",
			run: async () => {
				const guard = build();
				const { headers } = issued(guard);
				for (const origin of FOREIGN_ORIGINS) {
					refusedFor(guard.check(requestWith({ origin })), "foreign_origin", `Origin ${origin}`);
					refusedFor(
						guard.check(requestWith({ ...headers, origin })),
						"foreign_origin",
						`Origin ${origin} with a valid token`,
					);
				}
				refusedFor(
					guard.check(requestWith({ ...headers, referer: "https://attacker.contract.test/page" })),
					"foreign_origin",
					"a foreign Referer with no Origin, and a valid token",
				);
			},
		},
		{
			name: "with no origin signal, a request without a token is refused",
			run: async () => {
				refusedFor(build().check(requestWith({})), "token_absent", "a request with nothing");
			},
		},
		{
			name: "with no origin signal, the token issue set is accepted, echoed in its header or, where the guard names one, its body field",
			run: async () => {
				const guard = build();
				const { token, cookie, headers } = issued(guard);
				acceptedFor(guard.check(requestWith(headers)), "the issued token, echoed in its header");
				if (guard.bodyField !== undefined) {
					acceptedFor(
						guard.check(requestWith({ cookie }, { [guard.bodyField]: token })),
						`the issued token, echoed in the body field ${guard.bodyField}`,
					);
				}
			},
		},
		{
			name: "with no origin signal, a token that does not match its cookie, has no cookie, was changed, or was not issued by the guard is refused",
			run: async () => {
				const guard = build();
				const first = issued(guard);
				const second = issued(guard);
				refusedFor(
					guard.check(requestWith({ ...first.headers, [guard.headerName]: second.token })),
					"token_invalid",
					"a token echoed beside another's cookie",
				);
				refusedFor(
					guard.check(requestWith({ cookie: first.cookie })),
					"token_invalid",
					"a cookie with no token echoed",
				);
				refusedFor(
					guard.check(requestWith({ [guard.headerName]: first.token })),
					"token_invalid",
					"the issued token echoed with no cookie beside it",
				);
				const { token } = first;
				for (const changed of [
					tampered(token, Math.floor(token.length / 2), 1),
					tampered(token, token.length - 2, -1),
				]) {
					refusedFor(
						guard.check(
							requestWith({
								cookie: `${guard.cookieName}=${encodeURIComponent(changed)}`,
								[guard.headerName]: changed,
							}),
						),
						"token_invalid",
						`the issued token with one character changed (${changed}), as cookie and header`,
					);
				}
				const forged = `9999999999.${"A".repeat(32)}.${"B".repeat(43)}`;
				refusedFor(
					guard.check(
						requestWith({ cookie: `${guard.cookieName}=${forged}`, [guard.headerName]: forged }),
					),
					"token_invalid",
					"a matching pair the guard did not sign",
				);
			},
		},
		{
			name: "issue sets the token in a cookie script can read, named cookieName, on path /, with the attributes its prefix and the session cookie require",
			run: async () => {
				const guard = build();
				const { res, record } = fakeResponse();
				const token = guard.issue(res);
				assert.ok(typeof token === "string" && token.length > 0, "issue answered no token");
				const { value, options } = tokenCookie(record, guard.cookieName);
				assert.equal(value, token, "the cookie carries another token than issue answered");
				assert.notEqual(
					options?.httpOnly,
					true,
					"the token's cookie is httpOnly: script cannot echo it",
				);
				assert.equal(
					options?.path,
					"/",
					"the token's cookie is not on path /: a route elsewhere never sees it",
				);
				const secure = options?.secure === true;
				const domain = options?.domain;
				if (guard.cookieName.startsWith("__Host-")) {
					assert.ok(
						secure && domain === undefined,
						"a __Host- cookie that is not secure and host-only is dropped by the browser",
					);
				}
				if (guard.cookieName.startsWith("__Secure-")) {
					assert.ok(secure, "a __Secure- cookie that is not secure is dropped by the browser");
				}
				if (sessionCookie !== undefined) {
					assert.equal(
						secure,
						sessionCookie.secure,
						"the token's cookie is not secure as the session cookie is",
					);
					assert.equal(
						typeof options?.sameSite === "string"
							? options.sameSite.toLowerCase()
							: options?.sameSite,
						sessionCookie.sameSite,
						"the token's cookie is not same-site as the session cookie is",
					);
					assert.equal(
						domain,
						sessionCookie.domain,
						"the token's cookie is not scoped as the session cookie is",
					);
				}
			},
		},
		{
			name: "check never throws: a malformed cookie, Origin or Referer is refused",
			run: async () => {
				const guard = build();
				const malformed: ReadonlyArray<readonly [Record<string, string>, string]> = [
					[
						{ cookie: `${guard.cookieName}=%E0%A4%A`, [guard.headerName]: "%E0%A4%A" },
						"a cookie that is not percent-encoding",
					],
					[{ cookie: "=;;; ;=%%%", [guard.headerName]: "x" }, "a cookie header that names nothing"],
					[{ origin: "::::" }, "an Origin that is not a URL"],
					[{ origin: "https://[bad" }, "an Origin with a broken host"],
					[{ referer: "not a url" }, "a Referer that is not a URL"],
				];
				for (const [headers, what] of malformed) {
					const verdict = withoutThrowing(() => guard.check(requestWith(headers)), what);
					assert.equal(verdict.outcome, "refused", `${what} must be refused`);
				}
			},
		},
		{
			name: "the middleware runs the route exactly when check accepts, and answers 403 access_denied otherwise",
			run: async () => {
				const guard = build();
				const { headers } = issued(guard);
				const requests: ReadonlyArray<Record<string, string>> = [
					{ origin: CONTRACT_ORIGIN },
					{ origin: "https://attacker.contract.test" },
					{},
					headers,
					{ ...headers, origin: "null" },
				];
				for (const requestHeaders of requests) {
					const verdict = guard.check(requestWith(requestHeaders));
					const run = await runMiddleware(guard.middleware, requestWith(requestHeaders));
					const what = `a request with ${JSON.stringify(Object.keys(requestHeaders))}`;
					if (verdict.outcome === "accepted") {
						assert.equal(
							run.next,
							1,
							`${what}: check accepts, the middleware did not run the route`,
						);
						assert.equal(run.nextError, undefined, `${what}: the route was handed an error`);
						assert.equal(run.response.ended, false, `${what}: the middleware answered it`);
					} else {
						assert.equal(run.next, 0, `${what}: check refuses, the middleware ran the route`);
						assert.equal(run.response.status, 403, `${what}: refused with another status`);
						assert.equal(
							(run.response.body as { readonly error?: unknown } | undefined)?.error,
							"access_denied",
							`${what}: refused with another error code`,
						);
					}
				}
			},
		},
		{
			name: "the guard is frozen",
			run: async () => {
				assert.ok(
					Object.isFrozen(build()),
					"the guard is not frozen: a module that holds it could replace its policy under the others",
				);
			},
		},
		{
			name: "a navigation that starts a flow is accepted from this origin, typed or bookmarked, refused cross-site, and otherwise held to its Origin or Referer — never to a token",
			run: async () => {
				const guard = build();
				const own = `${CONTRACT_ORIGIN}/account`;
				const foreign = "https://attacker.contract.test/page";
				const navigation = (headers: Record<string, string>, what: string): NavigationVerdict =>
					withoutThrowing(() => guard.checkNavigation(navigationWith(headers)), what);
				acceptedFor(
					navigation({ "sec-fetch-site": "same-origin" }, "same-origin"),
					"Sec-Fetch-Site same-origin",
				);
				acceptedFor(
					navigation({ "sec-fetch-site": "none" }, "none"),
					"Sec-Fetch-Site none (typed or bookmarked)",
				);
				refusedFor(
					navigation({ "sec-fetch-site": "cross-site", referer: own }, "cross-site"),
					"cross_site",
					"Sec-Fetch-Site cross-site, whatever the Referer",
				);
				acceptedFor(
					navigation({ "sec-fetch-site": "same-site", referer: own }, "same-site"),
					"Sec-Fetch-Site same-site from a page of this origin",
				);
				refusedFor(
					navigation({ "sec-fetch-site": "same-site", referer: foreign }, "same-site"),
					"foreign_origin",
					"Sec-Fetch-Site same-site from a sibling's page",
				);
				refusedFor(
					navigation({ "sec-fetch-site": "same-site" }, "same-site"),
					"origin_absent",
					"Sec-Fetch-Site same-site naming no page",
				);
				acceptedFor(
					navigation({ "sec-fetch-site": "something-new", referer: own }, "an unknown value"),
					"an unknown Sec-Fetch-Site from a page of this origin",
				);
				acceptedFor(
					navigation({ referer: own }, "a Referer"),
					"a page of this origin, no Sec-Fetch-Site",
				);
				acceptedFor(
					navigation({ origin: CONTRACT_ORIGIN }, "an Origin"),
					"this origin, no Sec-Fetch-Site",
				);
				refusedFor(
					navigation({ referer: foreign }, "a Referer"),
					"foreign_origin",
					"a foreign page",
				);
				refusedFor(
					navigation({ referer: "not a url" }, "a malformed Referer"),
					"foreign_origin",
					"a Referer that is not a URL",
				);
				refusedFor(navigation({}, "nothing"), "origin_absent", "a navigation naming no page");
				refusedFor(
					navigation(issued(guard).headers, "a token"),
					"origin_absent",
					"a navigation naming no page, with a valid token",
				);
			},
		},
	];
	if (withClock !== undefined) {
		cases.push({
			name: "a token past its lifetime is refused",
			run: async () => {
				let now = Date.now();
				const guard = withClock(() => now);
				const { headers } = issued(guard);
				acceptedFor(guard.check(requestWith(headers)), "the token, when it was issued");
				now += PAST_ANY_LIFETIME_MS;
				refusedFor(guard.check(requestWith(headers)), "token_invalid", "the token, 400 days on");
			},
		});
	}
	if (trustedOrigin !== undefined) {
		cases.push({
			name: "a trusted origin is accepted without a token, for a request and for a navigation",
			run: async () => {
				const guard = build();
				acceptedFor(guard.check(requestWith({ origin: trustedOrigin })), `Origin ${trustedOrigin}`);
				acceptedFor(
					guard.checkNavigation(navigationWith({ referer: `${trustedOrigin}/page` })),
					`a navigation from ${trustedOrigin}`,
				);
			},
		});
	}
	return cases;
}

export interface TestCsrfGuardOptions {
	/** Origins other than the request's own a request may come from without a token. */
	readonly trustedOrigins?: readonly string[];
	/** The session cookie the guard stands beside: its token cookie is named from it and shares its attributes. The fixture's by default. */
	readonly sessionCookie?: SessionCookiePolicy;
	/** The clock, in epoch milliseconds, tokens are minted and judged by. */
	readonly now?: () => number;
}

const HEADER_NAME = "x-csrf-token";
const BODY_FIELD = "csrf_token";
const TTL_SECONDS = 7200;
const TOKEN_SHAPE = /^(\d{1,12})\.([A-Za-z0-9_-]{16,64})\.([A-Za-z0-9_-]{43})$/;

const originOf = (raw: string): string | undefined => {
	try {
		return new URL(raw).origin;
	} catch {
		return undefined;
	}
};

const headerOf = (req: Request, name: string): string | undefined => {
	const value = req.headers?.[name];
	const first = Array.isArray(value) ? value[0] : value;
	return typeof first === "string" && first.length > 0 ? first : undefined;
};

const cookieOf = (req: Request, name: string): string | undefined => {
	const header = headerOf(req, "cookie");
	if (header === undefined) return undefined;
	for (const pair of header.split(";")) {
		const eq = pair.indexOf("=");
		if (eq === -1 || pair.slice(0, eq).trim() !== name) continue;
		const raw = pair.slice(eq + 1).trim();
		try {
			return decodeURIComponent(raw);
		} catch {
			return raw;
		}
	}
	return undefined;
};

/**
 * A `CsrfGuard` for tests that keeps the contract: the `Origin` / `Referer`
 * rule against the request's own origin and `trustedOrigins`, the
 * navigation rule, and a double-submit token signed with a key drawn when
 * it is built, valid for two hours by `now`, set in a cookie named from the
 * session cookie's (`<name>.csrf`) and sharing its attributes. Frozen.
 */
export function createTestCsrfGuard(options: TestCsrfGuardOptions = {}): CsrfGuard {
	const key = randomBytes(32);
	const now = options.now ?? Date.now;
	const session = options.sessionCookie ?? createTestSessionCookiePolicy();
	const cookieName = `${session.name}.csrf`;
	const trusted = new Set(
		(options.trustedOrigins ?? []).map(originOf).filter((o): o is string => o !== undefined),
	);
	const sign = (payload: string): string =>
		createHmac("sha256", key).update(payload, "utf8").digest("base64url");
	const wellSigned = (token: string): boolean => {
		const match = TOKEN_SHAPE.exec(token);
		if (match === null) return false;
		const [, expires, nonce, signature] = match;
		const expected = Buffer.from(sign(`${expires}.${nonce}`));
		const given = Buffer.from(signature as string);
		return (
			given.length === expected.length &&
			timingSafeEqual(given, expected) &&
			Number(expires) * 1000 > now()
		);
	};
	/** Whether `claimed` — an Origin or a Referer — names this origin or a trusted one. */
	const ownOrTrusted = (req: Request, claimed: string): boolean => {
		const origin = originOf(claimed);
		const host = headerOf(req, "host") ?? req.host;
		const own = host === undefined ? undefined : originOf(`${req.protocol}://${host}`);
		return origin !== undefined && (origin === own || trusted.has(origin));
	};

	const check = (req: Request): CsrfVerdict => {
		const claimed = headerOf(req, "origin") ?? headerOf(req, "referer");
		if (claimed !== undefined) {
			return ownOrTrusted(req, claimed)
				? { outcome: "accepted" }
				: { outcome: "refused", reason: "foreign_origin" };
		}
		const cookie = cookieOf(req, cookieName);
		const body = (req as { body?: unknown }).body;
		const fromBody =
			typeof body === "object" && body !== null
				? (body as Record<string, unknown>)[BODY_FIELD]
				: undefined;
		const echoed =
			headerOf(req, HEADER_NAME) ??
			(typeof fromBody === "string" && fromBody.length > 0 ? fromBody : undefined);
		if (cookie === undefined && echoed === undefined) {
			return { outcome: "refused", reason: "token_absent" };
		}
		if (cookie === undefined || echoed === undefined || cookie !== echoed || !wellSigned(cookie)) {
			return { outcome: "refused", reason: "token_invalid" };
		}
		return { outcome: "accepted" };
	};

	const checkNavigation = (req: Request): NavigationVerdict => {
		const site = headerOf(req, "sec-fetch-site");
		if (site === "same-origin" || site === "none") return { outcome: "accepted" };
		if (site === "cross-site") return { outcome: "refused", reason: "cross_site" };
		const claimed = headerOf(req, "origin") ?? headerOf(req, "referer");
		if (claimed === undefined) return { outcome: "refused", reason: "origin_absent" };
		return ownOrTrusted(req, claimed)
			? { outcome: "accepted" }
			: { outcome: "refused", reason: "foreign_origin" };
	};

	const middleware: RequestHandler = (req, res, next) => {
		if (check(req).outcome === "accepted") {
			next();
			return;
		}
		res.status(403).json({ error: "access_denied", error_description: "CSRF check failed" });
	};

	return Object.freeze({
		cookieName,
		headerName: HEADER_NAME,
		bodyField: BODY_FIELD,
		check,
		checkNavigation,
		middleware,
		issue(res: Response): string {
			const expires = Math.floor(now() / 1000) + TTL_SECONDS;
			const nonce = randomBytes(24).toString("base64url");
			const token = `${expires}.${nonce}.${sign(`${expires}.${nonce}`)}`;
			res.cookie(cookieName, token, {
				httpOnly: false,
				path: "/",
				secure: session.secure,
				sameSite: session.sameSite,
				maxAge: TTL_SECONDS * 1000,
				...(session.domain === undefined ? {} : { domain: session.domain }),
			});
			return token;
		},
	});
}
