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
 * package's rule (#272): an `Origin` — or, without one, a `Referer` — that
 * names another origin (`null`, another scheme, another host) is refused
 * whatever the request carries, a valid token included; one that names
 * this origin, or the trusted origin the input names, is accepted without
 * a token; with neither, the token decides — absent is refused, the one
 * `issue` set echoed in `headerName` is accepted, one that does not match
 * its cookie or that the guard did not sign is refused; `issue` sets the
 * token in a cookie named `cookieName` that script can read; and the
 * middleware runs the route exactly when `check` accepts, answering `403
 * access_denied` otherwise.
 *
 * `createTestCsrfGuard` keeps that rule with a signing key of its own,
 * drawn when it is built. Published on `@o3co/auth-provider-core/testing`.
 */

import assert from "node:assert/strict";
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { Request, RequestHandler, Response } from "express";
import type { CsrfGuard, CsrfVerdict } from "../../browser-session/types.mjs";
import type { ContractCase } from "../../session-admission/testing/requirement.contract.mjs";
import { CONTRACT_ORIGIN, fakeRequest, fakeResponse, runMiddleware } from "./fake-http.mjs";

export interface CsrfGuardContractInput {
	/** A fresh guard for each case, serving `https://idp.contract.test`. */
	readonly build: () => CsrfGuard;
	/** An origin the guard was built to trust beside its own, when it trusts one: accepted without a token. */
	readonly trustedOrigin?: string;
}

const FOREIGN_ORIGINS: readonly string[] = [
	"https://attacker.contract.test",
	"null",
	"http://idp.contract.test",
	"https://idp.contract.test.attacker.test",
];

/** A request carrying `headers`, and nothing else a browser would add. */
const requestWith = (headers: Record<string, string>): Request => fakeRequest({ headers }).req;

/** A token `guard` issued, and the headers that echo it: its cookie, and the header. */
function issued(guard: CsrfGuard): {
	readonly token: string;
	readonly headers: Record<string, string>;
} {
	const { res, record } = fakeResponse();
	const token = guard.issue(res);
	const cookie = record.cookies.find((c) => c.name === guard.cookieName);
	assert.ok(cookie !== undefined, `issue set no cookie named ${guard.cookieName}`);
	return {
		token,
		headers: {
			cookie: `${guard.cookieName}=${encodeURIComponent(cookie.value)}`,
			[guard.headerName]: token,
		},
	};
}

const refusedFor = (verdict: CsrfVerdict, reason: string, what: string): void => {
	assert.deepEqual(verdict, { outcome: "refused", reason }, `${what} must be refused (${reason})`);
};

const acceptedFor = (verdict: CsrfVerdict, what: string): void => {
	assert.deepEqual(verdict, { outcome: "accepted" }, `${what} must be accepted`);
};

/** The cases of the `csrfGuard` contract over the guard `input` builds. */
export function csrfGuardContract(input: CsrfGuardContractInput): readonly ContractCase[] {
	const { build, trustedOrigin } = input;
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
			name: "with no origin signal, the token issue set, echoed in its header, is accepted",
			run: async () => {
				const guard = build();
				const { headers } = issued(guard);
				acceptedFor(guard.check(requestWith(headers)), "the issued token, echoed");
			},
		},
		{
			name: "with no origin signal, a token that does not match its cookie, or one the guard did not issue, is refused",
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
					guard.check(requestWith({ cookie: first.headers.cookie as string })),
					"token_invalid",
					"a cookie with no token echoed",
				);
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
			name: "issue sets the token as a cookie script can read, named cookieName",
			run: async () => {
				const guard = build();
				const { res, record } = fakeResponse();
				const token = guard.issue(res);
				assert.ok(typeof token === "string" && token.length > 0, "issue answered no token");
				const set = record.cookies.filter((c) => c.name === guard.cookieName);
				assert.ok(set.length > 0, `no cookie named ${guard.cookieName} was set`);
				for (const cookie of set) {
					assert.equal(cookie.value, token, "the cookie carries another token than issue answered");
					assert.notEqual(
						cookie.options?.httpOnly,
						true,
						"the token's cookie is httpOnly: script cannot echo it",
					);
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
	];
	if (trustedOrigin !== undefined) {
		cases.push({
			name: "a trusted origin is accepted without a token",
			run: async () => {
				acceptedFor(
					build().check(requestWith({ origin: trustedOrigin })),
					`Origin ${trustedOrigin}`,
				);
			},
		});
	}
	return cases;
}

export interface TestCsrfGuardOptions {
	/** Origins other than the request's own a request may come from without a token. */
	readonly trustedOrigins?: readonly string[];
}

const COOKIE_NAME = "__Host-auth.session.csrf";
const HEADER_NAME = "x-csrf-token";
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
		try {
			return decodeURIComponent(pair.slice(eq + 1).trim());
		} catch {
			return pair.slice(eq + 1).trim();
		}
	}
	return undefined;
};

/**
 * A `CsrfGuard` for tests that keeps the contract: the `Origin` /
 * `Referer` rule against the request's own origin and `trustedOrigins`,
 * and a double-submit token signed with a key drawn when it is built,
 * valid for two hours.
 */
export function createTestCsrfGuard(options: TestCsrfGuardOptions = {}): CsrfGuard {
	const key = randomBytes(32);
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
			Number(expires) * 1000 > Date.now()
		);
	};

	const check = (req: Request): CsrfVerdict => {
		const claimed = headerOf(req, "origin") ?? headerOf(req, "referer");
		if (claimed !== undefined) {
			const origin = originOf(claimed);
			const host = headerOf(req, "host") ?? req.host;
			const own = host === undefined ? undefined : originOf(`${req.protocol}://${host}`);
			if (origin !== undefined && (origin === own || trusted.has(origin))) {
				return { outcome: "accepted" };
			}
			return { outcome: "refused", reason: "foreign_origin" };
		}
		const cookie = cookieOf(req, COOKIE_NAME);
		const echoed = headerOf(req, HEADER_NAME);
		if (cookie === undefined && echoed === undefined) {
			return { outcome: "refused", reason: "token_absent" };
		}
		if (cookie === undefined || echoed === undefined || cookie !== echoed || !wellSigned(cookie)) {
			return { outcome: "refused", reason: "token_invalid" };
		}
		return { outcome: "accepted" };
	};

	const middleware: RequestHandler = (req, res, next) => {
		if (check(req).outcome === "accepted") {
			next();
			return;
		}
		res.status(403).json({ error: "access_denied", error_description: "CSRF check failed" });
	};

	return Object.freeze({
		cookieName: COOKIE_NAME,
		headerName: HEADER_NAME,
		check,
		middleware,
		issue(res: Response): string {
			const expires = Math.floor(Date.now() / 1000) + TTL_SECONDS;
			const nonce = randomBytes(24).toString("base64url");
			const token = `${expires}.${nonce}.${sign(`${expires}.${nonce}`)}`;
			res.cookie(COOKIE_NAME, token, {
				httpOnly: false,
				path: "/",
				secure: true,
				sameSite: "lax",
				maxAge: TTL_SECONDS * 1000,
			});
			return token;
		},
	});
}
