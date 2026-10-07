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
 * The test double of the `csrfGuard` slot. `createTestCsrfGuard` keeps the
 * slot's contract — the session package's rules for a request's origin and
 * token, a navigation's origin, and the token cookie — with its own signing
 * key beside the given session cookie (the fixture's by default). The
 * contract suite is `@o3co/auth-provider-test-kit`'s. Published on
 * `@o3co/auth-provider-core/testing`.
 */

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { Request, RequestHandler, Response } from "express";
import type {
	CsrfGuard,
	CsrfVerdict,
	NavigationVerdict,
	SessionCookiePolicy,
} from "../../browser-session/types.mjs";
import { createTestSessionCookiePolicy } from "./sessionCookiePolicy.mjs";

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

/** A header as Express reads it (`req.get`), when it carries anything. */
const headerOf = (req: Request, name: string): string | undefined => {
	const value = req.get(name);
	return typeof value === "string" && value.length > 0 ? value : undefined;
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
		const own = originOf(`${req.protocol}://${req.host}`);
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
		// `Object(…)` reads an absent body as an empty one.
		const fromBody = (Object((req as { body?: unknown }).body) as Record<string, unknown>)[
			BODY_FIELD
		];
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
