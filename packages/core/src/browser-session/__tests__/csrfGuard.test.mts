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
 * The `csrfGuard` slot (#728; #710's one browser-origin / CSRF policy):
 * whether a browser's request may change state, and whether a navigation
 * may start a flow that will, decided once for every package's routes. Its
 * contract suite and the test double: the double keeps every case, and each
 * way a guard can break the contract fails the case that names it.
 */

import { randomBytes } from "node:crypto";
import type { Request, RequestHandler, Response } from "express";
import { describe, expect, expectTypeOf, it } from "vitest";
import type { CsrfGuard, CsrfVerdict, NavigationVerdict } from "#/browser-session/types.mjs";
import { createApp, defineModule, type ProviderDeps } from "#/index.mjs";
import type { ComponentMap } from "#/modules/manifest/component-map.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";
import {
	type CsrfGuardContractInput,
	createTestCsrfGuard,
	createTestSessionCookiePolicy,
	csrfGuardContract,
} from "#/testing/index.mjs";

const RULES = {
	sameOrigin:
		"a request from this origin is accepted without a token, by its Origin or, without one, by its Referer",
	foreign: "a foreign origin is refused whatever the request carries, a valid token included",
	noToken: "with no origin signal, a request without a token is refused",
	token:
		"with no origin signal, the token issue set is accepted, echoed in its header or, where the guard names one, its body field",
	badToken:
		"with no origin signal, a token that does not match its cookie, has no cookie, was changed, or was not issued by the guard is refused",
	cookie:
		"issue sets the token in a cookie script can read, named cookieName, on path /, with the attributes its prefix and the session cookie require",
	malformed: "check never throws: a malformed cookie, Origin or Referer is refused",
	middleware:
		"the middleware runs the route exactly when check accepts, and answers 403 access_denied otherwise",
	frozen: "the guard is frozen",
	navigation:
		"a navigation that starts a flow is accepted from this origin, typed or bookmarked, refused cross-site, and otherwise held to its Origin or Referer — never to a token",
	expired: "a token past its lifetime is refused",
	trusted: "a trusted origin is accepted without a token, for a request and for a navigation",
} as const;

const TRUSTED = "https://login.contract.test";
const SESSION_COOKIE = createTestSessionCookiePolicy();

/** Everything the suite can be given beside `build`: every case runs. */
const EVERY_CASE: Omit<CsrfGuardContractInput, "build"> = {
	trustedOrigin: TRUSTED,
	withClock: (now) => createTestCsrfGuard({ trustedOrigins: [TRUSTED], now }),
	sessionCookie: SESSION_COOKIE,
};

/** The names of the cases the guards `build` makes fail. */
const failing = async (
	build: CsrfGuardContractInput["build"],
	rest: Omit<CsrfGuardContractInput, "build"> = EVERY_CASE,
): Promise<string[]> => {
	const failed: string[] = [];
	for (const { name, run } of csrfGuardContract({ build, ...rest })) {
		try {
			await run();
		} catch {
			failed.push(name);
		}
	}
	return failed;
};

const header = (req: Request, name: string): string | undefined => {
	const value = req.headers[name.toLowerCase()];
	return Array.isArray(value) ? value[0] : value;
};

const cookieValue = (req: Request, name: string): string | undefined => {
	for (const pair of (header(req, "cookie") ?? "").split(";")) {
		const eq = pair.indexOf("=");
		if (eq !== -1 && pair.slice(0, eq).trim() === name) return pair.slice(eq + 1).trim();
	}
	return undefined;
};

/** The middleware a guard whose policy is `check` answers with. */
const middlewareOf =
	(check: (req: Request) => CsrfVerdict): RequestHandler =>
	(req, res, next) => {
		if (check(req).outcome === "accepted") return next();
		res.status(403).json({ error: "access_denied" });
	};

/** The double with `check` replaced; the middleware follows the replacement, so only the policy breaks. */
const withPolicy = (
	policy: (req: Request, original: CsrfGuard) => CsrfVerdict,
): CsrfGuardContractInput["build"] => {
	return () => {
		const original = createTestCsrfGuard({ trustedOrigins: [TRUSTED] });
		const check = (req: Request) => policy(req, original);
		return Object.freeze({ ...original, check, middleware: middlewareOf(check) });
	};
};

/** The double with `checkNavigation` replaced. */
const withNavigation = (
	navigation: (req: Request, original: CsrfGuard) => NavigationVerdict,
): CsrfGuardContractInput["build"] => {
	return () => {
		const original = createTestCsrfGuard({ trustedOrigins: [TRUSTED] });
		return Object.freeze({
			...original,
			checkNavigation: (req: Request) => navigation(req, original),
		});
	};
};

/** The double with `issue` replaced by one that sets the cookie with `options`. */
const issuingWith = (options: Record<string, unknown>): CsrfGuardContractInput["build"] => {
	return () => {
		const original = createTestCsrfGuard({ trustedOrigins: [TRUSTED] });
		return Object.freeze({
			...original,
			issue: (res: Response) => {
				const { record, res: scratch } = scratchResponse();
				const token = original.issue(scratch);
				res.cookie(original.cookieName, token, { ...record.options, ...options });
				return token;
			},
		});
	};
};

/** A response that keeps the options the one cookie set on it carried. */
const scratchResponse = () => {
	const record: { options: Record<string, unknown> } = { options: {} };
	const res = {
		cookie(_name: string, _value: string, options: Record<string, unknown>) {
			record.options = options;
			return res;
		},
	};
	return { record, res: res as unknown as Response };
};

describe("the csrfGuard slot", () => {
	it("is optional, and holds the one policy for whether a browser's request may change state", () => {
		expectTypeOf<ComponentMap["csrfGuard"]>().toEqualTypeOf<CsrfGuard | undefined>();
		expectTypeOf<ProviderDeps<"csrfGuard">["csrfGuard"]>().toEqualTypeOf<CsrfGuard>();
		expectTypeOf<CsrfGuard["check"]>().toEqualTypeOf<(req: Request) => CsrfVerdict>();
		expectTypeOf<CsrfGuard["checkNavigation"]>().toEqualTypeOf<
			(req: Request) => NavigationVerdict
		>();
		expectTypeOf<CsrfGuard["middleware"]>().toEqualTypeOf<RequestHandler>();
		expectTypeOf<CsrfGuard["issue"]>().toEqualTypeOf<(res: Response) => string>();
		expectTypeOf<CsrfGuard["bodyField"]>().toEqualTypeOf<string | undefined>();
		expectTypeOf<CsrfVerdict>().toEqualTypeOf<
			| { readonly outcome: "accepted" }
			| {
					readonly outcome: "refused";
					readonly reason: "foreign_origin" | "token_absent" | "token_invalid";
			  }
		>();
		expectTypeOf<NavigationVerdict>().toEqualTypeOf<
			| { readonly outcome: "accepted" }
			| {
					readonly outcome: "refused";
					readonly reason: "cross_site" | "foreign_origin" | "origin_absent";
			  }
		>();
		expect(true).toBe(true);
	});

	it("is filled by a module, and read by another", async () => {
		const guard = createTestCsrfGuard();
		let seen: CsrfGuard | undefined;
		const owner = defineModule({
			name: "test:csrf-guard-owner",
			provides: { csrfGuard: () => guard },
		});
		const reader = defineModule({
			name: "test:csrf-guard-reader",
			requires: ["csrfGuard"] as const,
			contributes: {
				routes: [
					(deps) => {
						seen = deps.csrfGuard;
						return {
							id: "test-csrf-guard-reader",
							mountPath: "/__test_csrf_guard_reader__",
							handler: deps.csrfGuard.middleware,
						};
					},
				],
			},
		});
		const handle = await createApp({
			modules: [owner, reader],
			bootstrapComponents: {
				config: makeValidCoreConfig(),
				pathResolver: (p: string) => p,
			} as never,
		});
		try {
			expect(seen).toBe(guard);
		} finally {
			await handle.dispose();
		}
	});
});

describe("csrfGuardContract — the double", () => {
	const cases = csrfGuardContract({
		build: () => createTestCsrfGuard({ trustedOrigins: [TRUSTED] }),
		...EVERY_CASE,
	});

	it("names every rule", () => {
		expect(cases.map((c) => c.name)).toEqual([
			RULES.sameOrigin,
			RULES.foreign,
			RULES.noToken,
			RULES.token,
			RULES.badToken,
			RULES.cookie,
			RULES.malformed,
			RULES.middleware,
			RULES.frozen,
			RULES.navigation,
			RULES.expired,
			RULES.trusted,
		]);
	});

	it("leaves out the expiry and trusted-origin cases for a guard with no clock to set and no origin to trust", () => {
		const names = csrfGuardContract({ build: () => createTestCsrfGuard() }).map((c) => c.name);
		expect(names).not.toContain(RULES.expired);
		expect(names).not.toContain(RULES.trusted);
	});

	it.each(cases)("$name", async ({ run }) => {
		await run();
	});

	it("keeps them trusting no origin but its own", async () => {
		expect(await failing(() => createTestCsrfGuard(), {})).toEqual([]);
	});

	it("keeps them beside a session cookie shared across subdomains over plain HTTP", async () => {
		const sessionCookie = createTestSessionCookiePolicy({
			name: "auth.session",
			secure: false,
			sameSite: "strict",
			domain: ".example.com",
		});
		expect(await failing(() => createTestCsrfGuard({ sessionCookie }), { sessionCookie })).toEqual(
			[],
		);
	});

	it("keeps them beside a __Secure- session cookie", async () => {
		const sessionCookie = createTestSessionCookiePolicy({ name: "__Secure-auth.session" });
		expect(await failing(() => createTestCsrfGuard({ sessionCookie }), { sessionCookie })).toEqual(
			[],
		);
	});

	it("keeps them when a refusal also marks the response through Express's header setters", async () => {
		expect(
			await failing(() => {
				const original = createTestCsrfGuard({ trustedOrigins: [TRUSTED] });
				const middleware: RequestHandler = (req, res, next) => {
					if (original.check(req).outcome === "accepted") return next();
					res.set("Cache-Control", "no-store").header("Pragma", "no-cache");
					res.setHeader("X-Content-Type-Options", "nosniff");
					if (res.get("Cache-Control") !== "no-store" || res.getHeader("Pragma") !== "no-cache") {
						throw new Error("a header set on the response was lost");
					}
					res.status(403).json({ error: "access_denied" });
				};
				return Object.freeze({ ...original, middleware });
			}),
		).toEqual([]);
	});
});

describe("createTestCsrfGuard", () => {
	it("names its cookie from the session cookie's, as the session package does, and reads the body field csrf_token", () => {
		const guard = createTestCsrfGuard();
		expect(guard.cookieName).toBe(`${SESSION_COOKIE.name}.csrf`);
		expect(guard.headerName).toBe("x-csrf-token");
		expect(guard.bodyField).toBe("csrf_token");
		expect(
			createTestCsrfGuard({ sessionCookie: createTestSessionCookiePolicy({ name: "sid" }) })
				.cookieName,
		).toBe("sid.csrf");
	});
});

describe("csrfGuardContract — each way a guard can break it", () => {
	it("a Referer ignored: a same-origin form without Origin asked for a token", async () => {
		expect(
			await failing(
				withPolicy((req, original) =>
					header(req, "origin") === undefined && header(req, "referer") !== undefined
						? { outcome: "refused", reason: "token_absent" }
						: original.check(req),
				),
			),
		).toContain(RULES.sameOrigin);
	});

	it("a valid token that outweighs a foreign origin", async () => {
		expect(
			await failing(
				withPolicy((req, original) => {
					const verdict = original.check(req);
					const tokenOnly = original.check({
						...req,
						headers: { ...req.headers, origin: undefined, referer: undefined },
					} as unknown as Request);
					return verdict.outcome === "refused" &&
						verdict.reason === "foreign_origin" &&
						tokenOnly.outcome === "accepted"
						? { outcome: "accepted" }
						: verdict;
				}),
			),
		).toContain(RULES.foreign);
	});

	it("a same-origin Referer read before a foreign Origin: the Origin is not authoritative", async () => {
		const refererFirst = (req: Request): Request => {
			const referer = header(req, "referer");
			return referer === undefined
				? req
				: ({ ...req, headers: { ...req.headers, origin: referer } } as unknown as Request);
		};
		expect(
			await failing(withPolicy((req, original) => original.check(refererFirst(req)))),
		).toContain(RULES.foreign);
		expect(
			await failing(withNavigation((req, original) => original.checkNavigation(refererFirst(req)))),
		).toContain(RULES.navigation);
	});

	it("a request with no origin signal waved through — the pre-#272 guard", async () => {
		expect(
			await failing(
				withPolicy((req, original) =>
					header(req, "origin") === undefined && header(req, "referer") === undefined
						? { outcome: "accepted" }
						: original.check(req),
				),
			),
		).toEqual(expect.arrayContaining([RULES.noToken, RULES.badToken]));
	});

	it("a token held to its cookie alone, not to the guard's signature", async () => {
		expect(
			await failing(
				withPolicy((req, original) => {
					const verdict = original.check(req);
					const cookie = header(req, "cookie");
					const echoed = header(req, original.headerName);
					return verdict.outcome === "refused" &&
						verdict.reason === "token_invalid" &&
						echoed !== undefined &&
						cookie === `${original.cookieName}=${encodeURIComponent(echoed)}`
						? { outcome: "accepted" }
						: verdict;
				}),
			),
		).toContain(RULES.badToken);
	});

	it("an unsigned double-submit token: any pair of its own shape accepted", async () => {
		const unsigned = (): CsrfGuard => {
			const original = createTestCsrfGuard({ trustedOrigins: [TRUSTED] });
			const check = (req: Request): CsrfVerdict => {
				if (header(req, "origin") !== undefined || header(req, "referer") !== undefined) {
					return original.check(req);
				}
				const cookie = cookieValue(req, original.cookieName);
				const echoed = header(req, original.headerName);
				if (cookie === undefined && echoed === undefined) {
					return { outcome: "refused", reason: "token_absent" };
				}
				return cookie !== undefined && cookie === echoed && /^tok_[0-9a-f]+$/.test(cookie)
					? { outcome: "accepted" }
					: { outcome: "refused", reason: "token_invalid" };
			};
			return Object.freeze({
				...original,
				bodyField: undefined,
				check,
				middleware: middlewareOf(check),
				issue: (res: Response) => {
					const token = `tok_${randomBytes(16).toString("hex")}`;
					res.cookie(original.cookieName, token, {
						httpOnly: false,
						path: "/",
						secure: true,
						sameSite: "lax",
					});
					return token;
				},
			});
		};
		expect(await failing(unsigned)).toContain(RULES.badToken);
	});

	it("a signed token accepted from the header with no cookie beside it", async () => {
		expect(
			await failing(
				withPolicy((req, original) => {
					const echoed = header(req, original.headerName);
					if (cookieValue(req, original.cookieName) === undefined && echoed !== undefined) {
						return original.check({
							...req,
							headers: {
								...req.headers,
								cookie: `${original.cookieName}=${encodeURIComponent(echoed)}`,
							},
						} as unknown as Request);
					}
					return original.check(req);
				}),
			),
		).toContain(RULES.badToken);
	});

	it("a body field named but never read", async () => {
		expect(
			await failing(
				withPolicy((req, original) => original.check({ ...req, body: {} } as unknown as Request)),
			),
		).toContain(RULES.token);
	});

	it("a token that never expires", async () => {
		expect(
			await failing(() => createTestCsrfGuard({ trustedOrigins: [TRUSTED] }), {
				...EVERY_CASE,
				withClock: () => createTestCsrfGuard({ trustedOrigins: [TRUSTED] }),
			}),
		).toContain(RULES.expired);
	});

	it("a token the browser's script cannot read, on another path, or looser than the session cookie", async () => {
		expect(await failing(issuingWith({ httpOnly: true }))).toContain(RULES.cookie);
		expect(await failing(issuingWith({ path: "/session" }))).toContain(RULES.cookie);
		expect(await failing(issuingWith({ secure: false }))).toContain(RULES.cookie);
		expect(await failing(issuingWith({ sameSite: "none" }))).toContain(RULES.cookie);
		expect(await failing(issuingWith({ domain: "example.com" }))).toContain(RULES.cookie);
	});

	it("a check that throws on a malformed cookie", async () => {
		expect(
			await failing(
				withPolicy((req, original) => {
					const cookie = cookieValue(req, original.cookieName);
					if (cookie !== undefined) decodeURIComponent(cookie);
					return original.check(req);
				}),
			),
		).toContain(RULES.malformed);
	});

	it("a middleware that disagrees with check, or refuses with another status or code", async () => {
		const withMiddleware = (middleware: (original: CsrfGuard) => RequestHandler) => () => {
			const original = createTestCsrfGuard({ trustedOrigins: [TRUSTED] });
			return Object.freeze({ ...original, middleware: middleware(original) });
		};
		expect(await failing(withMiddleware(() => (_req, _res, next) => next()))).toContain(
			RULES.middleware,
		);
		expect(
			await failing(
				withMiddleware((original) => (req, res, next) => {
					if (original.check(req).outcome === "accepted") return next();
					res.status(401).json({ error: "access_denied" });
				}),
			),
		).toContain(RULES.middleware);
		expect(
			await failing(
				withMiddleware((original) => (req, res, next) => {
					if (original.check(req).outcome === "accepted") return next();
					res.status(403).json({ error: "invalid_request" });
				}),
			),
		).toContain(RULES.middleware);
	});

	it("a refusal with no RFC 6749 body, or a middleware that throws", async () => {
		const withMiddleware = (middleware: (original: CsrfGuard) => RequestHandler) => () => {
			const original = createTestCsrfGuard({ trustedOrigins: [TRUSTED] });
			return Object.freeze({ ...original, middleware: middleware(original) });
		};
		const refusing =
			(refuse: (res: Response) => void) =>
			(original: CsrfGuard): RequestHandler =>
			(req, res, next) => {
				if (original.check(req).outcome === "accepted") return next();
				refuse(res);
			};
		expect(await failing(withMiddleware(refusing((res) => res.sendStatus(403))))).toContain(
			RULES.middleware,
		);
		expect(await failing(withMiddleware(refusing((res) => res.status(403).end())))).toContain(
			RULES.middleware,
		);
		expect(
			await failing(
				withMiddleware(() => () => {
					throw new Error("the guard's own failure");
				}),
			),
		).toContain(RULES.middleware);
	});

	it("a token cookie set with no attributes, or a SameSite given as Express's boolean", async () => {
		expect(
			await failing(() => {
				const original = createTestCsrfGuard({ trustedOrigins: [TRUSTED] });
				return Object.freeze({
					...original,
					issue: (res: Response) => {
						const { res: scratch } = scratchResponse();
						const token = original.issue(scratch);
						res.cookie(original.cookieName, token);
						return token;
					},
				});
			}),
		).toContain(RULES.cookie);
		expect(await failing(issuingWith({ sameSite: true }))).toContain(RULES.cookie);
	});

	it("a guard a reader could change under the others", async () => {
		expect(
			await failing(() => ({ ...createTestCsrfGuard({ trustedOrigins: [TRUSTED] }) })),
		).toEqual([RULES.frozen]);
	});

	it("a navigation held to its Referer alone: Sec-Fetch-Site ignored", async () => {
		expect(
			await failing(
				withNavigation((req, original) =>
					original.checkNavigation({
						...req,
						headers: { ...req.headers, "sec-fetch-site": undefined },
					} as unknown as Request),
				),
			),
		).toContain(RULES.navigation);
	});

	it("a navigation accepted on a token, or with no origin signal at all", async () => {
		expect(
			await failing(
				withNavigation((req, original) => {
					const verdict = original.check(req);
					return verdict.outcome === "accepted"
						? verdict
						: { outcome: "refused", reason: "foreign_origin" };
				}),
			),
		).toContain(RULES.navigation);
		expect(
			await failing(
				withNavigation((req, original) => {
					const verdict = original.checkNavigation(req);
					return verdict.outcome === "refused" && verdict.reason === "origin_absent"
						? { outcome: "accepted" }
						: verdict;
				}),
			),
		).toContain(RULES.navigation);
	});

	it("a trusted origin refused", async () => {
		expect(await failing(() => createTestCsrfGuard())).toContain(RULES.trusted);
	});
});
