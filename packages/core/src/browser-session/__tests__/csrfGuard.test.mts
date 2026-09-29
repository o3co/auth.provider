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
 * whether a browser's request may change state, decided once for every
 * package's routes. Its contract suite and the test double: the double
 * keeps every case, and each way a guard can break the contract fails the
 * case that names it.
 */

import type { Request, RequestHandler, Response } from "express";
import { describe, expect, expectTypeOf, it } from "vitest";
import type { CsrfGuard, CsrfVerdict } from "#/browser-session/types.mjs";
import { createApp, defineModule, type ProviderDeps } from "#/index.mjs";
import type { ComponentMap } from "#/modules/manifest/component-map.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";
import {
	type CsrfGuardContractInput,
	createTestCsrfGuard,
	csrfGuardContract,
} from "#/testing/index.mjs";

const RULES = {
	sameOrigin:
		"a request from this origin is accepted without a token, by its Origin or, without one, by its Referer",
	foreign: "a foreign origin is refused whatever the request carries, a valid token included",
	noToken: "with no origin signal, a request without a token is refused",
	token: "with no origin signal, the token issue set, echoed in its header, is accepted",
	badToken:
		"with no origin signal, a token that does not match its cookie, or one the guard did not issue, is refused",
	cookie: "issue sets the token as a cookie script can read, named cookieName",
	middleware:
		"the middleware runs the route exactly when check accepts, and answers 403 access_denied otherwise",
	trusted: "a trusted origin is accepted without a token",
} as const;

const TRUSTED = "https://login.contract.test";

/** The names of the cases the guards `build` makes fail. */
const failing = async (
	build: CsrfGuardContractInput["build"],
	trusting: Pick<CsrfGuardContractInput, "trustedOrigin"> = { trustedOrigin: TRUSTED },
): Promise<string[]> => {
	const failed: string[] = [];
	for (const { name, run } of csrfGuardContract({ build, ...trusting })) {
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

/** The double with `check` replaced; the middleware follows the replacement, so only the policy breaks. */
const withPolicy = (
	policy: (req: Request, original: CsrfGuard) => CsrfVerdict,
): CsrfGuardContractInput["build"] => {
	return () => {
		const original = createTestCsrfGuard({ trustedOrigins: [TRUSTED] });
		const check = (req: Request) => policy(req, original);
		const middleware: RequestHandler = (req, res, next) => {
			if (check(req).outcome === "accepted") return next();
			res.status(403).json({ error: "access_denied" });
		};
		return Object.freeze({ ...original, check, middleware });
	};
};

describe("the csrfGuard slot", () => {
	it("is optional, and holds the one policy for whether a browser's request may change state", () => {
		expectTypeOf<ComponentMap["csrfGuard"]>().toEqualTypeOf<CsrfGuard | undefined>();
		expectTypeOf<ProviderDeps<"csrfGuard">["csrfGuard"]>().toEqualTypeOf<CsrfGuard>();
		expectTypeOf<CsrfGuard["check"]>().toEqualTypeOf<(req: Request) => CsrfVerdict>();
		expectTypeOf<CsrfGuard["middleware"]>().toEqualTypeOf<RequestHandler>();
		expectTypeOf<CsrfGuard["issue"]>().toEqualTypeOf<(res: Response) => string>();
		expectTypeOf<CsrfVerdict>().toEqualTypeOf<
			| { readonly outcome: "accepted" }
			| {
					readonly outcome: "refused";
					readonly reason: "foreign_origin" | "token_absent" | "token_invalid";
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
		trustedOrigin: TRUSTED,
	});

	it("names every rule", () => {
		expect(cases.map((c) => c.name)).toEqual([
			RULES.sameOrigin,
			RULES.foreign,
			RULES.noToken,
			RULES.token,
			RULES.badToken,
			RULES.cookie,
			RULES.middleware,
			RULES.trusted,
		]);
	});

	it("leaves the trusted-origin case out for a guard built to trust none", () => {
		expect(
			csrfGuardContract({ build: () => createTestCsrfGuard() }).map((c) => c.name),
		).not.toContain(RULES.trusted);
	});

	it.each(cases)("$name", async ({ run }) => {
		await run();
	});

	it("keeps them trusting no origin but its own", async () => {
		expect(await failing(() => createTestCsrfGuard(), {})).toEqual([]);
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

	it("a token the browser's script cannot read", async () => {
		expect(
			await failing(() => {
				const original = createTestCsrfGuard({ trustedOrigins: [TRUSTED] });
				return Object.freeze({
					...original,
					issue: (res: Response) => {
						const token = original.issue(res);
						res.cookie(original.cookieName, token, { httpOnly: true });
						return token;
					},
				});
			}),
		).toContain(RULES.cookie);
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

	it("a trusted origin refused", async () => {
		expect(await failing(() => createTestCsrfGuard())).toContain(RULES.trusted);
	});
});
