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
 * The `RateLimiter` port's contract suite, with its optional `failMode` —
 * the limiter's own outage policy — and the test double. The suite
 * runs against the double and against core's in-process limiter; each way a
 * limiter can break the contract fails the case that names it.
 */

import { describe, expect, expectTypeOf, it } from "vitest";
import type { RateLimitFailMode } from "#/ratelimit/guard.mjs";
import { createMemoryRateLimiter } from "#/ratelimit/memory.mjs";
import type { RateLimitDecision, RateLimiter, RateLimitSpec } from "#/ratelimit/types.mjs";
import {
	createTestRateLimiter,
	type RateLimiterContractInput,
	rateLimiterContract,
} from "#/testing/index.mjs";

const RULES = {
	kind: "kind is a non-empty string",
	failMode: "failMode, when present, is open or closed",
	defaultLimit: "defaultLimit, when present, is a budget a limiter can apply as written",
	decision:
		"check answers a decision: allowed true or false, and remaining, limit, resetAt and reason well-formed when present",
	outage: "an outage is thrown, never answered as a decision",
	budget: "a key is allowed its limit and refused past it, and another key is counted apart",
} as const;

const downDouble = () => {
	const limiter = createTestRateLimiter({ failMode: "closed" });
	limiter.failWith(new Error("limiter backend down"));
	return limiter;
};

/** The names of the cases the limiters `input` builds fail. */
const failing = async (input: RateLimiterContractInput): Promise<string[]> => {
	const failed: string[] = [];
	for (const { name, run } of rateLimiterContract(input)) {
		try {
			await run();
		} catch {
			failed.push(name);
		}
	}
	return failed;
};

/** A limiter answering `decision` to every check, as `kind`, with `failMode` when given. */
const answering = (decision: unknown, extra: Record<string, unknown> = {}): (() => RateLimiter) => {
	return () =>
		({
			kind: "fixed",
			...extra,
			check: async () => decision as RateLimitDecision,
		}) as RateLimiter;
};

describe("RateLimiter.failMode", () => {
	it("is optional, and is the guard's outage vocabulary", () => {
		expectTypeOf<RateLimiter["failMode"]>().toEqualTypeOf<RateLimitFailMode | undefined>();
		const withoutOne: RateLimiter = { kind: "none", check: async () => ({ allowed: true }) };
		const withOne: RateLimiter = {
			kind: "one",
			failMode: "open",
			check: async () => ({ allowed: true }),
		};
		expect(withoutOne.failMode).toBeUndefined();
		expect(withOne.failMode).toBe("open");
	});
});

describe("rateLimiterContract — the double", () => {
	const cases = rateLimiterContract({
		build: () => createTestRateLimiter({ failMode: "closed" }),
		withOutage: downDouble,
		withBudget: (spec) => createTestRateLimiter({ limit: spec.limit }),
	});

	it("names every rule", () => {
		expect(cases.map((c) => c.name)).toEqual([
			RULES.kind,
			RULES.failMode,
			RULES.defaultLimit,
			RULES.decision,
			RULES.outage,
			RULES.budget,
		]);
	});

	it("leaves the outage and budget cases out for a limiter that has neither", () => {
		expect(
			rateLimiterContract({ build: () => createTestRateLimiter() }).map((c) => c.name),
		).toEqual([RULES.kind, RULES.failMode, RULES.defaultLimit, RULES.decision]);
	});

	it.each(cases)("$name", async ({ run }) => {
		await run();
	});

	it("keeps them with either policy, and with none", async () => {
		for (const failMode of ["open", "closed", undefined] as const) {
			expect(
				await failing({
					build: () => createTestRateLimiter(failMode === undefined ? {} : { failMode }),
				}),
			).toEqual([]);
		}
	});
});

describe("rateLimiterContract — core's in-process limiter", () => {
	const spec: RateLimitSpec = { limit: 10, windowSeconds: 60 };
	it.each(
		rateLimiterContract({
			build: () => createMemoryRateLimiter({ defaultLimit: spec }),
			withBudget: (budget) => createMemoryRateLimiter({ defaultLimit: budget }),
		}),
	)("$name", async ({ run }) => {
		await run();
	});

	it("declares no outage policy: it has no backend to lose", () => {
		expect(createMemoryRateLimiter({ defaultLimit: spec }).failMode).toBeUndefined();
	});

	it("declares the defaultLimit it was built with, frozen", () => {
		const defaultLimit = { limit: 7, windowSeconds: 90 };
		const declared = createMemoryRateLimiter({ defaultLimit }).defaultLimit;
		defaultLimit.limit = 700;
		expect(declared).toEqual({ limit: 7, windowSeconds: 90 });
		expect(Object.isFrozen(declared)).toBe(true);
	});
});

describe("createTestRateLimiter", () => {
	it("allows every check without a limit, and records each key", async () => {
		const limiter = createTestRateLimiter();
		expect(limiter.kind).toBe("test");
		expect("failMode" in limiter).toBe(false);
		for (let i = 0; i < 5; i++) {
			expect((await limiter.check("login:ip:192.0.2.1", {})).allowed).toBe(true);
		}
		await limiter.check("token:ip:192.0.2.2", {});
		expect(limiter.checked).toEqual([...Array(5).fill("login:ip:192.0.2.1"), "token:ip:192.0.2.2"]);
		expect(Object.isFrozen(limiter.checked)).toBe(true);
	});

	it("refuses a key past its limit, counting each key apart", async () => {
		const limiter = createTestRateLimiter({ limit: 2, failMode: "open" });
		expect(limiter.failMode).toBe("open");
		const answers = [];
		for (let i = 0; i < 3; i++) answers.push(await limiter.check("a", {}));
		expect(answers.map((d) => [d.allowed, d.remaining, d.limit])).toEqual([
			[true, 1, 2],
			[true, 0, 2],
			[false, 0, 2],
		]);
		expect((await limiter.check("b", {})).allowed).toBe(true);
	});

	it("stands in for a backend that is down: every check rejects with the error, until it recovers", async () => {
		const limiter = createTestRateLimiter();
		const outage = new Error("down");
		limiter.failWith(outage);
		await expect(limiter.check("a", {})).rejects.toBe(outage);
		limiter.recover();
		expect((await limiter.check("a", {})).allowed).toBe(true);
	});
});

describe("rateLimiterContract — each way a limiter can break it", () => {
	it("a kind that names nothing", async () => {
		expect(await failing({ build: answering({ allowed: true }, { kind: "" }) })).toEqual([
			RULES.kind,
		]);
	});

	it("a failMode outside the guard's two", async () => {
		for (const failMode of ["OPEN", "fail-open", "", null]) {
			expect(await failing({ build: answering({ allowed: true }, { failMode }) })).toEqual([
				RULES.failMode,
			]);
		}
	});

	it("a defaultLimit no limiter can apply as written", async () => {
		for (const defaultLimit of [{ limit: 0, windowSeconds: 60 }, { limit: 5 }, null, "60/60"]) {
			expect(
				await failing({ build: answering({ allowed: true }, { defaultLimit }) }),
				JSON.stringify(defaultLimit),
			).toEqual([RULES.defaultLimit]);
		}
	});

	it("a decision that is not one", async () => {
		for (const decision of [
			undefined,
			{ allowed: "yes" },
			{ allowed: true, remaining: -1 },
			{ allowed: true, remaining: 0.5 },
			{ allowed: true, limit: 0 },
			{ allowed: false, resetAt: new Date(Number.NaN) },
			{ allowed: false, resetAt: "soon" },
			{ allowed: false, reason: 429 },
		]) {
			expect(await failing({ build: answering(decision) })).toEqual([RULES.decision]);
		}
	});

	it("an outage answered — allowed, or refused — instead of thrown", async () => {
		for (const answer of [{ allowed: true }, { allowed: false }]) {
			expect(
				await failing({ build: answering({ allowed: true }), withOutage: answering(answer) }),
			).toEqual([RULES.outage]);
		}
	});

	it("a budget never spent, or keys counted together", async () => {
		expect(
			await failing({
				build: () => createTestRateLimiter(),
				withBudget: () => createTestRateLimiter(),
			}),
		).toEqual([RULES.budget]);
		expect(
			await failing({
				build: () => createTestRateLimiter(),
				withBudget: (spec) => {
					const shared = createTestRateLimiter({ limit: spec.limit });
					return { ...shared, check: (_key, ctx) => shared.check("one-bucket", ctx) };
				},
			}),
		).toEqual([RULES.budget]);
	});
});
