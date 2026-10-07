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
 * `rateLimiterContract` run over core's in-process limiter and over core's
 * double, and the proof that each case is not vacuous: limiters broken one
 * way each, refused by the case that names what they break.
 */

import {
	createMemoryRateLimiter,
	type RateLimitDecision,
	type RateLimiter,
	type RateLimitSpec,
} from "@o3co/auth-provider-core";
import { createTestRateLimiter } from "@o3co/auth-provider-core/testing";
import { describe, expect, it } from "vitest";
import { type RateLimiterContractInput, rateLimiterContract } from "#/index.mjs";

const RULES = {
	kind: "kind is a non-empty string",
	failMode: "failMode, when present, is open or closed",
	defaultLimit: "defaultLimit, when present, is a budget a limiter can apply as written",
	decision:
		"check answers a decision: allowed true or false, and remaining, limit, resetAt and reason well-formed when present",
	outage: "an outage is thrown, never answered as a decision",
	budget:
		"a key is allowed its limit and refused past it, under a prefix named after an Object.prototype member too, and another key is counted apart",
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

/** A limiter answering `decision` to every check, as `kind`, with `extra` members. */
const answering = (decision: unknown, extra: Record<string, unknown> = {}): (() => RateLimiter) => {
	return () =>
		({
			kind: "fixed",
			...extra,
			check: async () => decision as RateLimitDecision,
		}) as RateLimiter;
};

describe("rateLimiterContract — core's in-process limiter", () => {
	const spec: RateLimitSpec = { limit: 10, windowSeconds: 60 };
	const cases = rateLimiterContract({
		build: () => createMemoryRateLimiter({ defaultLimit: spec }),
		withBudget: (budget) => createMemoryRateLimiter({ defaultLimit: budget }),
	});

	it("runs every case but the outage's: it has no backend to lose", () => {
		expect(cases.map((c) => c.name)).toEqual([
			RULES.kind,
			RULES.failMode,
			RULES.defaultLimit,
			RULES.decision,
			RULES.budget,
		]);
	});

	for (const contractCase of cases) {
		it(contractCase.name, contractCase.run);
	}
});

describe("rateLimiterContract — core's double", () => {
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

	for (const contractCase of cases) {
		it(contractCase.name, contractCase.run);
	}

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

	it("a budget looked up on a plain object, which finds an Object.prototype member for a prefix named after one", async () => {
		expect(
			await failing({
				build: () => createTestRateLimiter(),
				withBudget: (spec) => {
					const limits: Record<string, RateLimitSpec> = {};
					const counts = new Map<string, number>();
					return {
						kind: "plain-object",
						check: async (key) => {
							const { limit } = limits[key.slice(0, key.indexOf(":"))] ?? spec;
							const count = (counts.get(key) ?? 0) + 1;
							counts.set(key, count);
							return { allowed: !(count > limit) };
						},
					};
				},
			}),
		).toEqual([RULES.budget]);
	});
});
