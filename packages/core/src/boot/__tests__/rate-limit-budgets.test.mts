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
 * The `rateLimitBudgets` contribution kind: a module contributes the
 * budget of each rate-limit prefix it owns — the default limit and window it
 * reads from its own settings — name-keyed by the prefix, and core composes
 * them into one view, the synthetic `rateLimitBudgetResolver`, that a limiter
 * reads at request time. Two modules contributing one prefix refuse boot. No
 * limiter reads the view yet: the bundled ones still seed their limits from
 * `resolveSeededLimitSpecs`.
 */

import { describe, expect, it } from "vitest";
import { defineModule } from "../../modules/manifest/index.mjs";
import { memoryRateLimiterModule } from "../../ratelimit/module.mjs";
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import { createApp, mergeWithBuiltins } from "../create-app.mjs";
import type { BootstrapMap } from "../types.mjs";
import { BootError } from "../types.mjs";

declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly budgetFixtureSlot: number;
	}
}

const bootWith = (extra: Record<string, unknown> = {}): BootstrapMap =>
	({
		config: { ...makeValidCoreConfig(), ...extra } as never,
		pathResolver: (s: string) => s,
	}) satisfies Record<string, unknown> as BootstrapMap;

/** What `createApp` refused with, or a failure when it booted. */
async function refusal(promise: Promise<unknown>): Promise<BootError> {
	try {
		await promise;
	} catch (err) {
		expect(err).toBeInstanceOf(BootError);
		return err as BootError;
	}
	return expect.fail("boot should have been refused");
}

describe("rateLimitBudgets — contributed by the module that owns the prefix", () => {
	it("registers each budget under its prefix, read from the module's own settings, in one view", async () => {
		const fixed = defineModule({
			name: "budget-fixed",
			contributes: {
				rateLimitBudgets: { "fixture-fixed": () => ({ limit: 5, windowSeconds: 60 }) },
			},
		});
		const configured = defineModule({
			name: "budget-configured",
			requires: ["config"],
			contributes: {
				rateLimitBudgets: {
					"fixture-configured": (deps) =>
						(deps.config as unknown as { budgetFixture: { limit: number; windowSeconds: number } })
							.budgetFixture,
				},
			},
		});

		const handle = await createApp({
			modules: [fixed, configured],
			bootstrapComponents: bootWith({ budgetFixture: { limit: 3, windowSeconds: 900 } }),
		});

		const budgets = handle.components.rateLimitBudgetResolver;
		expect(budgets?.get("fixture-fixed")).toEqual({ limit: 5, windowSeconds: 60 });
		expect(budgets?.get("fixture-configured")).toEqual({ limit: 3, windowSeconds: 900 });
		expect(budgets?.get("unowned")).toBeUndefined();
		expect([...(budgets?.entries() ?? [])]).toEqual([
			["fixture-fixed", { limit: 5, windowSeconds: 60 }],
			["fixture-configured", { limit: 3, windowSeconds: 900 }],
		]);
		await handle.dispose();
	});

	it("registers what the factory answered at registration: the view holds a frozen copy", async () => {
		const answered = { limit: 5, windowSeconds: 60 };
		const mod = defineModule({
			name: "budget-owner",
			contributes: { rateLimitBudgets: { fixture: () => answered } },
		});

		const handle = await createApp({ modules: [mod], bootstrapComponents: bootWith() });
		answered.limit = 500;

		const budget = handle.components.rateLimitBudgetResolver?.get("fixture");
		expect(budget).toEqual({ limit: 5, windowSeconds: 60 });
		expect(Object.isFrozen(budget)).toBe(true);
		await handle.dispose();
	});

	it("a budget answered null claims its prefix and is absent from the view", async () => {
		const mod = defineModule({
			name: "budget-off",
			contributes: {
				rateLimitBudgets: {
					"fixture-off": () => null,
					"fixture-on": () => ({ limit: 1, windowSeconds: 1 }),
				},
			},
		});

		const handle = await createApp({ modules: [mod], bootstrapComponents: bootWith() });

		const budgets = handle.components.rateLimitBudgetResolver;
		expect(budgets?.get("fixture-off")).toBeUndefined();
		expect([...(budgets?.entries() ?? [])].map(([prefix]) => prefix)).toEqual(["fixture-on"]);
		await handle.dispose();
	});

	it("an override gives a budget to a prefix whose owner switched it off", async () => {
		const owner = defineModule({
			name: "budget-owner",
			contributes: { rateLimitBudgets: { fixture: () => null } },
		});
		const replacer = defineModule({
			name: "budget-replacer",
			overrides: { rateLimitBudgets: { fixture: () => ({ limit: 2, windowSeconds: 30 }) } },
		});

		const handle = await createApp({ modules: [owner, replacer], bootstrapComponents: bootWith() });

		expect(handle.components.rateLimitBudgetResolver?.get("fixture")).toEqual({
			limit: 2,
			windowSeconds: 30,
		});
		await handle.dispose();
	});

	it("an override replaces the budget another module contributed for the prefix", async () => {
		const owner = defineModule({
			name: "budget-owner",
			contributes: { rateLimitBudgets: { fixture: () => ({ limit: 5, windowSeconds: 60 }) } },
		});
		const replacer = defineModule({
			name: "budget-replacer",
			overrides: { rateLimitBudgets: { fixture: () => ({ limit: 1, windowSeconds: 10 }) } },
		});

		const handle = await createApp({ modules: [owner, replacer], bootstrapComponents: bootWith() });

		expect(handle.components.rateLimitBudgetResolver?.get("fixture")).toEqual({
			limit: 1,
			windowSeconds: 10,
		});
		await handle.dispose();
	});
});

describe("rateLimitBudgets — refused", () => {
	it("two modules contributing one prefix refuse boot, before any factory runs", async () => {
		let ran = false;
		const factory = () => {
			ran = true;
			return { limit: 5, windowSeconds: 60 };
		};
		const first = defineModule({
			name: "budget-first",
			contributes: { rateLimitBudgets: { fixture: factory } },
		});
		const second = defineModule({
			name: "budget-second",
			contributes: { rateLimitBudgets: { fixture: factory } },
		});

		const err = await refusal(
			createApp({ modules: [first, second], bootstrapComponents: bootWith() }),
		);

		expect(err.reason).toBe("duplicate-contribute");
		expect(err.stage).toBe("validateManifests");
		expect(err.details).toEqual({
			reason: "duplicate-contribute",
			kind: "rateLimitBudgets",
			identity: "fixture",
			identityKind: "name",
			modules: ["budget-first", "budget-second"],
		});
		expect(ran).toBe(false);
	});

	it.each([
		["a zero limit", { limit: 0, windowSeconds: 60 }],
		["a fractional window", { limit: 5, windowSeconds: 1.5 }],
		["a NaN limit", { limit: Number.NaN, windowSeconds: 60 }],
		["a window past the Date range", { limit: 5, windowSeconds: Number.MAX_SAFE_INTEGER }],
	])(
		"a budget no limiter can apply as written — %s — refuses boot naming the module and prefix",
		async (_label, budget) => {
			const mod = defineModule({
				name: "budget-broken",
				contributes: { rateLimitBudgets: { fixture: () => budget } },
			});

			const err = await refusal(createApp({ modules: [mod], bootstrapComponents: bootWith() }));

			expect(err.reason).toBe("contribute-factory-failed");
			expect(err.details).toMatchObject({
				reason: "contribute-factory-failed",
				module: "budget-broken",
				kind: "rateLimitBudgets",
				name: "fixture",
			});
			expect(err.message).toContain('rateLimitBudgets "fixture"');
		},
	);

	type Budget = { readonly limit: number; readonly windowSeconds: number } | null;
	const spec = (): Budget => ({ limit: 5, windowSeconds: 60 });
	const off = (): Budget => null;

	it.each<readonly [string, string, "contributes" | "overrides", () => Budget]>([
		["empty", "", "contributes", spec],
		["carrying a colon", "fixture:ip", "contributes", spec],
		["carrying a colon, on a budget switched off", "fixture:ip", "contributes", off],
		["carrying a colon, in an override", "fixture:ip", "overrides", off],
	])(
		"a prefix no limiter key can carry — %s — refuses boot at stage 1, before any factory runs",
		async (_label, prefix, channel, answer) => {
			let ran = false;
			const factory = (): Budget => {
				ran = true;
				return answer();
			};
			const mod = defineModule({
				name: "budget-misfiled",
				[channel]: { rateLimitBudgets: { [prefix]: factory } },
			});

			const err = await refusal(createApp({ modules: [mod], bootstrapComponents: bootWith() }));

			expect(err.reason).toBe("contribution-malformed");
			expect(err.stage).toBe("validateManifests");
			expect(err.details).toMatchObject({
				reason: "contribution-malformed",
				module: "budget-misfiled",
				kind: "rateLimitBudgets",
				name: prefix,
				channel,
			});
			expect(err.message).toContain("before its first");
			expect(ran).toBe(false);
		},
	);

	it.each([
		["undefined", undefined],
		["a string", "5"],
	])(
		"a factory answering %s instead of a budget refuses boot naming the module and prefix",
		async (_label, answered) => {
			const mod = defineModule({
				name: "budget-broken",
				contributes: { rateLimitBudgets: { fixture: () => answered as never } },
			});

			const err = await refusal(createApp({ modules: [mod], bootstrapComponents: bootWith() }));

			expect(err.reason).toBe("contribute-factory-failed");
			expect(err.details).toMatchObject({
				module: "budget-broken",
				kind: "rateLimitBudgets",
				name: "fixture",
			});
			expect(err.message).toContain('rateLimitBudgets "fixture"');
		},
	);

	it("a host may not replace the collector: the kind is guarded", async () => {
		const err = await refusal(
			createApp({
				modules: [],
				bootstrapComponents: bootWith(),
				contributionKinds: { rateLimitBudgets: mergeWithBuiltins(undefined).rateLimitBudgets },
			}),
		);

		expect(err.reason).toBe("contribution-kind-guarded");
		expect(err.stage).toBe("validateManifests");
		expect(err.details).toEqual({ reason: "contribution-kind-guarded", kind: "rateLimitBudgets" });
	});

	it("a provider that reads the view while the provides factories run refuses boot", async () => {
		const owner = defineModule({
			name: "budget-owner",
			contributes: { rateLimitBudgets: { fixture: () => ({ limit: 5, windowSeconds: 60 }) } },
		});
		const eagerReader = defineModule({
			name: "budget-eager-reader",
			requires: ["rateLimitBudgetResolver"],
			provides: {
				budgetFixtureSlot: (deps) => deps.rateLimitBudgetResolver.get("fixture")?.limit ?? 0,
			},
			lifecycle: { budgetFixtureSlot: { eager: true } },
		});

		const err = await refusal(
			createApp({ modules: [owner, eagerReader], bootstrapComponents: bootWith() }),
		);

		expect(err.reason).toBe("provides-factory-failed");
		expect(err.message).toContain(
			"rateLimitBudgetResolver was read while the provides factories run",
		);
	});
});

describe("rateLimitBudgets — no limiter reads them yet", () => {
	it("the memory limiter still limits a contributed prefix by its own limits alone", async () => {
		const owner = defineModule({
			name: "budget-owner",
			contributes: { rateLimitBudgets: { fixture: () => ({ limit: 1, windowSeconds: 60 }) } },
		});
		const limiterUser = defineModule({
			name: "limiter-user",
			requires: ["rateLimiter"],
			contributes: { grantMiddleware: [() => null] },
		});

		const handle = await createApp({
			modules: [memoryRateLimiterModule, owner, limiterUser],
			bootstrapComponents: bootWith({
				core: { deployment: { mode: "single" } },
				memoryRateLimiter: {
					limits: {},
					defaultLimit: { limit: 60, windowSeconds: 60 },
					maxBuckets: 100,
				},
			}),
		});

		const limiter = handle.components.rateLimiter;
		const first = await limiter?.check("fixture:ip:1.2.3.4", { ip: "1.2.3.4" });
		const second = await limiter?.check("fixture:ip:1.2.3.4", { ip: "1.2.3.4" });
		expect(first?.limit).toBe(60);
		expect(second?.allowed).toBe(true);
		await handle.dispose();
	});
});

describe("rateLimitBudgets — read once", () => {
	it("registers the budget it validated: a getter that answers differently on a second read changes nothing", async () => {
		let reads = 0;
		const shifty = {
			get limit() {
				reads += 1;
				return reads === 1 ? 5 : 1_000_000;
			},
			windowSeconds: 60,
		};
		const mod = defineModule({
			name: "budget-shifty",
			contributes: { rateLimitBudgets: { fixture: () => shifty } },
		});

		const handle = await createApp({ modules: [mod], bootstrapComponents: bootWith() });

		expect(reads).toBe(1);
		expect(handle.components.rateLimitBudgetResolver?.get("fixture")).toEqual({
			limit: 5,
			windowSeconds: 60,
		});
		await handle.dispose();
	});

	it("refuses the budget it read: a getter that answers a usable limit only on a later read is refused", async () => {
		let reads = 0;
		const shifty = {
			get limit() {
				reads += 1;
				return reads === 1 ? 0 : 5;
			},
			windowSeconds: 60,
		};
		const mod = defineModule({
			name: "budget-shifty",
			contributes: { rateLimitBudgets: { fixture: () => shifty } },
		});

		const err = await refusal(createApp({ modules: [mod], bootstrapComponents: bootWith() }));

		expect(err.reason).toBe("contribute-factory-failed");
		expect(err.message).toContain("got limit 0");
	});
});

describe("rateLimitBudgets — the kind takes a record keyed by prefix", () => {
	it.each<readonly [string, "contributes" | "overrides", unknown]>([
		["a function", "contributes", () => ({ limit: 5, windowSeconds: 60 })],
		["an array", "contributes", [() => ({ limit: 5, windowSeconds: 60 })]],
		["null", "contributes", null],
		["an array, in an override", "overrides", [() => null]],
	])("refuses %s in its place at stage 1", async (_label, channel, container) => {
		const mod = defineModule({
			name: "budget-container",
			[channel]: { rateLimitBudgets: container as never },
		});

		const err = await refusal(createApp({ modules: [mod], bootstrapComponents: bootWith() }));

		expect(err.reason).toBe("contribution-malformed");
		expect(err.stage).toBe("validateManifests");
		expect(err.details).toEqual({
			reason: "contribution-malformed",
			module: "budget-container",
			kind: "rateLimitBudgets",
			channel,
			problem: expect.stringContaining("record keyed by"),
		});
	});
});
