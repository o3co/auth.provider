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
 * reads at request time. Two modules contributing one prefix refuse boot.
 */

import { describe, expect, it, vi } from "vitest";
import { MAX_DURATION_SECONDS } from "../../config/durations.mjs";
import { defineModule, type Module } from "../../modules/manifest/index.mjs";
import { memoryRateLimiterModule } from "../../ratelimit/module.mjs";
import type { RateLimiter } from "../../ratelimit/types.mjs";
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

	it("an override tightens the budget another module contributed for the prefix", async () => {
		const owner = defineModule({
			name: "budget-owner",
			contributes: { rateLimitBudgets: { fixture: () => ({ limit: 5, windowSeconds: 60 }) } },
		});
		const replacer = defineModule({
			name: "budget-replacer",
			overrides: { rateLimitBudgets: { fixture: () => ({ limit: 1, windowSeconds: 600 }) } },
		});

		const handle = await createApp({ modules: [owner, replacer], bootstrapComponents: bootWith() });

		expect(handle.components.rateLimitBudgetResolver?.get("fixture")).toEqual({
			limit: 1,
			windowSeconds: 600,
		});
		await handle.dispose();
	});
});

/** A module that requires the limiter, so the planner builds it. */
const limiterUser = defineModule({
	name: "limiter-user",
	requires: ["rateLimiter"],
	contributes: { grantMiddleware: [() => null] },
});

/** The bundled in-process limiter, its default 60 per 60 s, and a module that uses it. */
const withMemoryLimiter = (extra: Record<string, unknown> = {}): BootstrapMap =>
	bootWith({
		core: { deployment: { mode: "single" } },
		"core-rate-limiter-memory": {
			limits: {},
			defaultLimit: { limit: 60, windowSeconds: 60 },
			maxBuckets: 100,
		},
		...extra,
	});

type Budget = { readonly limit: number; readonly windowSeconds: number } | null;

/** The boot of an owner contributing `contributed` and a module overriding it with `overridden`. */
const overriding = (contributed: Budget, overridden: Budget, bootstrap: BootstrapMap) =>
	createApp({
		modules: [
			memoryRateLimiterModule,
			limiterUser,
			defineModule({
				name: "budget-owner",
				contributes: { rateLimitBudgets: { fixture: () => contributed } },
			}),
			defineModule({
				name: "budget-replacer",
				overrides: { rateLimitBudgets: { fixture: () => overridden } },
			}),
		],
		bootstrapComponents: bootstrap,
	});

describe("rateLimitBudgets — an override may only tighten", () => {
	it.each<readonly [string, Budget]>([
		["a higher limit", { limit: 6, windowSeconds: 300 }],
		["a shorter window", { limit: 5, windowSeconds: 299 }],
		["both", { limit: 1_000_000, windowSeconds: 1 }],
	])(
		"refuses boot on an override that loosens a contributed budget — %s — naming both",
		async (_label, loosened) => {
			const err = await refusal(
				overriding({ limit: 5, windowSeconds: 300 }, loosened, withMemoryLimiter()),
			);

			expect(err.reason).toBe("contribute-factory-failed");
			expect(err.details).toMatchObject({
				module: "budget-replacer",
				kind: "rateLimitBudgets",
				name: "fixture",
			});
			expect(err.message).toContain("may only tighten");
			expect(err.message).toContain("limit 5, windowSeconds 300");
			expect(err.message).toContain(
				`(got limit ${loosened?.limit}, windowSeconds ${loosened?.windowSeconds})`,
			);
		},
	);

	it("refuses boot on an override one second over a year, which counts a longer window as tighter", async () => {
		const err = await refusal(
			overriding(
				{ limit: 5, windowSeconds: 300 },
				{ limit: 5, windowSeconds: MAX_DURATION_SECONDS + 1 },
				withMemoryLimiter(),
			),
		);
		expect(err.reason).toBe("contribute-factory-failed");
		expect(err.details).toMatchObject({ module: "budget-replacer", name: "fixture" });
		expect(err.message).toContain("at most a year");
	});

	it("registers an override no looser than the budget it replaces", async () => {
		const handle = await overriding(
			{ limit: 5, windowSeconds: 300 },
			{ limit: 5, windowSeconds: 300 },
			withMemoryLimiter(),
		);
		expect(handle.components.rateLimitBudgetResolver?.get("fixture")).toEqual({
			limit: 5,
			windowSeconds: 300,
		});
		await handle.dispose();
	});

	it("holds an override of a switched-off budget to the limiter's defaultLimit", async () => {
		const tighter = await overriding(null, { limit: 2, windowSeconds: 600 }, withMemoryLimiter());
		expect(tighter.components.rateLimitBudgetResolver?.get("fixture")).toEqual({
			limit: 2,
			windowSeconds: 600,
		});
		await tighter.dispose();

		for (const looser of [
			{ limit: 61, windowSeconds: 600 },
			{ limit: 2, windowSeconds: 59 },
		]) {
			const err = await refusal(overriding(null, looser, withMemoryLimiter()));
			expect(err.message, JSON.stringify(looser)).toContain("may only tighten");
		}
	});

	it("holds an override that switches a budget off to the limiter's defaultLimit", async () => {
		const looser = await refusal(
			overriding({ limit: 5, windowSeconds: 300 }, null, withMemoryLimiter()),
		);
		expect(looser.message).toContain("may only tighten");

		const tighter = await overriding({ limit: 100, windowSeconds: 30 }, null, withMemoryLimiter());
		expect(tighter.components.rateLimitBudgetResolver?.get("fixture")).toBeUndefined();
		await tighter.dispose();
	});

	it("registers an override that leaves a switched-off budget off, with no limiter to compare it with", async () => {
		const handle = await createApp({
			modules: [
				defineModule({
					name: "budget-owner",
					contributes: { rateLimitBudgets: { fixture: () => null } },
				}),
				defineModule({
					name: "budget-replacer",
					overrides: { rateLimitBudgets: { fixture: () => null } },
				}),
			],
			bootstrapComponents: bootWith(),
		});
		expect(handle.components.rateLimitBudgetResolver?.get("fixture")).toBeUndefined();
		await handle.dispose();
	});

	it("refuses an override of a switched-off budget when no limiter declares its default", async () => {
		const err = await refusal(
			createApp({
				modules: [
					defineModule({
						name: "budget-owner",
						contributes: { rateLimitBudgets: { fixture: () => null } },
					}),
					defineModule({
						name: "budget-replacer",
						overrides: { rateLimitBudgets: { fixture: () => ({ limit: 1, windowSeconds: 600 }) } },
					}),
				],
				bootstrapComponents: bootWith(),
			}),
		);

		expect(err.reason).toBe("contribute-factory-failed");
		expect(err.message).toContain("defaultLimit");
	});
});

describe("rateLimitBudgets — the boot line", () => {
	const spyLogger = () => ({
		trace: vi.fn(),
		debug: vi.fn(),
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		fatal: vi.fn(),
		child: vi.fn(),
	});

	it("logs each prefix with its budget and the module that set it, and the limiter's kind and outage policy", async () => {
		const logger = spyLogger();
		const handle = await createApp({
			modules: [
				memoryRateLimiterModule,
				limiterUser,
				defineModule({
					name: "budget-owner",
					contributes: {
						rateLimitBudgets: {
							fixture: () => ({ limit: 5, windowSeconds: 300 }),
							"fixture-off": () => null,
						},
					},
				}),
				defineModule({
					name: "budget-tightener",
					overrides: { rateLimitBudgets: { fixture: () => ({ limit: 1, windowSeconds: 600 }) } },
				}),
			],
			bootstrapComponents: { ...withMemoryLimiter(), logger: logger as never },
		});

		expect(
			logger.info.mock.calls.filter((call) => call[1] === "rate_limit_budgets_registered"),
		).toEqual([
			[
				{
					limiter: { kind: "memory", failMode: "closed" },
					budgets: [
						{
							prefix: "fixture",
							budget: { limit: 1, windowSeconds: 600 },
							module: "budget-tightener",
							by: "override",
						},
						{ prefix: "fixture-off", budget: null, module: "budget-owner", by: "contribution" },
					],
				},
				"rate_limit_budgets_registered",
			],
		]);
		await handle.dispose();
	});

	it.each<readonly [string, () => RateLimiter]>([
		[
			"a failMode outside the guard's two",
			() =>
				({
					kind: "custom",
					failMode: "maybe",
					check: async () => ({ allowed: true }),
				}) as unknown as RateLimiter,
		],
		[
			"a failMode that cannot be read",
			() =>
				({
					kind: "custom",
					get failMode(): never {
						throw new Error("getter down");
					},
					check: async () => ({ allowed: true }),
				}) as RateLimiter,
		],
	])("reports a wired limiter with %s as an invalid outage policy", async (_label, limiter) => {
		const logger = spyLogger();
		const handle = await createApp({
			modules: [
				defineModule({ name: "custom-limiter", provides: { rateLimiter: limiter } }),
				limiterUser,
			],
			bootstrapComponents: { ...bootWith(), logger: logger as never },
		});

		expect(
			logger.info.mock.calls.filter((call) => call[1] === "rate_limit_budgets_registered"),
		).toEqual([
			[
				{ limiter: { kind: "custom", failMode: "invalid" }, budgets: [] },
				"rate_limit_budgets_registered",
			],
		]);
		await handle.dispose();
	});

	it("warns when rateLimit.failMode says open and the wired limiter answers another policy", async () => {
		const logger = spyLogger();
		const handle = await createApp({
			modules: [memoryRateLimiterModule, limiterUser],
			bootstrapComponents: {
				...withMemoryLimiter({
					rateLimit: { login: { windowMs: 900_000, limit: 20 }, failMode: "open" },
				}),
				logger: logger as never,
			},
		});

		expect(
			logger.warn.mock.calls.filter((call) => call[1] === "rate_limit_fail_mode_not_applied"),
		).toEqual([
			[
				{ configured: "open", limiter: { kind: "memory", failMode: "closed" } },
				"rate_limit_fail_mode_not_applied",
			],
		]);
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
		["a window one second over a year", { limit: 5, windowSeconds: MAX_DURATION_SECONDS + 1 }],
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

	it.each<readonly [string, "contributes" | "overrides"]>([
		["constructor", "contributes"],
		["__proto__", "contributes"],
		["toString", "contributes"],
		["hasOwnProperty", "overrides"],
	])(
		"a prefix named after an Object.prototype member — %s, in %s — refuses boot at stage 1, before any factory runs",
		async (prefix, channel) => {
			let ran = false;
			const factory = (): Budget => {
				ran = true;
				return spec();
			};
			const mod = defineModule({
				name: "budget-inherited-name",
				[channel]: { rateLimitBudgets: { [prefix]: factory } },
			});

			const err = await refusal(createApp({ modules: [mod], bootstrapComponents: bootWith() }));

			expect(err.reason).toBe("contribution-malformed");
			expect(err.stage).toBe("validateManifests");
			expect(err.details).toMatchObject({
				reason: "contribution-malformed",
				module: "budget-inherited-name",
				kind: "rateLimitBudgets",
				name: prefix,
				channel,
			});
			expect(err.message).toContain("Object.prototype");
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

describe("rateLimitBudgets — the in-process limiter reads them", () => {
	/** The limiter a consumer of the slot is handed, after a boot with `modules`. */
	const limiterAfter = async (modules: readonly Module[]) => {
		let handed: RateLimiter | undefined;
		const limiterUser = defineModule({
			name: "limiter-user",
			requires: ["rateLimiter"],
			contributes: {
				grantMiddleware: [
					(deps) => {
						handed = deps.rateLimiter;
						return null;
					},
				],
			},
		});
		const handle = await createApp({
			modules: [memoryRateLimiterModule, ...modules, limiterUser],
			bootstrapComponents: bootWith({
				core: { deployment: { mode: "single" } },
				"core-rate-limiter-memory": {
					limits: { declared: { limit: 4, windowSeconds: 45 } },
					defaultLimit: { limit: 60, windowSeconds: 60 },
					maxBuckets: 100,
				},
			}),
		});
		if (handed === undefined) throw new Error("no consumer was handed the limiter");
		return { handle, limiter: handed };
	};

	it("limits a contributed prefix by its budget", async () => {
		const owner = defineModule({
			name: "budget-owner",
			contributes: { rateLimitBudgets: { fixture: () => ({ limit: 1, windowSeconds: 60 }) } },
		});
		const { handle, limiter } = await limiterAfter([owner]);

		const first = await limiter.check("fixture:ip:1.2.3.4", { ip: "1.2.3.4" });
		const second = await limiter.check("fixture:ip:1.2.3.4", { ip: "1.2.3.4" });
		expect(first.limit).toBe(1);
		expect(second.allowed).toBe(false);
		await handle.dispose();
	});

	it("limits a prefix its own limits declare by that entry, over a contributed budget", async () => {
		const owner = defineModule({
			name: "budget-owner",
			contributes: { rateLimitBudgets: { declared: () => ({ limit: 1, windowSeconds: 60 }) } },
		});
		const { handle, limiter } = await limiterAfter([owner]);

		expect((await limiter.check("declared:ip:1.2.3.4", { ip: "1.2.3.4" })).limit).toBe(4);
		await handle.dispose();
	});

	it("limits a prefix whose budget is switched off by its defaultLimit", async () => {
		const owner = defineModule({
			name: "budget-owner",
			contributes: { rateLimitBudgets: { fixture: () => null } },
		});
		const { handle, limiter } = await limiterAfter([owner]);

		expect((await limiter.check("fixture:ip:1.2.3.4", { ip: "1.2.3.4" })).limit).toBe(60);
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
