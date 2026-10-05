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
import { z } from "zod";
import { MAX_DURATION_SECONDS } from "../../config/durations.mjs";
import { defineModule, type Module } from "../../modules/manifest/index.mjs";
import { memoryRateLimiterModule } from "../../ratelimit/module.mjs";
import type { RateLimiter } from "../../ratelimit/types.mjs";
import { verifierLimitClaim } from "../../ratelimit/verifierLimits.mjs";
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

describe("rateLimitBudgets — no module overrides a prefix", () => {
	it.each<readonly [string, Budget]>([
		["a tighter budget", { limit: 1, windowSeconds: 600 }],
		["a looser budget", { limit: 1_000, windowSeconds: 1 }],
		["no budget", null],
	])(
		"refuses an override — %s — at stage 1, before any factory runs, naming the module and prefix",
		async (_label, overridden) => {
			let ran = false;
			const err = await refusal(
				createApp({
					modules: [
						memoryRateLimiterModule,
						limiterUser,
						defineModule({
							name: "budget-owner",
							contributes: {
								rateLimitBudgets: { fixture: () => ({ limit: 5, windowSeconds: 300 }) },
							},
						}),
						defineModule({
							name: "budget-replacer",
							overrides: {
								rateLimitBudgets: {
									fixture: () => {
										ran = true;
										return overridden;
									},
								},
							},
						}),
					],
					bootstrapComponents: withMemoryLimiter(),
				}),
			);

			expect(err.reason).toBe("contribution-kind-guarded");
			expect(err.stage).toBe("validateManifests");
			expect(err.details).toEqual({
				reason: "contribution-kind-guarded",
				kind: "rateLimitBudgets",
				channel: "overrides",
				module: "budget-replacer",
				name: "fixture",
			});
			expect(err.message).toContain('overrides rateLimitBudgets "fixture"');
			expect(ran).toBe(false);
		},
	);

	it.each([
		["login", "session.rateLimit.login"],
		["device_verification", "device-grant.rateLimit"],
	])(
		"refuses an override of %s, a verifier's own limit, naming the setting it is made at",
		async (prefix, setting) => {
			const err = await refusal(
				createApp({
					modules: [
						defineModule({
							name: "budget-replacer",
							overrides: {
								rateLimitBudgets: { [prefix]: () => ({ limit: 1, windowSeconds: 600 }) },
							},
						}),
					],
					bootstrapComponents: bootWith(),
				}),
			);

			expect(err.reason).toBe("contribution-kind-guarded");
			expect(err.message).toContain(`overrides rateLimitBudgets "${prefix}"`);
			expect(err.message).toContain(setting);
		},
	);
});

describe("rateLimitBudgets — an override is refused as the manifest was read", () => {
	it("refuses an override a manifest answers only on its first read", async () => {
		let reads = 0;
		const shifting = {
			name: "budget-replacer",
			get overrides() {
				reads += 1;
				return reads === 1
					? { rateLimitBudgets: { login: () => ({ limit: 1_000, windowSeconds: 1 }) } }
					: {};
			},
		} as unknown as Module;

		const err = await refusal(
			createApp({
				modules: [
					defineModule({
						name: "budget-owner",
						contributes: { rateLimitBudgets: { login: () => ({ limit: 5, windowSeconds: 300 }) } },
					}),
					shifting,
				],
				bootstrapComponents: bootWith(),
			}),
		);

		expect(err.reason).toBe("contribution-kind-guarded");
		expect(err.details).toMatchObject({ kind: "rateLimitBudgets", name: "login" });
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
						{ prefix: "fixture", budget: { limit: 5, windowSeconds: 300 }, module: "budget-owner" },
						{ prefix: "fixture-off", budget: null, module: "budget-owner" },
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

describe("rateLimitBudgets — a verifier's claim", () => {
	/** A module claiming `prefix` as a verifier's own limit, made at `setting`. */
	const verifierModule = (prefix: string, setting: string, name = "verifier-owner"): Module =>
		defineModule({
			name,
			contributes: { rateLimitBudgets: { [prefix]: verifierLimitClaim({ setting }) } },
		});

	/** The in-process limiter's own limits, one entry per prefix. */
	const limitsOn = (...prefixes: readonly string[]): BootstrapMap =>
		withMemoryLimiter({
			"core-rate-limiter-memory": {
				limits: Object.fromEntries(
					prefixes.map((prefix) => [prefix, { limit: 5, windowSeconds: 60 }]),
				),
				defaultLimit: { limit: 60, windowSeconds: 60 },
				maxBuckets: 100,
			},
		});

	it("refuses boot on a limiter's limits entry for the prefix, naming its path and the declared setting", async () => {
		const err = await refusal(
			createApp({
				modules: [memoryRateLimiterModule, verifierModule("fixture_attempts", "fixture.attempts")],
				bootstrapComponents: limitsOn("fixture_attempts", "token"),
			}),
		);

		expect(err.reason).toBe("config-validation-failed");
		expect(err.stage).toBe("validateManifests");
		expect(err.message).toContain("core-rate-limiter-memory.limits.fixture_attempts");
		expect(err.message).toContain("set fixture.attempts instead");
		expect(err.message).not.toContain("limits.token");
	});

	it("names the declared setting for login in place of the one core falls back to", async () => {
		const err = await refusal(
			createApp({
				modules: [memoryRateLimiterModule, verifierModule("login", "fixture.login.attempts")],
				bootstrapComponents: limitsOn("login"),
			}),
		);

		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toContain("core-rate-limiter-memory.limits.login");
		expect(err.message).toContain("set fixture.login.attempts instead");
		expect(err.message).not.toContain("session.rateLimit.login");
	});

	it("refuses the entry while the declaring module is switched off", async () => {
		const Switch = z.object({ enabled: z.boolean() }).strict();
		const switchable = defineModule({
			name: "verifier-switchable",
			section: { schema: Switch, isEnabled: (section) => section.enabled },
			contributes: {
				rateLimitBudgets: { fixture_attempts: verifierLimitClaim({ setting: "fixture.attempts" }) },
			},
		});
		const bootstrap = limitsOn("fixture_attempts");

		const err = await refusal(
			createApp({
				modules: [memoryRateLimiterModule, switchable],
				bootstrapComponents: {
					...bootstrap,
					config: { ...bootstrap.config, "verifier-switchable": { enabled: false } } as never,
				},
			}),
		);

		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toContain("set fixture.attempts instead");
	});

	it("boots with a limits entry for a prefix claimed without a declaration, and for one nobody claims", async () => {
		const plain = defineModule({
			name: "plain-owner",
			contributes: {
				rateLimitBudgets: {
					fixture_plain: () => null,
					fixture_budgeted: () => ({ limit: 1, windowSeconds: 60 }),
				},
			},
		});

		const handle = await createApp({
			modules: [
				memoryRateLimiterModule,
				plain,
				verifierModule("fixture_attempts", "fixture.attempts"),
			],
			bootstrapComponents: limitsOn("fixture_plain", "fixture_budgeted", "unclaimed"),
		});
		await handle.dispose();
	});

	it.each([
		["login", "session.rateLimit.login"],
		["device_verification", "device-grant.rateLimit"],
	])(
		"still refuses %s, which core names itself, while its claim declares nothing",
		async (prefix, setting) => {
			const undeclared = defineModule({
				name: "undeclared-owner",
				contributes: { rateLimitBudgets: { [prefix]: () => null } },
			});

			const err = await refusal(
				createApp({
					modules: [memoryRateLimiterModule, undeclared],
					bootstrapComponents: limitsOn(prefix),
				}),
			);

			expect(err.reason).toBe("config-validation-failed");
			expect(err.message).toContain(`core-rate-limiter-memory.limits.${prefix}`);
			expect(err.message).toContain(setting);
		},
	);

	it("claims the prefix with no budget: absent from the resolver, keyed by the limiter's defaultLimit", async () => {
		let resolver: { get: (prefix: string) => unknown } | undefined;
		let handed: RateLimiter | undefined;
		const reader = defineModule({
			name: "budget-reader",
			requires: ["rateLimitBudgetResolver", "rateLimiter"],
			contributes: {
				grantMiddleware: [
					(deps) => {
						resolver = deps.rateLimitBudgetResolver;
						handed = deps.rateLimiter;
						return null;
					},
				],
			},
		});

		const handle = await createApp({
			modules: [
				memoryRateLimiterModule,
				verifierModule("fixture_attempts", "fixture.attempts"),
				reader,
			],
			bootstrapComponents: limitsOn(),
		});

		expect(resolver?.get("fixture_attempts")).toBeUndefined();
		expect((await handed?.check("fixture_attempts:ip:1.2.3.4", { ip: "1.2.3.4" }))?.limit).toBe(60);
		await handle.dispose();
	});

	it("is a claim like any other: a second module contributing the prefix refuses boot", async () => {
		const err = await refusal(
			createApp({
				modules: [
					verifierModule("fixture_attempts", "fixture.attempts", "verifier-first"),
					defineModule({
						name: "budget-second",
						contributes: { rateLimitBudgets: { fixture_attempts: () => null } },
					}),
				],
				bootstrapComponents: bootWith(),
			}),
		);

		expect(err.reason).toBe("duplicate-contribute");
		expect(err.details).toMatchObject({
			kind: "rateLimitBudgets",
			identity: "fixture_attempts",
			modules: ["verifier-first", "budget-second"],
		});
	});

	it("names the declared setting when a module overrides the prefix", async () => {
		const err = await refusal(
			createApp({
				modules: [
					verifierModule("fixture_attempts", "fixture.attempts"),
					defineModule({
						name: "budget-replacer",
						overrides: {
							rateLimitBudgets: { fixture_attempts: () => ({ limit: 1, windowSeconds: 600 }) },
						},
					}),
				],
				bootstrapComponents: bootWith(),
			}),
		);

		expect(err.reason).toBe("contribution-kind-guarded");
		expect(err.message).toContain("set at fixture.attempts");
	});

	it.each<readonly [string, unknown]>([
		["an empty setting", { setting: "" }],
		["a setting that is not a string", { setting: 5 }],
		["no setting", {}],
		["a declaration that is not an object", "fixture.attempts"],
		["null", null],
	])("refuses a declaration with %s at stage 1", async (_label, verifier) => {
		let ran = false;
		const claim = Object.assign(
			() => {
				ran = true;
				return null;
			},
			{ verifier },
		);
		const err = await refusal(
			createApp({
				modules: [
					defineModule({
						name: "verifier-malformed",
						contributes: { rateLimitBudgets: { fixture_attempts: claim as never } },
					}),
				],
				bootstrapComponents: bootWith(),
			}),
		);

		expect(err.reason).toBe("contribution-malformed");
		expect(err.details).toEqual({
			reason: "contribution-malformed",
			module: "verifier-malformed",
			kind: "rateLimitBudgets",
			name: "fixture_attempts",
			channel: "contributes",
			problem: expect.stringContaining("setting"),
		});
		expect(ran).toBe(false);
	});

	it("refuses a declaration whose read throws at stage 1, as itself", async () => {
		const claim = Object.defineProperty(() => null, "verifier", {
			get(): never {
				throw new Error("declaration unavailable");
			},
		});
		const err = await refusal(
			createApp({
				modules: [
					defineModule({
						name: "verifier-throwing",
						contributes: { rateLimitBudgets: { fixture_attempts: claim as never } },
					}),
				],
				bootstrapComponents: bootWith(),
			}),
		);

		expect(err.reason).toBe("contribution-malformed");
		expect(err.details).toMatchObject({ module: "verifier-throwing", name: "fixture_attempts" });
		expect(err.message).toContain("declaration unavailable");
	});

	it("reads the declaration once: the setting a refusal names is the one first read", async () => {
		let reads = 0;
		const claim = Object.defineProperty(() => null, "verifier", {
			get() {
				reads += 1;
				return { setting: reads === 1 ? "fixture.attempts" : "" };
			},
		});

		const err = await refusal(
			createApp({
				modules: [
					memoryRateLimiterModule,
					defineModule({
						name: "verifier-shifting",
						contributes: { rateLimitBudgets: { fixture_attempts: claim as never } },
					}),
				],
				bootstrapComponents: limitsOn("fixture_attempts"),
			}),
		);

		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toContain("set fixture.attempts instead");
		expect(reads).toBe(1);
	});

	it("holds the declarations for that boot's section parse alone", async () => {
		await refusal(
			createApp({
				modules: [memoryRateLimiterModule, verifierModule("fixture_attempts", "fixture.attempts")],
				bootstrapComponents: limitsOn("fixture_attempts"),
			}),
		);

		const parsed = memoryRateLimiterModule.section?.schema.safeParse({
			limits: { fixture_attempts: { limit: 5, windowSeconds: 60 } },
		});
		expect(parsed?.success).toBe(true);
		const handle = await createApp({
			modules: [memoryRateLimiterModule],
			bootstrapComponents: limitsOn("fixture_attempts"),
		});
		await handle.dispose();
	});

	it("answers null as a factory, and holds its declaration frozen", () => {
		const claim = verifierLimitClaim({ setting: "fixture.attempts" });

		expect(claim(undefined as never)).toBeNull();
		expect(claim.verifier).toEqual({ setting: "fixture.attempts" });
		expect(Object.isFrozen(claim)).toBe(true);
		expect(Object.isFrozen(claim.verifier)).toBe(true);
	});
});
