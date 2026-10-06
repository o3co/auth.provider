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

import { describe, expect, it, vi } from "vitest";
import type { AuditSink } from "../../audit/types.mjs";
import type { GrantHandler } from "../../grants/types.mjs";
import { defineModule } from "../../modules/manifest/index.mjs";
import { coreConfigForTests, makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import { applyContributions } from "../apply-contributions.mjs";
import { materializeComponents } from "../materialize-components.mjs";
import { planBoot } from "../plan-boot.mjs";
import type {
	BootstrapMap,
	CollectedRouteContribution,
	ComponentWorld,
	ContributionCollectorMap,
	GrantCollector,
	ListCollector,
} from "../types.mjs";
import { BootError } from "../types.mjs";
import { validateManifests } from "../validate-manifests.mjs";

// ---------------------------------------------------------------------------
// Minimal typed fixtures. The contributes-map slots for `GrantHandler`,
// `AuditHook`, `MfaFactor` and `GrantPolicyHookContribution` have concrete
// types, so inline-literal stubs do not satisfy them. These tests verify
// routing (registration order, collector dedup, factory error wrapping), not
// contract semantics, so the stubs are no-ops. A test that needs value
// identity captures one instance (`const sharedHook = fakeAuditSink(...)`)
// and returns it from its factory closures.
// ---------------------------------------------------------------------------

// `tag` goes into `tokens.access_token` so spy collectors that record values
// can tell stub instances apart. Pipeline tests do not read the result
// downstream, so the rest of `TokenResponse` is `as never`.
const fakeGrantHandler = (tag = "stub"): GrantHandler => ({
	handle: async () => ({
		result: {
			status: 200,
			tokens: { access_token: tag } as never,
		},
	}),
});

const fakeAuditSink = (tag = "stub"): AuditSink => ({
	kind: tag,
	record: async () => {},
});

// ---------------------------------------------------------------------------
// Test-only ComponentMap slot augmentation
// ---------------------------------------------------------------------------

declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly slotAC: number;
		readonly slotBC: string;
	}
}

// ---------------------------------------------------------------------------
// Minimal bootstrap
// ---------------------------------------------------------------------------

// Per ADR 2026-04-30-config-schema-strict-defaults-from-hocon, defaults live
// in HOCON and validateAndComposeConfig parses CoreConfigSchema, so the
// fixture supplies a minimal schema-valid baseline (it diverges from
// reference.conf on purpose; see makeValidCoreConfig).
const minBoot = {
	config: makeValidCoreConfig() as never,
	pathResolver: (s: string) => s,
} satisfies Record<string, unknown> as BootstrapMap;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

function makeStubNameCollector<V = unknown>() {
	const m = new Map<string, V>();
	return {
		kind: "name-keyed" as const,
		register: (n: string, v: V) => {
			if (m.has(n)) throw new Error(`already ${n}`);
			m.set(n, v);
		},
		replace: (n: string, v: V) => {
			if (!m.has(n)) throw new Error(`unknown ${n}`);
			m.set(n, v);
		},
		get: (n: string) => m.get(n),
		entries: () => m.entries(),
	};
}

function makeStubListCollector<V = unknown>() {
	const arr: V[] = [];
	const seen = new Set<V>();
	return {
		kind: "list" as const,
		append: (v: V) => {
			if (seen.has(v)) return;
			seen.add(v);
			arr.push(v);
		},
		values: () => arr.values(),
	};
}

/**
 * Build a ComponentWorld from an array of modules. The function runs
 * validateManifests + planBoot + materializeComponents in the test-standard
 * way, forwarding contributionKinds for validateManifests step 5 checks.
 */
async function buildWorld(
	modules: ReturnType<typeof defineModule>[],
	contributionKinds: ContributionCollectorMap = {},
): Promise<ComponentWorld> {
	const validated = validateManifests({
		modules,
		bootstrapComponents: minBoot,
		contributionKinds,
	});
	const plan = planBoot(validated, minBoot, undefined);
	return materializeComponents(plan, minBoot, undefined, contributionKinds);
}

// Minimal stub handler factory to satisfy RouteContribution.handler shape
function stubHandler(): never {
	return ((_req: unknown, _res: unknown, next: () => void) => next()) as never;
}

// ---------------------------------------------------------------------------
// 1. Synthetic projections (step 0)
// ---------------------------------------------------------------------------

describe("applyContributions — step 0: synthetic projections", () => {
	it("grants provided → grantHandlerResolver is defined in component map; lazy read-through works after step 2", async () => {
		const grantCollector = makeStubNameCollector<GrantHandler | null>();
		const contributionKinds: ContributionCollectorMap = {
			grants: grantCollector,
		};

		const modA = defineModule({
			name: "ModA",
			contributes: {
				grants: {
					authorization_code: () => fakeGrantHandler("authcode"),
				},
			},
		});

		const world = await buildWorld([modA], contributionKinds);
		const result = await applyContributions(world, contributionKinds);

		// The grantHandlerResolver must be in the (mutated) working components.
		const resolver = (result.material.components as Record<string, unknown>).grantHandlerResolver;
		expect(resolver).toBeDefined();

		// Lazy read-through: resolver.get reads the underlying collector,
		// which was populated during step 2.
		const resolverObj = resolver as { get: (n: string) => unknown };
		expect(resolverObj.get("authorization_code")).toBeDefined();
	});

	it("when grants collector is NOT provided, grantHandlerResolver is NOT injected", async () => {
		const modA = defineModule({ name: "ModA" });
		const world = await buildWorld([modA], {});
		const result = await applyContributions(world, {});

		const comps = result.material.components as Record<string, unknown>;
		expect(comps.grantHandlerResolver).toBeUndefined();
	});
});

// ---------------------------------------------------------------------------
// 2. Name-keyed pass: register order = initOrder
// ---------------------------------------------------------------------------

describe("applyContributions — step 2: register order = initOrder", () => {
	it("2 modules contributing different grants: register call order matches initOrder", async () => {
		const registerOrder: string[] = [];

		const spyCollector: GrantCollector = {
			kind: "name-keyed" as const,
			register: (n: string, _v: GrantHandler | null) => {
				registerOrder.push(n);
			},
			replace: (_n: string, _v: GrantHandler | null) => {},
			get: (_n: string) => undefined,
			entries: () => new Map<string, GrantHandler | null>().entries(),
		};

		const contributionKinds: ContributionCollectorMap = {
			grants: spyCollector,
		};

		// ModB depends on slotAC from ModA: forces initOrder = [ModA, ModB]
		// even if input order were reversed.
		const modA = defineModule({
			name: "ModA",
			provides: {
				slotAC: () => 1,
			},
			contributes: {
				grants: { grant_a: () => fakeGrantHandler("a") },
			},
		});

		const modB = defineModule({
			name: "ModB",
			requires: ["slotAC"] as const,
			contributes: {
				grants: { grant_b: () => fakeGrantHandler("b") },
			},
		});

		// Input order: ModA first (same as dependency order).
		const world = await buildWorld([modA, modB], contributionKinds);
		await applyContributions(world, contributionKinds);

		// ModA's grant must be registered before ModB's
		expect(registerOrder).toEqual(["grant_a", "grant_b"]);
	});
});

// ---------------------------------------------------------------------------
// 3. List-shaped pass: append order = INPUT-ARRAY order (not initOrder)
// ---------------------------------------------------------------------------

describe("applyContributions — step 3: append order = input-array order", () => {
	it("append order for auditHooks matches input array order, not initOrder", async () => {
		const appendOrder: string[] = [];

		// Spy collector that records which hook's `kind` was appended.
		const auditCollector: ListCollector<AuditSink> = {
			kind: "list" as const,
			append: (v: AuditSink) => {
				appendOrder.push(v.kind);
			},
			values: () => ([] as AuditSink[]).values(),
		};

		const contributionKinds: ContributionCollectorMap = {
			auditHooks: auditCollector,
		};

		// ModB provides slotAC which ModA requires → initOrder is [ModB, ModA]
		// But input-array order is [ModA, ModB]
		const modA = defineModule({
			name: "ModA",
			requires: ["slotAC"] as const,
			contributes: {
				auditHooks: [() => fakeAuditSink("hook_a")],
			},
		});

		const modB = defineModule({
			name: "ModB",
			provides: {
				slotAC: () => 42,
			},
			contributes: {
				auditHooks: [() => fakeAuditSink("hook_b")],
			},
		});

		// Input array order: [ModA, ModB] — but initOrder is [ModB, ModA]
		const world = await buildWorld([modA, modB], contributionKinds);
		await applyContributions(world, contributionKinds);

		// List-shaped append must follow INPUT-ARRAY order: hook_a first, hook_b second
		expect(appendOrder).toEqual(["hook_a", "hook_b"]);
	});
});

// ---------------------------------------------------------------------------
// 4. Bare RouteContribution value entries
// ---------------------------------------------------------------------------

describe("applyContributions — step 3: bare RouteContribution value entries", () => {
	it("static RouteContribution value is taken directly without invoking a factory wrapper", async () => {
		const collectedRoutes: CollectedRouteContribution[] = [];
		const routeCollector = {
			kind: "list-routes" as const,
			append: (v: CollectedRouteContribution) => {
				collectedRoutes.push(v);
			},
			freeze: () => {},
			values: () => collectedRoutes.values(),
		};

		const contributionKinds: ContributionCollectorMap = {
			routes: routeCollector,
		};

		const handler = stubHandler();
		const staticRoute = { mountPath: "/health", handler };

		const modA = defineModule({
			name: "ModA",
			contributes: {
				routes: [staticRoute],
			},
		});

		const world = await buildWorld([modA], contributionKinds);
		const result = await applyContributions(world, contributionKinds);

		// The route was collected
		expect(result.routes).toHaveLength(1);
		expect(result.routes[0]?.contribution).toBe(staticRoute);
		expect(result.routes[0]?.contributedBy).toBe("ModA");
		expect(result.routes[0]?.declarationIndex).toBe(0);
	});
});

// ---------------------------------------------------------------------------
// 5. Factory throw → BootError contribute-factory-failed
// ---------------------------------------------------------------------------

describe("applyContributions — step 2: factory throw wraps as BootError", () => {
	it("cause === thrown (reference equality), details.module/kind/name/originalError correct", async () => {
		const grantCollector = makeStubNameCollector<GrantHandler | null>();
		const contributionKinds: ContributionCollectorMap = { grants: grantCollector };

		const thrown = new Error("factory exploded");
		const modA = defineModule({
			name: "ModA",
			contributes: {
				grants: {
					failing_grant: () => {
						throw thrown;
					},
				},
			},
		});

		const world = await buildWorld([modA], contributionKinds);

		await expect(applyContributions(world, contributionKinds)).rejects.toSatisfy((err: unknown) => {
			if (!(err instanceof BootError)) return false;
			if (err.reason !== "contribute-factory-failed") return false;
			if (err.cause !== thrown) return false;
			const det = err.details as {
				module: string;
				kind: string;
				name: string;
				originalError: unknown;
			};
			return (
				det.module === "ModA" &&
				det.kind === "grants" &&
				det.name === "failing_grant" &&
				det.originalError === thrown
			);
		});
	});
});

describe("applyContributions — step 2: a grant is a handler", () => {
	it.each([
		["undefined", undefined],
		["a string", "handler"],
		["an array", []],
		["an object with no handle", {}],
		["an object whose handle is not a function", { handle: "handle" }],
	])(
		"refuses a grants factory that answers %s, naming the grant, and registers nothing",
		async (_label, answer) => {
			const grantCollector = makeStubNameCollector<GrantHandler | null>();
			const contributionKinds: ContributionCollectorMap = { grants: grantCollector };
			const modA = defineModule({
				name: "ModA",
				contributes: { grants: { broken_grant: () => answer as never } },
			});

			const world = await buildWorld([modA], contributionKinds);

			await expect(applyContributions(world, contributionKinds)).rejects.toSatisfy(
				(err: unknown) =>
					err instanceof BootError &&
					err.reason === "contribute-factory-failed" &&
					err.cause instanceof RangeError &&
					(err.cause as Error).message.startsWith('grants "broken_grant":'),
			);
			expect([...grantCollector.entries()]).toEqual([]);
		},
	);
});

// ---------------------------------------------------------------------------
// 6. Pre-scan prevents factory side-effect leak
// ---------------------------------------------------------------------------

describe("applyContributions — step 2: pre-scan prevents factory side-effect leak", () => {
	it("if the second grant name of a module is already registered, no factory runs", async () => {
		const spy1 = vi.fn((): GrantHandler => fakeGrantHandler("handler1"));
		const spy2 = vi.fn((): GrantHandler => fakeGrantHandler("handler2"));

		// Pre-populate the collector with "grant_conflict" so it already exists.
		// `as unknown as GrantHandler` on the existing entry: the pre-scan
		// path checks NAME presence (collector.entries()), not value shape;
		// the placeholder string is never invoked.
		const m = new Map<string, GrantHandler | null>([
			["grant_conflict", "existing" as unknown as GrantHandler],
		]);
		const spyCollector: GrantCollector = {
			kind: "name-keyed" as const,
			register: (n: string, v: GrantHandler | null) => {
				if (m.has(n)) throw new Error(`already ${n}`);
				m.set(n, v);
			},
			replace: (_n: string, _v: GrantHandler | null) => {},
			get: (n: string) => m.get(n),
			entries: () => m.entries(),
		};

		const contributionKinds: ContributionCollectorMap = { grants: spyCollector };

		// This module contributes 2 grants: grant_ok and grant_conflict.
		// grant_conflict already exists in the collector → pre-scan should catch it
		// before running ANY factory for this module.
		const modA = defineModule({
			name: "ModA",
			contributes: {
				grants: {
					grant_ok: spy1,
					grant_conflict: spy2,
				},
			},
		});

		const world = await buildWorld([modA], contributionKinds);

		await expect(applyContributions(world, contributionKinds)).rejects.toSatisfy(
			(err: unknown) => err instanceof BootError && err.reason === "duplicate-contribute",
		);

		// Neither factory should have run — pre-scan catches before materialise
		expect(spy1).not.toHaveBeenCalled();
		expect(spy2).not.toHaveBeenCalled();
	});
});

// ---------------------------------------------------------------------------
// 6b. A pre-scan refusal rolls back stage 3
// ---------------------------------------------------------------------------

describe("applyContributions — step 2: a pre-scan refusal runs the stage-3 cleanups", () => {
	/**
	 * Two providers whose lifecycle cleanups record their names, materialised
	 * A then B (B requires A's slot); B's cleanup throws after recording when
	 * `bThrows`.
	 */
	function providersWithCleanups(
		cleaned: string[],
		bThrows = false,
	): ReturnType<typeof defineModule>[] {
		return [
			defineModule({
				name: "ProvA",
				provides: { slotAC: () => 1 },
				lifecycle: { slotAC: { eager: true, cleanup: () => void cleaned.push("A") } },
			}),
			defineModule({
				name: "ProvB",
				requires: ["slotAC"] as never,
				provides: { slotBC: () => "b" },
				lifecycle: {
					slotBC: {
						eager: true,
						cleanup: () => {
							cleaned.push("B");
							if (bThrows) throw new Error("close failed");
						},
					},
				},
			}),
		];
	}

	const cases: readonly {
		readonly reason: string;
		readonly existing: ReadonlyMap<string, GrantHandler | null>;
		readonly module: ReturnType<typeof defineModule>;
	}[] = [
		{
			reason: "duplicate-contribute",
			existing: new Map([["taken", fakeGrantHandler("existing")]]),
			module: defineModule({
				name: "Contributor",
				contributes: { grants: { taken: () => fakeGrantHandler("second") } },
			}),
		},
		// Stage 1 refuses an override of a name nothing holds; one of a
		// switched-off entry reaches the pre-scan.
		{
			reason: "override-target-missing",
			existing: new Map([["off", null]]),
			module: defineModule({
				name: "Overrider",
				overrides: { grants: { off: () => fakeGrantHandler("override") } },
			}),
		},
	];

	it.each(cases)(
		"refuses as $reason after running each cleanup once, in reverse",
		async ({ reason, existing, module }) => {
			const cleaned: string[] = [];
			const collector = makeStubNameCollector<GrantHandler | null>();
			for (const [name, value] of existing) collector.register(name, value);
			const contributionKinds: ContributionCollectorMap = { grants: collector };
			const world = await buildWorld(
				[...providersWithCleanups(cleaned), module],
				contributionKinds,
			);
			expect(world.cleanups.map((record) => record.module)).toEqual(["ProvA", "ProvB"]);

			const err = await applyContributions(world, contributionKinds).then(
				() => undefined,
				(thrown: unknown) => thrown,
			);

			expect(err).toBeInstanceOf(BootError);
			expect((err as BootError).reason).toBe(reason);
			expect((err as BootError).details).not.toHaveProperty("cleanupErrors");
			expect(cleaned).toEqual(["B", "A"]);
		},
	);

	it("runs every cleanup when one throws, and still refuses with the pre-scan's reason", async () => {
		const cleaned: string[] = [];
		const collector = makeStubNameCollector<GrantHandler | null>();
		collector.register("off", null);
		const contributionKinds: ContributionCollectorMap = { grants: collector };
		const world = await buildWorld(
			[
				...providersWithCleanups(cleaned, true),
				defineModule({
					name: "Overrider",
					overrides: { grants: { off: () => fakeGrantHandler("override") } },
				}),
			],
			contributionKinds,
		);

		await expect(applyContributions(world, contributionKinds)).rejects.toMatchObject({
			reason: "override-target-missing",
		});
		expect(cleaned).toEqual(["B", "A"]);
	});
});

// ---------------------------------------------------------------------------
// 7. Overrides routed via collector.replace
// ---------------------------------------------------------------------------

describe("applyContributions — step 2: overrides routed via collector.replace", () => {
	it("override factory result is passed to collector.replace, not register", async () => {
		const registerCalls: Array<[string, GrantHandler | null]> = [];
		const replaceCalls: Array<[string, GrantHandler | null]> = [];

		// Collector whose internal map is mutated by both register and replace.
		const m = new Map<string, GrantHandler | null>();
		const spyCollector: GrantCollector = {
			kind: "name-keyed" as const,
			register: (n: string, v: GrantHandler | null) => {
				if (m.has(n)) throw new Error(`already registered: ${n}`);
				m.set(n, v);
				registerCalls.push([n, v]);
			},
			replace: (n: string, v: GrantHandler | null) => {
				if (!m.has(n)) throw new Error(`unknown: ${n}`);
				m.set(n, v);
				replaceCalls.push([n, v]);
			},
			get: (n: string) => m.get(n),
			entries: () => m.entries(),
		};

		const contributionKinds: ContributionCollectorMap = { grants: spyCollector };

		// Typed instance for the identity-equality assertion below.
		const overrideValue: GrantHandler = fakeGrantHandler("override");

		// ModA contributes base_grant via register; ModB overrides it via replace.
		const modA = defineModule({
			name: "ModA",
			contributes: {
				grants: { base_grant: () => fakeGrantHandler("base") },
			},
		});

		const modB = defineModule({
			name: "ModB",
			overrides: {
				grants: { base_grant: () => overrideValue },
			},
		});

		const world = await buildWorld([modA, modB], contributionKinds);
		await applyContributions(world, contributionKinds);

		// ModA's register was called first to set up the key
		expect(registerCalls).toHaveLength(1);
		expect(registerCalls[0]?.[0]).toBe("base_grant");

		// ModB's override was routed to replace, not register
		expect(replaceCalls).toHaveLength(1);
		expect(replaceCalls[0]?.[0]).toBe("base_grant");
		expect(replaceCalls[0]?.[1]).toBe(overrideValue);
	});
});

// ---------------------------------------------------------------------------
// 8. auditHooks same-instance dedup via collector
// ---------------------------------------------------------------------------

describe("applyContributions — step 3: auditHooks same-instance dedup", () => {
	it("two modules contributing the same hook reference: append called twice but collector dedupes", async () => {
		const auditCollector = makeStubListCollector<AuditSink>();
		const appendSpy = vi.spyOn(auditCollector, "append");

		const contributionKinds: ContributionCollectorMap = { auditHooks: auditCollector };

		// Typed instance for the identity-equality assertion below.
		const sharedHook: AuditSink = fakeAuditSink("shared_hook");

		const modA = defineModule({
			name: "ModA",
			contributes: {
				auditHooks: [() => sharedHook],
			},
		});

		const modB = defineModule({
			name: "ModB",
			contributes: {
				auditHooks: [() => sharedHook],
			},
		});

		const world = await buildWorld([modA, modB], contributionKinds);
		await applyContributions(world, contributionKinds);

		// append was called twice (once per module)
		expect(appendSpy).toHaveBeenCalledTimes(2);

		// But the collector deduplicated — only one entry in values
		const entries = [...auditCollector.values()];
		expect(entries).toHaveLength(1);
		expect(entries[0]).toBe(sharedHook);
	});
});

// ---------------------------------------------------------------------------
// 9. Defence-in-depth: missing required dep at apply-time throws
// ---------------------------------------------------------------------------

describe("applyContributions — defence-in-depth: missing required dep", () => {
	it("throws an invariant Error when a required dep is absent from the component map", async () => {
		// validate-manifests step 4 and planBoot's activation closure should make
		// this unreachable in normal flow, so the test corrupts material after
		// them to pin the apply-time boundary (the same throw as
		// materializeComponents.buildDeps).
		const modA = defineModule({
			name: "ModA",
			requires: ["slotAC"] as never,
			contributes: {
				grants: {
					my_grant: () => fakeGrantHandler("my_grant"),
				},
			},
		});
		const seededBoot = { ...minBoot, slotAC: 1 } as unknown as BootstrapMap;
		const validated = validateManifests({
			modules: [modA],
			bootstrapComponents: seededBoot,
			contributionKinds: { grants: makeStubNameCollector() },
		});
		const plan = planBoot(validated, seededBoot, undefined);
		const material = await materializeComponents(plan, seededBoot, undefined);

		// Corrupt: delete the required slot from material.components so the
		// apply-time buildDeps boundary trips on the missing key.
		const corruptedComponents = { ...material.components } as Record<string, unknown>;
		delete corruptedComponents.slotAC;
		const corruptedMaterial = {
			...material,
			components: corruptedComponents as ComponentWorld["components"],
		};

		await expect(
			applyContributions(corruptedMaterial, { grants: makeStubNameCollector() }),
		).rejects.toThrow(/missing required dep "slotAC"/);
	});
});

// ---------------------------------------------------------------------------
// 10. Consumer-defined kinds: step 2 / step 3 routing by collector.kind
// ---------------------------------------------------------------------------

describe("applyContributions — consumer-defined kinds, routed by collector.kind", () => {
	it("routes consumer-defined name-keyed kinds to register via collector.kind discriminant", async () => {
		// "myCustomKind" is not in the built-in NAME_KEYED_KINDS set, so routing
		// must rely on collector.kind === "name-keyed".
		const m = defineModule({
			name: "consumer-kind-mod",
			contributes: {
				myCustomKind: { item1: () => ({ tag: "v1" }) },
			} as never,
		});
		const validated = validateManifests({
			modules: [m],
			bootstrapComponents: minBoot,
			contributionKinds: { myCustomKind: makeStubNameCollector() } as never,
		});
		const plan = planBoot(validated, minBoot, undefined);
		const material = await materializeComponents(plan, minBoot, undefined);
		const stubCollector = makeStubNameCollector();
		await applyContributions(material, {
			myCustomKind: stubCollector,
		} as never);
		expect(stubCollector.get("item1")).toBeDefined();
	});

	it("routes consumer-defined list-shaped kinds to append via collector.kind discriminant", async () => {
		const hookA = () => ({});
		const hookB = () => ({});
		const m = defineModule({
			name: "consumer-list-mod",
			contributes: {
				myListKind: [() => hookA, () => hookB],
			} as never,
		});
		const validated = validateManifests({
			modules: [m],
			bootstrapComponents: minBoot,
			contributionKinds: { myListKind: makeStubListCollector() } as never,
		});
		const plan = planBoot(validated, minBoot, undefined);
		const material = await materializeComponents(plan, minBoot, undefined);
		const stubCollector = makeStubListCollector();
		await applyContributions(material, {
			myListKind: stubCollector,
		} as never);
		const values = Array.from(stubCollector.values());
		expect(values).toHaveLength(2);
	});
});

describe("core.sessionRequirements.secondFactorAuthority without a sessionRequirements collector", () => {
	it("refuses the key rather than skipping it: nothing can register the requirement it names", async () => {
		const bootstrap = {
			config: {
				...makeValidCoreConfig(),
				...coreConfigForTests({ expected: ["mfa"], secondFactorAuthority: "mfa" }),
			} as never,
			pathResolver: (s: string) => s,
		} satisfies Record<string, unknown> as BootstrapMap;
		const validated = validateManifests({
			modules: [],
			bootstrapComponents: bootstrap,
			contributionKinds: {},
		});
		const plan = planBoot(validated, bootstrap, undefined);
		const world = await materializeComponents(plan, bootstrap, undefined, {});
		await expect(applyContributions(world, {})).rejects.toSatisfy((err: unknown) => {
			expect(err).toBeInstanceOf(BootError);
			expect((err as BootError).details).toEqual({
				reason: "second-factor-authority-not-declared",
				configKey: "core.sessionRequirements.secondFactorAuthority",
				name: "mfa",
				unmet: ["not-registered"],
			});
			return true;
		});
	});
});
