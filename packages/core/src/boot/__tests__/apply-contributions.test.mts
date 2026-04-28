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
import { defineModule } from "../../modules/manifest/index.mjs";
import { applyContributions } from "../apply-contributions.mjs";
import { materializeComponents } from "../materialize-components.mjs";
import { planBoot } from "../plan-boot.mjs";
import type {
	BootstrapMap,
	CollectedRouteContribution,
	ComponentWorld,
	ContributionCollectorMap,
} from "../types.mjs";
import { BootError } from "../types.mjs";
import { validateManifests } from "../validate-manifests.mjs";

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

const minBoot = {
	config: {} as never,
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
	return materializeComponents(plan, minBoot, undefined);
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
		const grantCollector = makeStubNameCollector<unknown>();
		const contributionKinds: ContributionCollectorMap = {
			grants: grantCollector,
		};

		const modA = defineModule({
			name: "ModA",
			contributes: {
				grants: {
					authorization_code: () => ({ type: "grant" }),
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

		const spyCollector = {
			kind: "name-keyed" as const,
			register: (n: string, _v: unknown) => {
				registerOrder.push(n);
			},
			replace: (_n: string, _v: unknown) => {},
			get: (_n: string) => undefined,
			entries: () => new Map<string, unknown>().entries(),
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
				grants: { grant_a: () => "handlerA" as unknown },
			},
		});

		const modB = defineModule({
			name: "ModB",
			requires: ["slotAC"] as const,
			contributes: {
				grants: { grant_b: () => "handlerB" as unknown },
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

		// Spy collector that records which hook's tag was appended
		const auditCollector = {
			kind: "list" as const,
			append: (v: unknown) => {
				appendOrder.push((v as { tag: string }).tag);
			},
			values: () => ([] as unknown[]).values(),
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
				auditHooks: [() => ({ tag: "hook_a" }) as unknown],
			},
		});

		const modB = defineModule({
			name: "ModB",
			provides: {
				slotAC: () => 42,
			},
			contributes: {
				auditHooks: [() => ({ tag: "hook_b" }) as unknown],
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
		const grantCollector = makeStubNameCollector<unknown>();
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

// ---------------------------------------------------------------------------
// 6. Pre-scan prevents factory side-effect leak
// ---------------------------------------------------------------------------

describe("applyContributions — step 2: pre-scan prevents factory side-effect leak", () => {
	it("if the second grant name of a module is already registered, no factory runs", async () => {
		const spy1 = vi.fn(() => "handler1");
		const spy2 = vi.fn(() => "handler2");

		// Pre-populate the collector with "grant_conflict" so it already exists
		const m = new Map<string, unknown>([["grant_conflict", "existing"]]);
		const spyCollector = {
			kind: "name-keyed" as const,
			register: (n: string, v: unknown) => {
				if (m.has(n)) throw new Error(`already ${n}`);
				m.set(n, v);
			},
			replace: (_n: string, _v: unknown) => {},
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
// 7. Overrides routed via collector.replace
// ---------------------------------------------------------------------------

describe("applyContributions — step 2: overrides routed via collector.replace", () => {
	it("override factory result is passed to collector.replace, not register", async () => {
		const registerCalls: Array<[string, unknown]> = [];
		const replaceCalls: Array<[string, unknown]> = [];

		// Collector whose internal map is mutated by both register and replace.
		const m = new Map<string, unknown>();
		const spyCollector = {
			kind: "name-keyed" as const,
			register: (n: string, v: unknown) => {
				if (m.has(n)) throw new Error(`already registered: ${n}`);
				m.set(n, v);
				registerCalls.push([n, v]);
			},
			replace: (n: string, v: unknown) => {
				if (!m.has(n)) throw new Error(`unknown: ${n}`);
				m.set(n, v);
				replaceCalls.push([n, v]);
			},
			get: (n: string) => m.get(n),
			entries: () => m.entries(),
		};

		const contributionKinds: ContributionCollectorMap = { grants: spyCollector };

		const overrideValue = { type: "override_handler" };

		// ModA contributes base_grant via register; ModB overrides it via replace.
		const modA = defineModule({
			name: "ModA",
			contributes: {
				grants: { base_grant: () => "base_handler" as unknown },
			},
		});

		const modB = defineModule({
			name: "ModB",
			overrides: {
				grants: { base_grant: () => overrideValue as unknown },
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
		const auditCollector = makeStubListCollector<unknown>();
		const appendSpy = vi.spyOn(auditCollector, "append");

		const contributionKinds: ContributionCollectorMap = { auditHooks: auditCollector };

		const sharedHook = { type: "shared_hook" };

		const modA = defineModule({
			name: "ModA",
			contributes: {
				auditHooks: [() => sharedHook as unknown],
			},
		});

		const modB = defineModule({
			name: "ModB",
			contributes: {
				auditHooks: [() => sharedHook as unknown],
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
