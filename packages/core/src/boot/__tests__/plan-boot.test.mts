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
import { describe, expect, it } from "vitest";
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import { defineModule } from "../../modules/manifest/index.mjs";
import { planBoot } from "../plan-boot.mjs";
import type { BootstrapMap as BM, BootstrapMap } from "../types.mjs";
import { BootError } from "../types.mjs";
import { validateManifests } from "../validate-manifests.mjs";

// ---------------------------------------------------------------------------
// Test-only ComponentMap slot augmentation
// ---------------------------------------------------------------------------

declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly slotA: number;
		readonly slotB: number;
		readonly slotC: number;
	}
}

// ---------------------------------------------------------------------------
// In-test stub helpers — satisfy collector contracts without importing real
// collector implementations.
// ---------------------------------------------------------------------------

function makeStubNameCollector() {
	const m = new Map<string, unknown>();
	return {
		kind: "name-keyed" as const,
		register: (n: string, v: unknown) => {
			if (m.has(n)) throw new Error(`already registered: ${n}`);
			m.set(n, v);
		},
		replace: (n: string, v: unknown) => {
			if (!m.has(n)) throw new Error(`unknown key: ${n}`);
			m.set(n, v);
		},
		get: (n: string) => m.get(n),
		entries: () => m.entries() as IterableIterator<readonly [string, unknown]>,
	};
}

function makeStubListCollector() {
	const arr: unknown[] = [];
	return {
		kind: "list" as const,
		append: (v: unknown) => {
			arr.push(v);
		},
		values: () => arr.values() as IterableIterator<unknown>,
	};
}

// Per ADR 2026-04-30: schema is a pure type contract; defaults live in
// hocon. validateAndComposeConfig calls CoreConfigSchema.parse, so the
// fixture supplies a minimal schema-valid baseline (intentionally
// diverges from application.conf — see makeValidCoreConfig docstring).
const minBootstrap = {
	config: makeValidCoreConfig() as never,
	pathResolver: (s: string) => s,
} satisfies Record<string, unknown> as BM;

/**
 * Build a ValidatedManifests from modules + bootstrap for use as planBoot input.
 */
function validated(
	modules: ReturnType<typeof defineModule>[],
	bootstrap: BootstrapMap = minBootstrap,
	contributionKinds: Record<string, unknown> = {},
	overrideComponents?: Record<string, unknown>,
) {
	return validateManifests({
		modules,
		bootstrapComponents: bootstrap,
		contributionKinds: contributionKinds as never,
		overrideComponents: overrideComponents as never,
	});
}

// ---------------------------------------------------------------------------
// Cycle detection (step 2)
// ---------------------------------------------------------------------------

describe("planBoot — cycle detection (step 2)", () => {
	it("step 2: detects self-cycle (module requires its own provided key)", () => {
		const a = defineModule({
			name: "A",
			requires: ["slotA"] as const,
			provides: { slotA: () => 1 },
		});
		const vm = validated([a]);
		try {
			planBoot(vm, minBootstrap, undefined);
		} catch (e) {
			const err = e as BootError;
			expect(err.reason).toBe("circular-dependency");
			expect(err.stage).toBe("planBoot");
			if (err.details.reason === "circular-dependency") {
				expect(err.details.cycle.length).toBeGreaterThanOrEqual(1);
				expect(err.details.cycle[0]?.module).toBe("A");
			}
			return;
		}
		expect.fail("should have thrown");
	});

	it("step 2: detects self-cycle even when the slot is eager-seeded", () => {
		const a = defineModule({
			name: "A",
			requires: ["slotA"] as const,
			provides: { slotA: () => 1 },
			lifecycle: { slotA: { eager: true } },
		});
		const vm = validated([a]);
		expect(() => planBoot(vm, minBootstrap, undefined)).toThrowError(BootError);
	});

	it("throws circular-dependency with stage planBoot when A→B→A", () => {
		// A requires slotB (provided by B); B requires slotA (provided by A).
		const modA = defineModule({
			name: "A",
			requires: ["slotB"] as const,
			provides: {
				slotA: (_deps) => 1,
			},
		});
		const modB = defineModule({
			name: "B",
			requires: ["slotA"] as const,
			provides: {
				slotB: (_deps) => 2,
			},
		});

		// validateManifests passes (requires are all satisfiable).
		const vm = validated([modA, modB]);

		expect(() => planBoot(vm, minBootstrap, undefined)).toThrowError(BootError);

		try {
			planBoot(vm, minBootstrap, undefined);
		} catch (e) {
			const err = e as BootError;
			expect(err.reason).toBe("circular-dependency");
			expect(err.stage).toBe("planBoot");
			if (err.details.reason === "circular-dependency") {
				expect(err.details.cycle.length).toBe(2);
				// Cycle entries must reference the two modules
				const moduleNames = err.details.cycle.map((c) => c.module);
				expect(moduleNames).toContain("A");
				expect(moduleNames).toContain("B");
			}
		}
	});
});

// ---------------------------------------------------------------------------
// Topological sort (step 3)
// ---------------------------------------------------------------------------

describe("planBoot — step 3: topological sort respects requires edges", () => {
	it("places provider module before requiring module in initOrder", () => {
		// A requires slotB which is provided by B. B must come before A.
		const modB = defineModule({
			name: "B",
			provides: {
				slotB: () => 2,
			},
		});
		const modA = defineModule({
			name: "A",
			requires: ["slotB"] as const,
			provides: {
				slotA: () => 1,
			},
		});

		const vm = validated([modA, modB]);
		const plan = planBoot(vm, minBootstrap, undefined);

		const bIdx = plan.initOrder.indexOf("B");
		const aIdx = plan.initOrder.indexOf("A");
		expect(bIdx).toBeGreaterThanOrEqual(0);
		expect(aIdx).toBeGreaterThanOrEqual(0);
		expect(bIdx).toBeLessThan(aIdx);
	});
});

describe("planBoot — step 3: declaration-order tie-breaking", () => {
	it("for three independent modules [A,B,C], initOrder === [A,B,C]", () => {
		const modA = defineModule({ name: "A", provides: { slotA: () => 1 } });
		const modB = defineModule({ name: "B", provides: { slotB: () => 2 } });
		const modC = defineModule({ name: "C", provides: { slotC: () => 3 } });

		const vm = validated([modA, modB, modC]);
		const plan = planBoot(vm, minBootstrap, undefined);

		expect(plan.initOrder).toEqual(["A", "B", "C"]);
	});

	it("for three independent modules [C,B,A], initOrder === [C,B,A]", () => {
		const modC = defineModule({ name: "C", provides: { slotC: () => 3 } });
		const modB = defineModule({ name: "B", provides: { slotB: () => 2 } });
		const modA = defineModule({ name: "A", provides: { slotA: () => 1 } });

		const vm = validated([modC, modB, modA]);
		const plan = planBoot(vm, minBootstrap, undefined);

		expect(plan.initOrder).toEqual(["C", "B", "A"]);
	});
});

// ---------------------------------------------------------------------------
// Per-component activation closure (step 4)
// ---------------------------------------------------------------------------

describe("planBoot — step 4: skip unused providers", () => {
	it("unused non-eager provider does NOT appear in providerActivations", () => {
		// Module A provides slotA but no one requires it, no contributes, no eager.
		const modA = defineModule({ name: "A", provides: { slotA: () => 1 } });

		const vm = validated([modA]);
		const plan = planBoot(vm, minBootstrap, undefined);

		const hasSlotA = plan.providerActivations.some(
			(pa) => pa.module === "A" && pa.componentKey === "slotA",
		);
		expect(hasSlotA).toBe(false);
	});

	it("eager provider IS in providerActivations with eager:true", () => {
		// Module B provides slotB with lifecycle.slotB.eager === true.
		const modB = defineModule({
			name: "B",
			provides: { slotB: () => 2 },
			lifecycle: { slotB: { eager: true } },
		});

		const vm = validated([modB]);
		const plan = planBoot(vm, minBootstrap, undefined);

		const act = plan.providerActivations.find(
			(pa) => pa.module === "B" && pa.componentKey === "slotB",
		);
		expect(act).toBeDefined();
		expect(act?.eager).toBe(true);
	});
});

describe("planBoot — step 4: closure root via contributes", () => {
	it("contribute-driven module causes its required provider to appear in providerActivations", () => {
		// Module C requires slotC and contributes auditHooks.
		// Module P provides slotC.
		// C is a closure root via contributes → P's slotC must materialise.
		const modP = defineModule({ name: "P", provides: { slotC: () => 3 } });
		const modC = defineModule({
			name: "C",
			requires: ["slotC"] as const,
			contributes: {
				auditHooks: [() => ({ name: "hook", run: async () => {} })],
			},
		});

		const vm = validated([modP, modC], minBootstrap, {
			auditHooks: makeStubListCollector(),
		});
		const plan = planBoot(vm, minBootstrap, undefined);

		const slotCActivation = plan.providerActivations.find(
			(pa) => pa.module === "P" && pa.componentKey === "slotC",
		);
		expect(slotCActivation).toBeDefined();
	});
});

describe("planBoot — step 4: closure root via overrides", () => {
	it("overrides-driven module causes its required provider to appear in providerActivations", () => {
		// Module P provides slotC.
		// Module Base contributes grants.baseGrant (so override target exists).
		// Module C requires slotC and overrides grants.baseGrant.
		// C is a closure root via overrides → P's slotC must materialise.
		const modP = defineModule({ name: "P", provides: { slotC: () => 3 } });
		const modBase = defineModule({
			name: "Base",
			contributes: {
				grants: {
					baseGrant: () =>
						({ type: "authorization_code", handle: async () => ({ error: "denied" }) }) as never,
				},
			},
		});
		const modC = defineModule({
			name: "C",
			requires: ["slotC"] as const,
			overrides: {
				grants: {
					baseGrant: () =>
						({ type: "authorization_code", handle: async () => ({ error: "denied" }) }) as never,
				},
			},
		});

		const vm = validated([modP, modBase, modC], minBootstrap, {
			grants: makeStubNameCollector(),
		});
		const plan = planBoot(vm, minBootstrap, undefined);

		const slotCActivation = plan.providerActivations.find(
			(pa) => pa.module === "P" && pa.componentKey === "slotC",
		);
		expect(slotCActivation).toBeDefined();
	});
});

describe("planBoot — step 4: eager seeds independent of require closure", () => {
	it("eager component appears in providerActivations with eager:true even when nothing requires it", () => {
		// Module A provides slotA with lifecycle.slotA.eager === true.
		// No other module requires slotA.
		const modA = defineModule({
			name: "A",
			provides: { slotA: () => 1 },
			lifecycle: { slotA: { eager: true } },
		});

		const vm = validated([modA]);
		const plan = planBoot(vm, minBootstrap, undefined);

		const act = plan.providerActivations.find(
			(pa) => pa.module === "A" && pa.componentKey === "slotA",
		);
		expect(act).toBeDefined();
		expect(act?.eager).toBe(true);
	});
});

describe("planBoot — step 4: non-eager sibling does NOT piggy-back", () => {
	it("module M with slotA eager + slotB non-eager: only slotA appears, slotB absent", () => {
		// Module M provides both slotA (eager) and slotB (not eager).
		// No other module requires slotB.
		const modM = defineModule({
			name: "M",
			provides: {
				slotA: () => 1,
				slotB: () => 2,
			},
			lifecycle: { slotA: { eager: true } },
		});

		const vm = validated([modM]);
		const plan = planBoot(vm, minBootstrap, undefined);

		const slotAActivation = plan.providerActivations.find(
			(pa) => pa.module === "M" && pa.componentKey === "slotA",
		);
		expect(slotAActivation).toBeDefined();
		expect(slotAActivation?.eager).toBe(true);

		const slotBActivation = plan.providerActivations.find(
			(pa) => pa.module === "M" && pa.componentKey === "slotB",
		);
		expect(slotBActivation).toBeUndefined();
	});
});

// ---------------------------------------------------------------------------
// eager flag: true only when activation entered exclusively via eager-seed
// ---------------------------------------------------------------------------

describe("planBoot — eager flag semantics", () => {
	it("provider required by a contribute-root module has eager:false even if also eager-seeded", () => {
		// Module P provides slotC with lifecycle.slotC.eager === true.
		// Module C requires slotC and contributes auditHooks.
		// P.slotC enters the closure both via eager-seed AND require-chain.
		// Per spec: eager:true only when the activation entered EXCLUSIVELY via eager-seed.
		// Since it also entered via require-chain, eager should be false.
		const modP = defineModule({
			name: "P",
			provides: { slotC: () => 3 },
			lifecycle: { slotC: { eager: true } },
		});
		const modC = defineModule({
			name: "C",
			requires: ["slotC"] as const,
			contributes: {
				auditHooks: [() => ({ name: "hook", run: async () => {} })],
			},
		});

		const vm = validated([modP, modC], minBootstrap, {
			auditHooks: makeStubListCollector(),
		});
		const plan = planBoot(vm, minBootstrap, undefined);

		const act = plan.providerActivations.find(
			(pa) => pa.module === "P" && pa.componentKey === "slotC",
		);
		expect(act).toBeDefined();
		// Entered via both paths — eager must be false.
		expect(act?.eager).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// depsBlueprint
// ---------------------------------------------------------------------------

describe("planBoot — depsBlueprint", () => {
	it("modules with contributes entries appear in depsBlueprint with their requires", () => {
		const modP = defineModule({ name: "P", provides: { slotC: () => 3 } });
		const modC = defineModule({
			name: "C",
			requires: ["slotC"] as const,
			contributes: {
				auditHooks: [() => ({ name: "hook", run: async () => {} })],
			},
		});

		const vm = validated([modP, modC], minBootstrap, {
			auditHooks: makeStubListCollector(),
		});
		const plan = planBoot(vm, minBootstrap, undefined);

		const blueprint = plan.depsBlueprint.get("C");
		expect(blueprint).toBeDefined();
		expect(blueprint?.requires).toContain("slotC");
	});

	it("modules with in-closure provides appear in depsBlueprint", () => {
		const modP = defineModule({ name: "P", provides: { slotC: () => 3 } });
		const modC = defineModule({
			name: "C",
			requires: ["slotC"] as const,
			contributes: {
				auditHooks: [() => ({ name: "hook", run: async () => {} })],
			},
		});

		const vm = validated([modP, modC], minBootstrap, {
			auditHooks: makeStubListCollector(),
		});
		const plan = planBoot(vm, minBootstrap, undefined);

		// P is a provider module in the closure; it should have a depsBlueprint entry.
		const blueprint = plan.depsBlueprint.get("P");
		expect(blueprint).toBeDefined();
	});
});
