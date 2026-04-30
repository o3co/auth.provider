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
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import { defineModule } from "../../modules/manifest/index.mjs";
import { materializeComponents } from "../materialize-components.mjs";
import { planBoot } from "../plan-boot.mjs";
import type { BootstrapMap } from "../types.mjs";
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
		readonly slotD: number;
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Per ADR 2026-04-30: schema is a pure type contract; defaults live in
// hocon. validateAndComposeConfig calls CoreConfigSchema.parse, so the
// fixture supplies a minimal schema-valid baseline (intentionally
// diverges from application.conf — see makeValidCoreConfig docstring).
const minBoot = {
	config: makeValidCoreConfig() as never,
	pathResolver: (s: string) => s,
} satisfies Record<string, unknown> as BootstrapMap;

/**
 * Build a BootPlan from modules + optional bootstrap/overrides.
 */
function buildPlan(
	modules: ReturnType<typeof defineModule>[],
	bootstrap: BootstrapMap = minBoot,
	overrideComponents?: Partial<Record<string, unknown>>,
) {
	const validated = validateManifests({
		modules,
		bootstrapComponents: bootstrap,
		contributionKinds: {},
		overrideComponents: overrideComponents as never,
	});
	return planBoot(validated, bootstrap, overrideComponents as never);
}

// ---------------------------------------------------------------------------
// 1. Pre-seed bootstrap
// ---------------------------------------------------------------------------

describe("materializeComponents — pre-seed bootstrap", () => {
	it("bootstrap values appear in world.components; factory can read them as deps", async () => {
		// Module depends on 'config' (bootstrap) and provides slotA using it.
		// We verify via a side-channel that the factory received the bootstrap value.
		let receivedConfig: unknown;
		const modA = defineModule({
			name: "A",
			requires: ["config"] as const,
			provides: {
				slotA: (deps) => {
					receivedConfig = deps.config;
					return 42;
				},
			},
			lifecycle: { slotA: { eager: true } },
		});

		const plan = buildPlan([modA]);
		const world = await materializeComponents(plan, minBoot, undefined);

		// The bootstrap config must be present in the world's components
		expect(world.components.config).toBe(minBoot.config);
		// The factory received it as a dep
		expect(receivedConfig).toBe(minBoot.config);
		// slotA was materialised
		expect(world.components.slotA).toBe(42);
	});
});

// ---------------------------------------------------------------------------
// 2. overrideComponents skip-and-replace
// ---------------------------------------------------------------------------

describe("materializeComponents — overrideComponents skip-and-replace", () => {
	it("provider factory is NOT invoked; override value is stored; lifecycle.cleanup is NOT recorded", async () => {
		const factorySpy = vi.fn(() => 99);
		const cleanupSpy = vi.fn();

		const modA = defineModule({
			name: "A",
			provides: {
				slotA: factorySpy,
			},
			lifecycle: {
				slotA: {
					eager: true,
					cleanup: cleanupSpy,
				},
			},
		});

		const overrides = { slotA: 777 } as Partial<Record<string, unknown>>;
		const plan = buildPlan([modA], minBoot, overrides);

		const world = await materializeComponents(plan, minBoot, overrides as never);

		// Factory must NOT have been called
		expect(factorySpy).not.toHaveBeenCalled();
		// Override value must be in components
		expect(world.components.slotA).toBe(777);
		// Lifecycle cleanup must NOT be recorded (consumer's responsibility)
		expect(world.cleanups).toHaveLength(0);
	});
});

// ---------------------------------------------------------------------------
// 3. Sync factory
// ---------------------------------------------------------------------------

describe("materializeComponents — sync factory", () => {
	it("factory returning a plain value is stored correctly", async () => {
		const modA = defineModule({
			name: "A",
			provides: {
				slotA: () => 123,
			},
			lifecycle: { slotA: { eager: true } },
		});

		const plan = buildPlan([modA]);
		const world = await materializeComponents(plan, minBoot, undefined);

		expect(world.components.slotA).toBe(123);
	});
});

// ---------------------------------------------------------------------------
// 4. Async factory
// ---------------------------------------------------------------------------

describe("materializeComponents — async factory", () => {
	it("factory returning a Promise resolves and the value is stored", async () => {
		const modA = defineModule({
			name: "A",
			provides: {
				slotA: async () => Promise.resolve(456),
			},
			lifecycle: { slotA: { eager: true } },
		});

		const plan = buildPlan([modA]);
		const world = await materializeComponents(plan, minBoot, undefined);

		expect(world.components.slotA).toBe(456);
	});
});

// ---------------------------------------------------------------------------
// 5. Factory throw → BootError provides-factory-failed
// ---------------------------------------------------------------------------

describe("materializeComponents — factory throw → BootError", () => {
	it("thrown value is preserved as cause (reference equality) and details.originalError", async () => {
		const thrown = new Error("kaboom");

		const modA = defineModule({
			name: "A",
			provides: {
				slotA: () => {
					throw thrown;
				},
			},
			lifecycle: { slotA: { eager: true } },
		});

		const plan = buildPlan([modA]);

		let caught: unknown;
		try {
			await materializeComponents(plan, minBoot, undefined);
		} catch (e) {
			caught = e;
		}

		expect(caught).toBeInstanceOf(BootError);
		const err = caught as BootError;
		expect(err.reason).toBe("provides-factory-failed");
		expect(err.stage).toBe("materializeComponents");
		// cause reference equality — verbatim thrown value
		expect(err.cause).toBe(thrown);
		if (err.details.reason === "provides-factory-failed") {
			expect(err.details.originalError).toBe(thrown);
			expect(err.details.module).toBe("A");
			expect(err.details.componentKey).toBe("slotA");
		} else {
			expect.fail("unexpected details reason");
		}
	});
});

// ---------------------------------------------------------------------------
// 6. Partial rollback runs cleanups in REVERSE order
// ---------------------------------------------------------------------------

describe("materializeComponents — partial rollback reverse order", () => {
	it("first module's cleanup runs after BootError from second factory", async () => {
		const cleanupOrder: string[] = [];

		// Module A: provides slotA, has a cleanup that records 'A'
		const modA = defineModule({
			name: "A",
			provides: {
				slotA: () => 1,
			},
			lifecycle: {
				slotA: {
					eager: true,
					cleanup: () => {
						cleanupOrder.push("A");
					},
				},
			},
		});

		// Module B: provides slotB, requires slotA, its factory throws
		const modB = defineModule({
			name: "B",
			requires: ["slotA"] as const,
			provides: {
				slotB: () => {
					throw new Error("B failed");
				},
			},
			lifecycle: { slotB: { eager: true } },
		});

		const plan = buildPlan([modA, modB]);

		let caught: unknown;
		try {
			await materializeComponents(plan, minBoot, undefined);
		} catch (e) {
			caught = e;
		}

		expect(caught).toBeInstanceOf(BootError);
		// A's cleanup ran during partial rollback
		expect(cleanupOrder).toEqual(["A"]);
	});
});

// ---------------------------------------------------------------------------
// 7. Cleanup error during partial rollback is collected
// ---------------------------------------------------------------------------

describe("materializeComponents — cleanup error during partial rollback collected", () => {
	it("cleanup throwing does not abort rollback; errors collected in details.cleanupErrors", async () => {
		const cleanupOrder: string[] = [];

		// Module A: cleanup THROWS
		const modA = defineModule({
			name: "A",
			provides: {
				slotA: () => 1,
			},
			lifecycle: {
				slotA: {
					eager: true,
					cleanup: () => {
						cleanupOrder.push("A-fail");
						throw new Error("cleanup-A-error");
					},
				},
			},
		});

		// Module B: provides slotB, requires slotA, its factory throws
		const modB = defineModule({
			name: "B",
			requires: ["slotA"] as const,
			provides: {
				slotB: () => {
					throw new Error("B failed");
				},
			},
			lifecycle: { slotB: { eager: true } },
		});

		const plan = buildPlan([modA, modB]);

		let caught: unknown;
		try {
			await materializeComponents(plan, minBoot, undefined);
		} catch (e) {
			caught = e;
		}

		expect(caught).toBeInstanceOf(BootError);
		const err = caught as BootError;
		expect(err.reason).toBe("provides-factory-failed");

		if (err.details.reason === "provides-factory-failed") {
			// cleanupErrors must be populated with A's cleanup error
			expect(err.details.cleanupErrors).toBeDefined();
			expect(err.details.cleanupErrors).toHaveLength(1);
			expect(err.details.cleanupErrors?.[0]?.module).toBe("A");
			expect(err.details.cleanupErrors?.[0]?.componentKey).toBe("slotA");
			expect((err.details.cleanupErrors?.[0]?.error as Error).message).toBe("cleanup-A-error");
		} else {
			expect.fail("unexpected details reason");
		}

		// Cleanup ran despite the error (it was just recorded)
		expect(cleanupOrder).toEqual(["A-fail"]);
	});

	it("two cleanups: first throws, second still runs; both errors collected", async () => {
		const cleanupOrder: string[] = [];

		// Module A: cleanup throws
		const modA = defineModule({
			name: "A",
			provides: {
				slotA: () => 1,
			},
			lifecycle: {
				slotA: {
					eager: true,
					cleanup: () => {
						cleanupOrder.push("A");
						throw new Error("cleanup-A");
					},
				},
			},
		});

		// Module B: provides slotB (requires slotA), also has cleanup that throws
		const modB = defineModule({
			name: "B",
			requires: ["slotA"] as const,
			provides: {
				slotB: () => 100,
			},
			lifecycle: {
				slotB: {
					eager: true,
					cleanup: () => {
						cleanupOrder.push("B");
						throw new Error("cleanup-B");
					},
				},
			},
		});

		// Module C: provides slotC (requires slotB), its factory throws
		const modC = defineModule({
			name: "C",
			requires: ["slotB"] as const,
			provides: {
				slotC: () => {
					throw new Error("C failed");
				},
			},
			lifecycle: { slotC: { eager: true } },
		});

		const plan = buildPlan([modA, modB, modC]);

		let caught: unknown;
		try {
			await materializeComponents(plan, minBoot, undefined);
		} catch (e) {
			caught = e;
		}

		expect(caught).toBeInstanceOf(BootError);
		const err = caught as BootError;

		if (err.details.reason === "provides-factory-failed") {
			expect(err.details.cleanupErrors).toHaveLength(2);
			// Both ran even though both threw
		} else {
			expect.fail("unexpected details reason");
		}

		// Both cleanups ran (reverse order: B first, then A)
		expect(cleanupOrder).toEqual(["B", "A"]);
	});
});

// ---------------------------------------------------------------------------
// 8. CleanupRecord only for components with lifecycle[K].cleanup
// ---------------------------------------------------------------------------

describe("materializeComponents — CleanupRecord only when cleanup defined", () => {
	it("module WITHOUT lifecycle cleanup does NOT push a CleanupRecord", async () => {
		// Module A: provides slotA, NO lifecycle.cleanup
		const modA = defineModule({
			name: "A",
			provides: {
				slotA: () => 1,
			},
			lifecycle: { slotA: { eager: true } }, // eager but no cleanup
		});

		const plan = buildPlan([modA]);
		const world = await materializeComponents(plan, minBoot, undefined);

		expect(world.cleanups).toHaveLength(0);
	});

	it("module WITH lifecycle.cleanup DOES push a CleanupRecord", async () => {
		const cleanupFn = vi.fn();

		const modA = defineModule({
			name: "A",
			provides: {
				slotA: () => 42,
			},
			lifecycle: {
				slotA: {
					eager: true,
					cleanup: cleanupFn,
				},
			},
		});

		const plan = buildPlan([modA]);
		const world = await materializeComponents(plan, minBoot, undefined);

		expect(world.cleanups).toHaveLength(1);
		expect(world.cleanups[0]?.module).toBe("A");
		expect(world.cleanups[0]?.componentKey).toBe("slotA");
		expect(world.cleanups[0]?.cleanup).toBe(cleanupFn);
		expect(world.cleanups[0]?.value).toBe(42);
	});
});
