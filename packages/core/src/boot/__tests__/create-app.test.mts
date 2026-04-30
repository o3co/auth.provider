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
 * boot/__tests__/create-app.test.mts — Orchestrator-level tests.
 *
 * Covers:
 *   1. Happy path: minimal manifest boots — one module providing one slot,
 *      no contributes, no routes. `createApp(...)` resolves to an `AppHandle`.
 *   2. Each stage's representative error reaches the caller with the correct
 *      `stage` field (5 stages that can fail: validateManifests, planBoot,
 *      materializeComponents, applyContributions, assembleApp).
 *
 * Per A2-β §6.2 / §6.4 / §9.
 */

import { describe, expect, it } from "vitest";
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import { defineModule } from "../../modules/manifest/index.mjs";
import { createApp } from "../create-app.mjs";
import type {
	AppHandle,
	BootstrapMap,
	CollectedRouteContribution,
	ContributionCollectorMap,
} from "../types.mjs";
import { BootError } from "../types.mjs";

// ---------------------------------------------------------------------------
// Test-only ComponentMap augmentation
// ---------------------------------------------------------------------------

declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly slotCA: number;
		readonly slotCB: string;
	}
}

// ---------------------------------------------------------------------------
// Minimal bootstrap stub
// ---------------------------------------------------------------------------

// Per ADR 2026-04-30: schema is a pure type contract; defaults live in
// hocon. validateAndComposeConfig calls CoreConfigSchema.parse, so the
// fixture supplies a minimal schema-valid baseline (intentionally
// diverges from application.conf — see makeValidCoreConfig docstring).
const minBoot = {
	config: makeValidCoreConfig() as never,
	pathResolver: (s: string) => s,
} satisfies Record<string, unknown> as BootstrapMap;

// ---------------------------------------------------------------------------
// Stub helpers
// ---------------------------------------------------------------------------

function makeStubNameCollector<V = unknown>() {
	const m = new Map<string, V>();
	return {
		kind: "name-keyed" as const,
		register: (n: string, v: V) => {
			if (m.has(n)) throw new Error(`already registered: ${n}`);
			m.set(n, v);
		},
		replace: (n: string, v: V) => {
			if (!m.has(n)) throw new Error(`unknown key: ${n}`);
			m.set(n, v);
		},
		get: (n: string) => m.get(n),
		entries: () => m.entries() as IterableIterator<readonly [string, V]>,
	};
}

function makeStubRouteCollector() {
	const arr: CollectedRouteContribution[] = [];
	let frozen = false;
	return {
		kind: "list-routes" as const,
		append: (v: CollectedRouteContribution) => {
			if (frozen) throw new Error("collector is frozen");
			arr.push(v);
		},
		freeze: () => {
			frozen = true;
		},
		values: () => arr.values(),
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
		values: () => arr.values() as IterableIterator<V>,
	};
}

/** Full stub ContributionCollectorMap for tests that do not exercise contribution kinds. */
function makeStubCollectors(): ContributionCollectorMap {
	return {
		grants: makeStubNameCollector(),
		tokenExchangeValidators: makeStubNameCollector(),
		federations: makeStubNameCollector(),
		mfaFactors: makeStubNameCollector(),
		auditHooks: makeStubListCollector(),
		routes: makeStubRouteCollector(),
		grantPolicyHooks: makeStubListCollector(),
	};
}

// ---------------------------------------------------------------------------
// 1. Happy path: minimal manifest boots
// ---------------------------------------------------------------------------

describe("createApp — 1. happy path: minimal manifest boots", () => {
	it("resolves to an AppHandle with frozen components — module activated via eager lifecycle", async () => {
		// Use `lifecycle.slotCA.eager = true` to force the module into the
		// activation closure. Without eager or a requiring module, a provides-only
		// module will not be materialised (planBoot design: closure roots are
		// contributes/overrides or eager seeds).
		const mod = defineModule({
			name: "MinimalMod",
			provides: {
				slotCA: async (_deps) => 42,
			},
			lifecycle: {
				slotCA: { eager: true },
			},
		});

		const handle = await createApp({
			modules: [mod],
			bootstrapComponents: minBoot,
			contributionKinds: makeStubCollectors(),
		});

		expect(handle).toBeDefined();
		// AppHandle is frozen (Theme D)
		expect(Object.isFrozen(handle)).toBe(true);
		// components map is accessible and contains the bootstrap keys
		expect(handle.components).toBeDefined();
		// config is now the parsed (CoreConfigSchema-validated) result —
		// not the raw bootstrap reference. See validateAndComposeConfig
		// substitution per Codex P2-A hardening. The `port: 3000` value
		// comes from the makeValidCoreConfig fixture; per ADR 2026-04-30
		// the schema layer no longer carries a default for it.
		expect((handle.components.config as { http: { port: number } }).http.port).toBe(3000);
		expect(handle.components.pathResolver).toBe(minBoot.pathResolver);
		// The slot provided by the module is materialised (eager activation)
		expect(handle.components.slotCA).toBe(42);
		// router is present
		expect(handle.router).toBeDefined();
		// dispose is a function
		expect(typeof handle.dispose).toBe("function");
	});

	it("resolves to an AppHandle with no modules — bootstrap components are accessible", async () => {
		const handle: AppHandle = await createApp({
			modules: [],
			bootstrapComponents: minBoot,
			contributionKinds: makeStubCollectors(),
		});

		expect(handle).toBeDefined();
		expect(Object.isFrozen(handle)).toBe(true);
		expect(Object.isFrozen(handle.components)).toBe(true);
		// Bootstrap components are present in the frozen component map.
		// config is now the parsed (CoreConfigSchema-validated) result —
		// not the raw bootstrap reference. See validateAndComposeConfig
		// substitution per Codex P2-A hardening. The `port: 3000` value
		// comes from the makeValidCoreConfig fixture; per ADR 2026-04-30
		// the schema layer no longer carries a default for it.
		expect((handle.components.config as { http: { port: number } }).http.port).toBe(3000);
		expect(handle.components.pathResolver).toBe(minBoot.pathResolver);
	});
});

// ---------------------------------------------------------------------------
// 2. Stage error propagation — each stage's representative error reaches the
//    caller with the correct `stage` field.
// ---------------------------------------------------------------------------

describe("createApp — 2. stage 1 error: duplicate-module-name → stage: validateManifests", () => {
	it("throws BootError with stage=validateManifests on duplicate module name", async () => {
		const modA = defineModule({ name: "DupMod", provides: {} });
		const modB = defineModule({ name: "DupMod", provides: {} });

		const promise = createApp({
			modules: [modA, modB],
			bootstrapComponents: minBoot,
			contributionKinds: makeStubCollectors(),
		});

		await expect(promise).rejects.toBeInstanceOf(BootError);
		await expect(promise).rejects.toMatchObject({
			reason: "duplicate-module-name",
			stage: "validateManifests",
		});
	});
});

describe("createApp — 3. stage 2 error: circular-dependency → stage: planBoot", () => {
	it("throws BootError with stage=planBoot on a circular dependency", async () => {
		// ModA requires slotCB (provided by ModB), ModB requires slotCA (provided by ModA)
		const modA = defineModule({
			name: "CircA",
			requires: ["slotCB"],
			provides: {
				slotCA: async (_deps) => 1,
			},
		});
		const modB = defineModule({
			name: "CircB",
			requires: ["slotCA"],
			provides: {
				slotCB: async (_deps) => "hi",
			},
		});

		const promise = createApp({
			modules: [modA, modB],
			bootstrapComponents: minBoot,
			contributionKinds: makeStubCollectors(),
		});

		await expect(promise).rejects.toBeInstanceOf(BootError);
		await expect(promise).rejects.toMatchObject({
			reason: "circular-dependency",
			stage: "planBoot",
		});
	});
});

describe("createApp — 4. stage 3 error: provides-factory-failed → stage: materializeComponents", () => {
	it("throws BootError with stage=materializeComponents when a provider factory throws", async () => {
		const failErr = new Error("provider boom");
		// Use eager: true to force the module into the activation closure so
		// the factory actually runs (same pattern as test 1).
		const mod = defineModule({
			name: "FailProviderMod",
			provides: {
				slotCA: async (_deps) => {
					throw failErr;
				},
			},
			lifecycle: {
				slotCA: { eager: true },
			},
		});

		const promise = createApp({
			modules: [mod],
			bootstrapComponents: minBoot,
			contributionKinds: makeStubCollectors(),
		});

		await expect(promise).rejects.toBeInstanceOf(BootError);

		try {
			await createApp({
				modules: [mod],
				bootstrapComponents: minBoot,
				contributionKinds: makeStubCollectors(),
			});
		} catch (err) {
			const bootErr = err as BootError;
			expect(bootErr.reason).toBe("provides-factory-failed");
			expect(bootErr.stage).toBe("materializeComponents");
			expect((bootErr.cause as Error)?.message).toBe("provider boom");
		}
	});
});

describe("createApp — 5. stage 4 error: contribute-factory-failed → stage: applyContributions", () => {
	it("throws BootError with stage=applyContributions when a contribution factory throws", async () => {
		// Module contributes a grant; the grant factory throws.
		// createApp uses built-in grants collector so no explicit override needed.
		const mod = defineModule({
			name: "FailContribMod",
			provides: {},
			contributes: {
				grants: {
					"urn:fail-grant": (_deps) => {
						throw new Error("contribution boom");
					},
				},
			},
		});

		const promise = createApp({
			modules: [mod],
			bootstrapComponents: minBoot,
			// No contributionKinds override — built-in grants collector will be used
			// and the failing factory will trigger contribute-factory-failed.
		});

		await expect(promise).rejects.toBeInstanceOf(BootError);
		await expect(promise).rejects.toMatchObject({
			reason: "contribute-factory-failed",
			stage: "applyContributions",
		});
	});
});

describe("createApp — 6. stage 6 error: route-order-cycle → stage: assembleApp", () => {
	it("throws BootError with stage=assembleApp on a route before/after cycle", async () => {
		// Two routes that reference each other in before/after, creating a cycle.
		const mod = defineModule({
			name: "RoutesCycleMod",
			provides: {},
			contributes: {
				routes: [
					{
						mountPath: "/route-a",
						handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
						id: "route-a",
						before: ["route-b"],
					},
					{
						mountPath: "/route-b",
						handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
						id: "route-b",
						before: ["route-a"],
					},
				],
			},
		});

		const promise = createApp({
			modules: [mod],
			bootstrapComponents: minBoot,
			// No contributionKinds override — built-in route collector will be used.
		});

		await expect(promise).rejects.toBeInstanceOf(BootError);
		await expect(promise).rejects.toMatchObject({
			reason: "route-order-cycle",
			stage: "assembleApp",
		});
	});
});
