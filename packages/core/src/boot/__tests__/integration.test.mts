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
 * boot/__tests__/integration.test.mts — End-to-end integration tests for
 * the A2-β boot planner pipeline (createBootApp).
 *
 * Covers three end-to-end scenarios per spec §12 + §8.1:
 *   1. Happy boot — multi-module manifest with grants + routes contributions.
 *   2. Spec §12 worked-example failure diagnostic — oauthAuthorizationModule
 *      missing refreshTokenStore; BootError shape matches §12 exactly.
 *   3. Reverse-topological cleanup order on dispose (§8.1).
 *
 * Per A2-β §12 + §8.1 / Phase 4 Task 10.
 */

import { Router } from "express";
import { describe, expect, it } from "vitest";
import { createBootApp } from "../../index.mjs";
import { defineModule } from "../../modules/manifest/index.mjs";
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import type { BootstrapMap } from "../types.mjs";
import { BootError } from "../types.mjs";

// ---------------------------------------------------------------------------
// Test-only ComponentMap augmentation
// Declares every slot used across all three scenarios in this file.
// ---------------------------------------------------------------------------

declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		// Scenario 1 + 2 — infrastructure slots
		readonly keyStore: { readonly stub: "keyStore" };
		readonly clientRepository: { readonly stub: "clientRepository" };
		readonly codeRepository: { readonly stub: "codeRepository" };
		readonly userRepository: { readonly stub: "userRepository" };
		readonly auditSink: { readonly stub: "auditSink" };
		// userSessionStore is canonically declared as UserSessionStore? in
		// `user-sessions/types.mts` ComponentMap merge — do not redeclare here
		// (would conflict with the canonical type). The Scenario 2 provider
		// returns a UserSessionStore-compatible stub directly at the call site.
		// NOTE: refreshTokenStore is intentionally NOT declared here — the
		// X1 cross-spec constraint (legacy-slots-absent.test.mts) prohibits
		// it from appearing in ComponentMap. Scenario 2 injects the key via a
		// runtime cast on the requires array so the planner sees it at runtime
		// without adding it to the type-level ComponentMap.
		// Scenario 3 — cleanup-order slots (prefixed "int" to avoid clashing
		// with materialize-components.test.mts which declares slotA/B/C as number)
		readonly intSlotA: { readonly label: "A" };
		readonly intSlotB: { readonly label: "B" };
		readonly intSlotC: { readonly label: "C" };
	}
}

// ---------------------------------------------------------------------------
// Shared bootstrap stub
// ---------------------------------------------------------------------------

// Per ADR 2026-04-30: schema is a pure type contract, defaults live in
// hocon. validateAndComposeConfig calls CoreConfigSchema.parse, so the
// fixture supplies a minimal schema-valid baseline (intentionally
// diverges from application.conf — see makeValidCoreConfig docstring).
const minBoot = {
	config: makeValidCoreConfig() as never,
	pathResolver: (s: string) => s,
} satisfies Record<string, unknown> as BootstrapMap;

// ---------------------------------------------------------------------------
// Scenario 1: Happy boot — multi-module manifest
// ---------------------------------------------------------------------------

describe("integration — Scenario 1: happy boot of a multi-module manifest", () => {
	it("produces an AppHandle with components, a real Express Router, and dispose", async () => {
		const stubKeyStore = { stub: "keyStore" } as const;
		const stubClientRepository = { stub: "clientRepository" } as const;
		const stubCodeRepository = { stub: "codeRepository" } as const;
		const stubUserRepository = { stub: "userRepository" } as const;
		const stubAuditSink = { stub: "auditSink" } as const;

		// Module: provides keyStore (requires config from bootstrap).
		const keyStoreModule = defineModule({
			name: "key-store",
			requires: ["config"],
			provides: {
				keyStore: (_deps) => stubKeyStore,
			},
		});

		// Module: provides three repository slots (no requires beyond bootstrap).
		const repositoriesModule = defineModule({
			name: "repositories",
			provides: {
				clientRepository: (_deps) => stubClientRepository,
				codeRepository: (_deps) => stubCodeRepository,
				userRepository: (_deps) => stubUserRepository,
			},
		});

		// Handler stub used for the route contribution.
		const routeHandler = ((_req: unknown, _res: unknown, next: () => void) => next()) as never;

		// Module: requires several slots, contributes a grant + a route.
		// Activation is guaranteed because it contributes, which seeds the closure.
		// Requiring all three repository slots pulls repositoriesModule into
		// the activation closure (userRepository is not needed by any other module
		// so we must require it here to ensure it materialises).
		const oauthAuthorizationModule = defineModule({
			name: "oauth-authorization",
			requires: ["keyStore", "clientRepository", "codeRepository", "userRepository"],
			contributes: {
				grants: {
					"urn:test:authorization_code": (_deps) => ({ grantType: "authorization_code" }),
				},
				routes: [
					{
						mountPath: "/oauth/authorize",
						id: "oauth-authorize",
						handler: routeHandler,
					},
				],
			},
		});

		// Module: requires auditSink provided by auditSinkModule; provides nothing.
		// Activation: auditSink is required, which is satisfied by auditSinkModule,
		// pulling auditModule into the closure; but auditModule itself has no provides.
		// To force activation of auditSinkModule, declare auditSink as eager.
		const auditSinkEagerModule = defineModule({
			name: "audit-sink-eager",
			requires: ["config"],
			provides: {
				auditSink: (_deps) => stubAuditSink,
			},
			lifecycle: {
				// Note: overriding auditSink with a dedicated eager module is simpler
				// than having a module that requires it with no provides. Instead,
				// just use the eager lifecycle on the providing module (auditSinkModule
				// is superseded here by combining in one module with eager: true).
				auditSink: { eager: true },
			},
		});

		// In this scenario we use auditSinkEagerModule instead of the two-module
		// split above so auditSink is activated unconditionally.
		// oauthAuthorizationModule does NOT require auditSink here — the audit
		// concern is handled separately to keep the scenario realistic.

		const handle = await createBootApp({
			modules: [keyStoreModule, repositoriesModule, auditSinkEagerModule, oauthAuthorizationModule],
			bootstrapComponents: minBoot,
		});

		// AppHandle properties
		expect(handle).toBeDefined();
		expect(Object.isFrozen(handle)).toBe(true);

		// Component slots are materialised.
		expect(handle.components.keyStore).toBe(stubKeyStore);
		expect(handle.components.clientRepository).toBe(stubClientRepository);
		expect(handle.components.codeRepository).toBe(stubCodeRepository);
		expect(handle.components.userRepository).toBe(stubUserRepository);
		expect(handle.components.auditSink).toBe(stubAuditSink);

		// Bootstrap components are accessible.
		// config is now the parsed (CoreConfigSchema-validated) result —
		// not the raw bootstrap reference. See validateAndComposeConfig
		// substitution per Codex P2-A hardening. The `port: 3000` value
		// comes from the makeValidCoreConfig fixture; per ADR 2026-04-30
		// the schema layer no longer carries a default for it.
		expect((handle.components.config as { http: { port: number } }).http.port).toBe(3000);
		expect(handle.components.pathResolver).toBe(minBoot.pathResolver);

		// Router is a real Express Router instance with a callable .use method.
		expect(handle.router).toBeDefined();
		expect(typeof handle.router.use).toBe("function");
		// Verify it is an Express Router (stack exists after mounting a route).
		const tempRouter = Router();
		tempRouter.use("/test", handle.router);
		// Calling .use on the real express Router does not throw.

		// dispose resolves without error.
		await expect(handle.dispose()).resolves.toBeUndefined();
	});

	it("router.use is callable on the AppHandle router after boot", async () => {
		const mod = defineModule({
			name: "route-mod",
			contributes: {
				routes: [
					{
						mountPath: "/health",
						id: "health",
						handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
					},
				],
			},
		});

		const handle = await createBootApp({
			modules: [mod],
			bootstrapComponents: minBoot,
		});

		// Verify router.use does not throw when called on the AppHandle router.
		const outer = Router();
		expect(() => outer.use("/api", handle.router)).not.toThrow();
		await handle.dispose();
	});
});

// ---------------------------------------------------------------------------
// Scenario 2: Spec §12 worked-example failure diagnostic
// ---------------------------------------------------------------------------

describe("integration — Scenario 2: spec §12 worked-example failure diagnostic", () => {
	it("throws BootError with missing-required-component for refreshTokenStore", async () => {
		// Replicate the §12 module list. Module names match the spec exactly so
		// the path assertions below are stable.

		const keyStoreModule = defineModule({
			name: "key-store",
			requires: ["config"],
			provides: {
				keyStore: (_deps) => ({ stub: "keyStore" as const }),
			},
		});

		const repositoriesModule = defineModule({
			name: "repositories",
			provides: {
				clientRepository: (_deps) => ({ stub: "clientRepository" as const }),
				codeRepository: (_deps) => ({ stub: "codeRepository" as const }),
				userRepository: (_deps) => ({ stub: "userRepository" as const }),
			},
		});

		// oauthAuthorizationModule requires refreshTokenStore — intentionally
		// not provided by any module in this test, which triggers the BootError.
		//
		// "refreshTokenStore" is cast as `never` to bypass the ComponentMap type-level
		// check: the X1 cross-spec constraint prohibits the legacy slot name from
		// being declared in ComponentMap. At runtime the planner only reads the
		// string value, so the cast is safe for this diagnostic test.
		const oauthAuthorizationModule = defineModule({
			name: "oauth-authorization",
			requires: ["keyStore", "clientRepository", "codeRepository", "refreshTokenStore" as never],
			contributes: {
				grants: {
					"urn:test:authorization_code": (_deps) => ({}),
				},
			},
		});

		const sessionModule = defineModule({
			name: "session",
			requires: ["config"],
			provides: {
				userSessionStore: (_deps) => ({
					kind: "memory" as const,
					create: async () => {},
					get: async () => null,
					delete: async () => {},
				}),
			},
		});

		const oauthModule = defineModule({
			name: "oauth",
			requires: ["keyStore"],
			provides: {},
		});

		// googleFederationModule contributes a federation entry.
		const googleFederationModule = defineModule({
			name: "google-federation",
			contributes: {
				federations: {
					google: (_deps) => ({}),
				},
			},
		});

		// auditModule requires auditSink — also missing, but the planner surfaces
		// only the FIRST violation in input-array order (oauth-authorization's
		// refreshTokenStore comes first per module iteration, which iterates
		// oauthAuthorizationModule before auditModule in the input array).
		const auditModule = defineModule({
			name: "audit",
			requires: ["auditSink"],
		});

		let caught: unknown;
		try {
			await createBootApp({
				modules: [
					keyStoreModule,
					repositoriesModule,
					oauthAuthorizationModule,
					sessionModule,
					oauthModule,
					googleFederationModule,
					auditModule,
				],
				bootstrapComponents: minBoot,
			});
		} catch (err) {
			caught = err;
		}

		expect(caught).toBeInstanceOf(BootError);
		const err = caught as BootError;

		// Top-level discriminants — match §12 exactly.
		expect(err.reason).toBe("missing-required-component");
		expect(err.stage).toBe("validateManifests");
		expect(err.details.reason).toBe("missing-required-component");

		if (err.details.reason === "missing-required-component") {
			expect(err.details.missingKey).toBe("refreshTokenStore");
			// rootModule: the module that first hits the unsatisfied requires key;
			// since oauthAuthorizationModule has no provider chain leading back to
			// a requirer, it IS the root module.
			expect(err.details.rootModule).toBe("oauth-authorization");
			// path: single entry — the failing module with its missing key, no satisfiedBy.
			expect(err.details.path).toEqual([
				{ module: "oauth-authorization", requires: "refreshTokenStore" },
			]);
		}
	});
});

// ---------------------------------------------------------------------------
// Scenario 3: Cleanup runs in reverse-topological order on dispose
// ---------------------------------------------------------------------------

describe("integration — Scenario 3: cleanup runs in reverse-topological order on dispose", () => {
	it("invokes cleanup callbacks in reverse-topological order C → B → A", async () => {
		// Dependency chain: C requires slotB (provided by B), B requires slotA
		// (provided by A). Topological init order: A → B → C.
		// Expected cleanup order (reverse): C → B → A.
		const order: string[] = [];

		// Module A: provides intSlotA with a cleanup recording "A".
		// eager: true to ensure activation without a downstream requirer in
		// the root-discovery pass.
		const moduleA = defineModule({
			name: "module-a",
			provides: {
				intSlotA: (_deps) => ({ label: "A" as const }),
			},
			lifecycle: {
				intSlotA: {
					eager: true,
					cleanup: (_value) => {
						order.push("A");
					},
				},
			},
		});

		// Module B: requires intSlotA, provides intSlotB with a cleanup recording "B".
		const moduleB = defineModule({
			name: "module-b",
			requires: ["intSlotA"],
			provides: {
				intSlotB: (_deps) => ({ label: "B" as const }),
			},
			lifecycle: {
				intSlotB: {
					eager: true,
					cleanup: (_value) => {
						order.push("B");
					},
				},
			},
		});

		// Module C: requires intSlotB, provides intSlotC with a cleanup recording "C".
		const moduleC = defineModule({
			name: "module-c",
			requires: ["intSlotB"],
			provides: {
				intSlotC: (_deps) => ({ label: "C" as const }),
			},
			lifecycle: {
				intSlotC: {
					eager: true,
					cleanup: (_value) => {
						order.push("C");
					},
				},
			},
		});

		const handle = await createBootApp({
			modules: [moduleA, moduleB, moduleC],
			bootstrapComponents: minBoot,
		});

		// All three slots should be materialised.
		expect(handle.components.intSlotA).toEqual({ label: "A" });
		expect(handle.components.intSlotB).toEqual({ label: "B" });
		expect(handle.components.intSlotC).toEqual({ label: "C" });

		// Cleanup order should be empty before dispose.
		expect(order).toEqual([]);

		await handle.dispose();

		// After dispose: reverse-topological order — C first, then B, then A.
		expect(order).toEqual(["C", "B", "A"]);
	});
});
