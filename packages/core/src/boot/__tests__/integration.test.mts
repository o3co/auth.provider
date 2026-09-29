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
 * End-to-end integration tests for the boot planner pipeline (createApp):
 *   1. Happy boot: a multi-module manifest with grants and routes
 *      contributions.
 *   2. Failure diagnostic: oauthAuthorizationModule requires intMissingSlot,
 *      a test-only slot nothing provides; the BootError shape is pinned.
 *   3. Reverse-topological cleanup order on dispose.
 *   4. `grantHandlerResolver` lists what the grants registry holds.
 */

import { Router } from "express";
import { describe, expect, it } from "vitest";
import type { GrantHandler } from "../../grants/types.mjs";
import { createApp } from "../../index.mjs";
import { defineModule } from "../../modules/manifest/index.mjs";
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import type { BootstrapMap } from "../types.mjs";
import { BootError } from "../types.mjs";

// Typed GrantHandler stub for the grants contributions. `tag` goes into
// `access_token` so pipeline assertions can tell stubs apart; the handler is
// never invoked, so the rest of `TokenResponse` is `as never`.
const fakeGrantHandler = (tag = "stub"): GrantHandler => ({
	handle: async () => ({
		result: {
			status: 200,
			tokens: { access_token: tag } as never,
		},
	}),
});

// ---------------------------------------------------------------------------
// Test-only ComponentMap augmentation
// ---------------------------------------------------------------------------

declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		// keyStore, the repositories and auditSink are declared in their core
		// files (keys/KeyStore.mts, repositories/{Client,Code,User}Repository.mts,
		// audit/types.mts), userSessionStore in user-sessions/types.mts.
		// Redeclaring them here would conflict with the real types and fail
		// typecheck, so the stub providers return `as never` instead.
		//
		// Scenario 2: declared here and never provided, so requiring it triggers
		// missing-required-component without casting a slot name to `never`.
		readonly intMissingSlot: { readonly purpose: "scenario-2-trigger" };
		//
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

// Per ADR 2026-04-30-config-schema-strict-defaults-from-hocon, defaults live
// in HOCON and validateAndComposeConfig parses CoreConfigSchema, so the
// fixture supplies a minimal schema-valid baseline (it diverges from
// reference.conf on purpose; see makeValidCoreConfig).
const minBoot = {
	config: makeValidCoreConfig() as never,
	pathResolver: (s: string) => s,
} satisfies Record<string, unknown> as BootstrapMap;

// ---------------------------------------------------------------------------
// Scenario 1: Happy boot — multi-module manifest
// ---------------------------------------------------------------------------

describe("integration — Scenario 1: happy boot of a multi-module manifest", () => {
	it("produces an AppHandle with components, a real Express Router, and dispose", async () => {
		// Stub return values typed `as never`: these scenarios cover boot-planner
		// shape (closure, ordering, error catalogue), not the typed contracts of
		// each ComponentMap slot. Satisfying each real interface would add
		// vacuous method stubs without adding planner coverage.
		const stubKeyStore = { stub: "keyStore" } as never;
		const stubClientRepository = { stub: "clientRepository" } as never;
		const stubCodeRepository = { stub: "codeRepository" } as never;
		const stubUserRepository = { stub: "userRepository" } as never;
		const stubAuditSink = { stub: "auditSink" } as never;

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
					"urn:test:authorization_code": (_deps) => fakeGrantHandler("authorization_code"),
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

		// Module: provides auditSink, eager so it activates although no module
		// here requires it.
		const auditSinkEagerModule = defineModule({
			name: "audit-sink-eager",
			requires: ["config"],
			provides: {
				auditSink: (_deps) => stubAuditSink,
			},
			lifecycle: {
				auditSink: { eager: true },
			},
		});

		const handle = await createApp({
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

		// Bootstrap components are accessible. config is the parsed
		// (CoreConfigSchema-validated) result, not the raw bootstrap reference
		// (see validateAndComposeConfig). `port: 3000` comes from the
		// makeValidCoreConfig fixture: the schema carries no default.
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

		const handle = await createApp({
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
// Scenario 2: missing-required-component failure diagnostic
// ---------------------------------------------------------------------------

describe("integration — Scenario 2: spec §12 worked-example failure diagnostic", () => {
	it("throws BootError with missing-required-component for a slot that is never provided", async () => {
		// The path assertions below depend on these module names. Stubs are
		// typed `as never`, as in Scenario 1.
		const keyStoreModule = defineModule({
			name: "key-store",
			requires: ["config"],
			provides: {
				keyStore: (_deps) => ({ stub: "keyStore" }) as never,
			},
		});

		const repositoriesModule = defineModule({
			name: "repositories",
			provides: {
				clientRepository: (_deps) => ({ stub: "clientRepository" }) as never,
				codeRepository: (_deps) => ({ stub: "codeRepository" }) as never,
				userRepository: (_deps) => ({ stub: "userRepository" }) as never,
			},
		});

		// oauthAuthorizationModule requires "intMissingSlot", declared above and
		// never provided, which triggers the BootError.
		const oauthAuthorizationModule = defineModule({
			name: "oauth-authorization",
			requires: ["keyStore", "clientRepository", "codeRepository", "intMissingSlot"],
			contributes: {
				grants: {
					"urn:test:authorization_code": (_deps) => fakeGrantHandler("authorization_code"),
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
					// A federation, not a placeholder: the contribution type is the
					// contract, so `{}` does not compile. The scenario is about the
					// missing-slot diagnostic below.
					google: (_deps) => ({
						name: "google",
						scope: ["openid"],
						buildAuthorizationUrl: () => new URL("https://accounts.google.com/auth"),
						exchangeCode: async () => ({
							issuer: "https://accounts.google.com",
							sub: "123",
							expiresAt: null,
						}),
					}),
				},
			},
		});

		// auditModule's auditSink is also missing, but the planner surfaces only
		// the FIRST violation in input-array order, where oauthAuthorizationModule
		// comes before auditModule.
		const auditModule = defineModule({
			name: "audit",
			requires: ["auditSink"],
		});

		let caught: unknown;
		try {
			await createApp({
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

		// Top-level discriminants.
		expect(err.reason).toBe("missing-required-component");
		expect(err.stage).toBe("validateManifests");
		expect(err.details.reason).toBe("missing-required-component");

		if (err.details.reason === "missing-required-component") {
			expect(err.details.missingKey).toBe("intMissingSlot");
			// rootModule: the module that first hits the unsatisfied requires key;
			// since oauthAuthorizationModule has no provider chain leading back to
			// a requirer, it IS the root module.
			expect(err.details.rootModule).toBe("oauth-authorization");
			// path: single entry — the failing module with its missing key, no satisfiedBy.
			expect(err.details.path).toEqual([
				{ module: "oauth-authorization", requires: "intMissingSlot" },
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

		const handle = await createApp({
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

// ---------------------------------------------------------------------------
// Scenario 4: the grants collector lists what the registry holds
// ---------------------------------------------------------------------------

describe("integration — Scenario 4: grantHandlerResolver lists the registered grants", () => {
	it("in contribution order, an overridden grant in its place, after the registry is frozen", async () => {
		// `/oauth/token` dispatches through `get`, and `oauth` derives
		// `grant_types_supported` from `entries()`: the two must read one
		// registry, whatever a module overrides.
		const first = fakeGrantHandler("first");
		const second = fakeGrantHandler("second");
		const replacement = fakeGrantHandler("replacement");
		const grantsModule = defineModule({
			name: "grants",
			contributes: {
				grants: {
					"urn:test:first": () => first,
					"urn:test:second": () => second,
				},
			},
		});
		const overridingModule = defineModule({
			name: "overriding",
			overrides: {
				grants: { "urn:test:first": () => replacement },
			},
		});

		const handle = await createApp({
			modules: [grantsModule, overridingModule],
			bootstrapComponents: minBoot,
		});

		const resolver = handle.components.grantHandlerResolver;
		expect(resolver).toBeDefined();
		expect([...(resolver?.entries() ?? [])]).toEqual([
			["urn:test:first", replacement],
			["urn:test:second", second],
		]);
		expect(resolver?.get("urn:test:first")).toBe(replacement);

		await handle.dispose();
	});
});
