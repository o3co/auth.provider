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
import { z } from "zod";
import { defineModule } from "../../modules/manifest/index.mjs";
import { BootError } from "../types.mjs";
import { validateManifests } from "../validate-manifests.mjs";

declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly cfgA: { readonly v: number };
		readonly cfgB: string;
		readonly cfgC: number;
	}
}

// Cast to BootstrapMap so tests can pass a minimal stub without satisfying
// the full AppConfig shape (which would require all nested required fields).
import type { BootstrapMap } from "../types.mjs";

const minBootstrap = {
	config: {} as never,
	pathResolver: (s: string) => s,
} satisfies Record<string, unknown> as BootstrapMap;

// ---------------------------------------------------------------------------
// In-test stub helpers — satisfy collector contracts without importing real
// collector implementations (which do not exist yet in Phase 4 Task 3).
// ---------------------------------------------------------------------------

function stubHandler(): never {
	return ((_req: unknown, _res: unknown, next: () => void) => next()) as never;
}

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

function makeStubRouteCollector() {
	const arr: unknown[] = [];
	let frozen = false;
	return {
		kind: "list-routes" as const,
		append: (v: unknown) => {
			if (frozen) throw new Error("collector is frozen");
			arr.push(v);
		},
		freeze: () => {
			frozen = true;
		},
		values: () => arr.values() as IterableIterator<unknown>,
	};
}

// ---------------------------------------------------------------------------
// Step 1 — duplicate-module-name
// ---------------------------------------------------------------------------

describe("validateManifests — step 1: duplicate-module-name", () => {
	it("throws duplicate-module-name on two modules sharing a name", () => {
		const m1 = defineModule({ name: "dup", provides: { cfgA: () => ({ v: 1 }) } });
		const m2 = defineModule({ name: "dup", provides: { cfgB: () => "x" } });
		expect(() =>
			validateManifests({
				modules: [m1, m2],
				bootstrapComponents: minBootstrap,
				contributionKinds: {},
			}),
		).toThrowError(BootError);
		try {
			validateManifests({
				modules: [m1, m2],
				bootstrapComponents: minBootstrap,
				contributionKinds: {},
			});
		} catch (e) {
			const err = e as BootError;
			expect(err.reason).toBe("duplicate-module-name");
			expect(err.stage).toBe("validateManifests");
			if (err.details.reason === "duplicate-module-name") {
				expect(err.details.name).toBe("dup");
				expect(err.details.modules).toEqual(["dup", "dup"]);
			}
		}
	});
});

// ---------------------------------------------------------------------------
// Step 2 — duplicate-provides
// ---------------------------------------------------------------------------

describe("validateManifests — step 2: duplicate-provides", () => {
	it("throws duplicate-provides when two modules provide the same key", () => {
		const m1 = defineModule({ name: "p1", provides: { cfgA: () => ({ v: 1 }) } });
		const m2 = defineModule({ name: "p2", provides: { cfgA: () => ({ v: 2 }) } });
		try {
			validateManifests({ modules: [m1, m2], bootstrapComponents: minBootstrap });
		} catch (e) {
			const err = e as BootError;
			expect(err.reason).toBe("duplicate-provides");
			if (err.details.reason === "duplicate-provides") {
				expect(err.details.componentKey).toBe("cfgA");
				expect(err.details.modules).toEqual(["p1", "p2"]);
			}
			return;
		}
		expect.fail("should have thrown");
	});
});

// ---------------------------------------------------------------------------
// Step 3 — bootstrap-component-collision + synthetic-key-collision
// ---------------------------------------------------------------------------

describe("validateManifests — step 3: bootstrap + synthetic collisions", () => {
	it("step 3a: throws bootstrap-component-collision when a module provides a bootstrap key", () => {
		const m = defineModule({ name: "m", provides: { cfgA: () => ({ v: 1 }) } });
		try {
			validateManifests({
				modules: [m],
				bootstrapComponents: { ...minBootstrap, cfgA: { v: 99 } },
			});
		} catch (e) {
			const err = e as BootError;
			expect(err.reason).toBe("bootstrap-component-collision");
			if (err.details.reason === "bootstrap-component-collision") {
				expect(err.details.source).toBe("module-provides");
				expect(err.details.componentKey).toBe("cfgA");
				if (err.details.source === "module-provides") {
					expect(err.details.module).toBe("m");
				}
			}
			return;
		}
		expect.fail("should have thrown");
	});

	it("step 3b: throws bootstrap-component-collision when overrideComponents shares a bootstrap key", () => {
		try {
			validateManifests({
				modules: [],
				bootstrapComponents: { ...minBootstrap, cfgA: { v: 1 } },
				overrideComponents: { cfgA: { v: 2 } },
			});
		} catch (e) {
			const err = e as BootError;
			expect(err.reason).toBe("bootstrap-component-collision");
			if (
				err.details.reason === "bootstrap-component-collision" &&
				err.details.source === "overrideComponents"
			) {
				expect(err.details.componentKey).toBe("cfgA");
			}
			return;
		}
		expect.fail("should have thrown");
	});

	it("step 3c: throws synthetic-key-collision when a module provides federationProviders", () => {
		const m = defineModule({
			name: "bad",
			// federationProviders is a synthetic key — only the planner may produce it.
			provides: { federationProviders: () => new Map() } as unknown as never,
		});
		try {
			validateManifests({ modules: [m as never], bootstrapComponents: minBootstrap });
		} catch (e) {
			const err = e as BootError;
			expect(err.reason).toBe("synthetic-key-collision");
			if (
				err.details.reason === "synthetic-key-collision" &&
				err.details.source === "module-provides"
			) {
				expect(err.details.componentKey).toBe("federationProviders");
				expect(err.details.module).toBe("bad");
			}
			return;
		}
		expect.fail("should have thrown");
	});

	it("step 3c: throws synthetic-key-collision when bootstrapComponents contains grantHandlerResolver", () => {
		try {
			validateManifests({
				modules: [],
				bootstrapComponents: {
					...minBootstrap,
					// grantHandlerResolver is a synthetic key — host environment cannot pre-seed it.
					grantHandlerResolver: { get: () => undefined, entries: () => [][Symbol.iterator]() },
				} as never,
			});
		} catch (e) {
			const err = e as BootError;
			expect(err.reason).toBe("synthetic-key-collision");
			if (
				err.details.reason === "synthetic-key-collision" &&
				err.details.source === "bootstrapComponents"
			) {
				expect(err.details.componentKey).toBe("grantHandlerResolver");
			}
			return;
		}
		expect.fail("should have thrown");
	});

	it("step 3c: throws synthetic-key-collision when overrideComponents contains tokenExchangeValidatorResolver", () => {
		try {
			validateManifests({
				modules: [],
				bootstrapComponents: minBootstrap,
				overrideComponents: {
					// tokenExchangeValidatorResolver is a synthetic key — overrideComponents cannot supply it.
					tokenExchangeValidatorResolver: {
						get: () => undefined,
						entries: () => [][Symbol.iterator](),
					},
				} as never,
			});
		} catch (e) {
			const err = e as BootError;
			expect(err.reason).toBe("synthetic-key-collision");
			if (
				err.details.reason === "synthetic-key-collision" &&
				err.details.source === "overrideComponents"
			) {
				expect(err.details.componentKey).toBe("tokenExchangeValidatorResolver");
			}
			return;
		}
		expect.fail("should have thrown");
	});
});

// ---------------------------------------------------------------------------
// Step 4 — missing-required-component (path algorithm)
// ---------------------------------------------------------------------------

describe("validateManifests — step 4: missing-required-component", () => {
	it("single-module case: path has one entry with no satisfiedBy", () => {
		const m = defineModule({
			name: "needsThing",
			requires: ["cfgA"],
		});
		try {
			validateManifests({ modules: [m], bootstrapComponents: minBootstrap });
		} catch (e) {
			const err = e as BootError;
			expect(err.reason).toBe("missing-required-component");
			if (err.details.reason === "missing-required-component") {
				expect(err.details.missingKey).toBe("cfgA");
				expect(err.details.rootModule).toBe("needsThing");
				expect(err.details.path).toEqual([{ module: "needsThing", requires: "cfgA" }]);
				// Terminal link: no satisfiedBy field
				expect(err.details.path[0]).not.toHaveProperty("satisfiedBy");
			}
			return;
		}
		expect.fail("should have thrown");
	});

	it("multi-module chain: path follows requirer chain from rootModule to failing module", () => {
		// A requires cfgB (satisfied by B); B requires cfgC (not satisfied).
		const a = defineModule({
			name: "A",
			requires: ["cfgB"],
			provides: { cfgA: () => ({ v: 1 }) },
		});
		const b = defineModule({
			name: "B",
			requires: ["cfgC"],
			provides: { cfgB: () => "x" },
		});
		try {
			validateManifests({ modules: [a, b], bootstrapComponents: minBootstrap });
		} catch (e) {
			const err = e as BootError;
			expect(err.reason).toBe("missing-required-component");
			if (err.details.reason === "missing-required-component") {
				expect(err.details.missingKey).toBe("cfgC");
				expect(err.details.rootModule).toBe("A");
				expect(err.details.path).toEqual([
					{ module: "A", requires: "cfgB", satisfiedBy: "B" },
					{ module: "B", requires: "cfgC" },
				]);
			}
			return;
		}
		expect.fail("should have thrown");
	});
});

// ---------------------------------------------------------------------------
// Step 5 — unknown-contribution-kind
// ---------------------------------------------------------------------------

describe("validateManifests — step 5: unknown-contribution-kind", () => {
	it("throws unknown-contribution-kind when a module contributes a kind with no collector", () => {
		const m = defineModule({
			name: "uses-unknown",
			contributes: {
				madeUpKind: { foo: () => ({}) },
			} as never,
		});
		try {
			validateManifests({
				modules: [m],
				bootstrapComponents: minBootstrap,
				contributionKinds: {},
			});
		} catch (e) {
			const err = e as BootError;
			expect(err.reason).toBe("unknown-contribution-kind");
			if (err.details.reason === "unknown-contribution-kind") {
				expect(err.details.kind).toBe("madeUpKind");
				expect(err.details.contributedBy).toEqual(["uses-unknown"]);
			}
			return;
		}
		expect.fail("should have thrown");
	});
});

// ---------------------------------------------------------------------------
// Step 6 — duplicate-contribute (name-keyed)
// ---------------------------------------------------------------------------

describe("validateManifests — step 6: duplicate-contribute (name-keyed)", () => {
	it("throws duplicate-contribute on (kind, name) collision across modules", () => {
		const m1 = defineModule({
			name: "g1",
			contributes: { grants: { authcode: () => ({}) as never } },
		});
		const m2 = defineModule({
			name: "g2",
			contributes: { grants: { authcode: () => ({}) as never } },
		});
		try {
			validateManifests({
				modules: [m1, m2],
				bootstrapComponents: minBootstrap,
				contributionKinds: { grants: makeStubNameCollector() as never },
			});
		} catch (e) {
			const err = e as BootError;
			expect(err.reason).toBe("duplicate-contribute");
			if (err.details.reason === "duplicate-contribute") {
				expect(err.details.kind).toBe("grants");
				expect(err.details.identity).toBe("authcode");
				expect(err.details.identityKind).toBe("name");
				expect(err.details.modules).toEqual(["g1", "g2"]);
			}
			return;
		}
		expect.fail("should have thrown");
	});
});

// ---------------------------------------------------------------------------
// Step 7 — RouteContribution collision + advertisement path validation
// ---------------------------------------------------------------------------

describe("validateManifests — step 7: route collisions", () => {
	it("step 7a: routes — duplicate id throws duplicate-contribute (identityKind=id)", () => {
		const r1 = defineModule({
			name: "r1",
			contributes: {
				routes: [{ mountPath: "/a", handler: stubHandler(), id: "X" }],
			},
		});
		const r2 = defineModule({
			name: "r2",
			contributes: {
				routes: [{ mountPath: "/b", handler: stubHandler(), id: "X" }],
			},
		});
		try {
			validateManifests({
				modules: [r1, r2],
				bootstrapComponents: minBootstrap,
				contributionKinds: { routes: makeStubRouteCollector() as never },
			});
		} catch (e) {
			const err = e as BootError;
			expect(err.reason).toBe("duplicate-contribute");
			if (err.details.reason === "duplicate-contribute") {
				expect(err.details.identityKind).toBe("id");
				expect(err.details.identity).toBe("X");
			}
			return;
		}
		expect.fail("should have thrown");
	});

	it("step 7b: routes — same mountPath without id throws duplicate-contribute (identityKind=mountPath)", () => {
		const r1 = defineModule({
			name: "r1",
			contributes: { routes: [{ mountPath: "/x", handler: stubHandler() }] },
		});
		const r2 = defineModule({
			name: "r2",
			contributes: { routes: [{ mountPath: "/x", handler: stubHandler() }] },
		});
		try {
			validateManifests({
				modules: [r1, r2],
				bootstrapComponents: minBootstrap,
				contributionKinds: { routes: makeStubRouteCollector() as never },
			});
		} catch (e) {
			const err = e as BootError;
			expect(err.reason).toBe("duplicate-contribute");
			if (err.details.reason === "duplicate-contribute") {
				expect(err.details.identityKind).toBe("mountPath");
				expect(err.details.identity).toBe("/x");
			}
			return;
		}
		expect.fail("should have thrown");
	});

	it("step 7c: routes — effective (method, mountPath+adv.path) collision throws (identityKind=effective-method-path, identity='GET /api/users')", () => {
		const r1 = defineModule({
			name: "r1",
			contributes: {
				routes: [
					{
						mountPath: "/api",
						handler: stubHandler(),
						id: "alpha",
						routes: [{ method: "GET", path: "/users" }],
					},
				],
			},
		});
		const r2 = defineModule({
			name: "r2",
			contributes: {
				routes: [
					{
						mountPath: "/api",
						handler: stubHandler(),
						id: "beta",
						routes: [{ method: "GET", path: "/users" }],
					},
				],
			},
		});
		try {
			validateManifests({
				modules: [r1, r2],
				bootstrapComponents: minBootstrap,
				contributionKinds: { routes: makeStubRouteCollector() as never },
			});
		} catch (e) {
			const err = e as BootError;
			expect(err.reason).toBe("duplicate-contribute");
			if (err.details.reason === "duplicate-contribute") {
				expect(err.details.identityKind).toBe("effective-method-path");
				expect(err.details.identity).toBe("GET /api/users");
			}
			return;
		}
		expect.fail("should have thrown");
	});

	it("step 7d: routes — RouteAdvertisement.path missing leading slash throws invalid-route-advertisement-path", () => {
		const r = defineModule({
			name: "r",
			contributes: {
				routes: [
					{
						mountPath: "/api",
						handler: stubHandler(),
						id: "a",
						routes: [{ method: "GET", path: "users" }],
					},
				],
			},
		});
		try {
			validateManifests({
				modules: [r],
				bootstrapComponents: minBootstrap,
				contributionKinds: { routes: makeStubRouteCollector() as never },
			});
		} catch (e) {
			const err = e as BootError;
			expect(err.reason).toBe("invalid-route-advertisement-path");
			if (err.details.reason === "invalid-route-advertisement-path") {
				expect(err.details.module).toBe("r");
				expect(err.details.mountPath).toBe("/api");
				expect(err.details.path).toBe("users");
				expect(err.details.identityKind).toBe("missing-leading-slash");
			}
			return;
		}
		expect.fail("should have thrown");
	});
});

// ---------------------------------------------------------------------------
// Step 8 — override-target-missing
// ---------------------------------------------------------------------------

describe("validateManifests — step 8: override-target-missing", () => {
	it("throws override-target-missing when overrides[kind][name] has no contributing module", () => {
		const m = defineModule({
			name: "ov",
			overrides: { grants: { absent: () => ({}) as never } },
		});
		try {
			validateManifests({
				modules: [m],
				bootstrapComponents: minBootstrap,
				contributionKinds: { grants: makeStubNameCollector() as never },
			});
		} catch (e) {
			const err = e as BootError;
			expect(err.reason).toBe("override-target-missing");
			if (err.details.reason === "override-target-missing") {
				expect(err.details.kind).toBe("grants");
				expect(err.details.name).toBe("absent");
				expect(err.details.overridingModule).toBe("ov");
			}
			return;
		}
		expect.fail("should have thrown");
	});
});

// ---------------------------------------------------------------------------
// Step 9 — duplicate-override
// ---------------------------------------------------------------------------

describe("validateManifests — step 9: duplicate-override", () => {
	it("throws duplicate-override on two modules overriding the same (kind, name)", () => {
		const base = defineModule({
			name: "base",
			contributes: { grants: { x: () => ({}) as never } },
		});
		const o1 = defineModule({
			name: "o1",
			overrides: { grants: { x: () => ({}) as never } },
		});
		const o2 = defineModule({
			name: "o2",
			overrides: { grants: { x: () => ({}) as never } },
		});
		try {
			validateManifests({
				modules: [base, o1, o2],
				bootstrapComponents: minBootstrap,
				contributionKinds: { grants: makeStubNameCollector() as never },
			});
		} catch (e) {
			const err = e as BootError;
			expect(err.reason).toBe("duplicate-override");
			if (err.details.reason === "duplicate-override") {
				expect(err.details.kind).toBe("grants");
				expect(err.details.name).toBe("x");
				expect(err.details.modules).toEqual(["o1", "o2"]);
			}
			return;
		}
		expect.fail("should have thrown");
	});
});

// ---------------------------------------------------------------------------
// Step 10 — contribute-and-override-same-key
// ---------------------------------------------------------------------------

describe("validateManifests — step 10: contribute-and-override-same-key", () => {
	it("throws contribute-and-override-same-key when one module declares both", () => {
		const base = defineModule({
			name: "base",
			contributes: { grants: { x: () => ({}) as never } },
		});
		const m = defineModule({
			name: "self",
			contributes: { grants: { y: () => ({}) as never } },
			overrides: { grants: { y: () => ({}) as never } },
		});
		try {
			validateManifests({
				modules: [base, m],
				bootstrapComponents: minBootstrap,
				contributionKinds: { grants: makeStubNameCollector() as never },
			});
		} catch (e) {
			const err = e as BootError;
			expect(err.reason).toBe("contribute-and-override-same-key");
			if (err.details.reason === "contribute-and-override-same-key") {
				expect(err.details.module).toBe("self");
				expect(err.details.kind).toBe("grants");
				expect(err.details.name).toBe("y");
			}
			return;
		}
		expect.fail("should have thrown");
	});
});

// ---------------------------------------------------------------------------
// Step 11 — list-shaped-override-not-allowed
// ---------------------------------------------------------------------------

describe("validateManifests — step 11: list-shaped-override-not-allowed", () => {
	it("throws list-shaped-override-not-allowed for routes override", () => {
		const m = defineModule({
			name: "bad-override",
			overrides: { routes: [{ mountPath: "/x", handler: stubHandler() }] } as never,
		});
		try {
			validateManifests({
				modules: [m],
				bootstrapComponents: minBootstrap,
				contributionKinds: { routes: makeStubRouteCollector() as never },
			});
		} catch (e) {
			const err = e as BootError;
			expect(err.reason).toBe("list-shaped-override-not-allowed");
			if (err.details.reason === "list-shaped-override-not-allowed") {
				expect(err.details.kind).toBe("routes");
				expect(err.details.module).toBe("bad-override");
			}
			return;
		}
		expect.fail("should have thrown");
	});
});

// ---------------------------------------------------------------------------
// Step 12 — lifecycle-without-provides
// ---------------------------------------------------------------------------

describe("validateManifests — step 12: lifecycle-without-provides", () => {
	it("throws lifecycle-without-provides for K not in same module's provides", () => {
		const m = defineModule({
			name: "lc",
			provides: { cfgA: () => ({ v: 1 }) },
			lifecycle: { cfgB: { eager: true } } as never,
		});
		try {
			validateManifests({ modules: [m], bootstrapComponents: minBootstrap });
		} catch (e) {
			const err = e as BootError;
			expect(err.reason).toBe("lifecycle-without-provides");
			if (err.details.reason === "lifecycle-without-provides") {
				expect(err.details.componentKey).toBe("cfgB");
				expect(err.details.module).toBe("lc");
			}
			return;
		}
		expect.fail("should have thrown");
	});
});

// ---------------------------------------------------------------------------
// Step 13 — config-validation-failed
// ---------------------------------------------------------------------------

describe("validateManifests — step 13: config-validation-failed", () => {
	it("composes configSchemas and throws config-validation-failed on parse error", () => {
		const m = defineModule({
			name: "cfg-mod",
			configSchema: z.object({ port: z.number() }),
		});
		try {
			validateManifests({
				modules: [m],
				bootstrapComponents: {
					config: { port: "not-a-number" } as never,
					pathResolver: minBootstrap.pathResolver,
				},
			});
		} catch (e) {
			const err = e as BootError;
			expect(err.reason).toBe("config-validation-failed");
			if (err.details.reason === "config-validation-failed") {
				expect(err.details.issues.length).toBeGreaterThan(0);
				expect(err.details.modules.some((mod) => mod.module === "cfg-mod")).toBe(true);
			}
			return;
		}
		expect.fail("should have thrown");
	});
});

// ---------------------------------------------------------------------------
// Step 14 — route-order-target-missing
// ---------------------------------------------------------------------------

describe("validateManifests — step 14: route-order-target-missing", () => {
	it("throws route-order-target-missing for unknown referenced id in before", () => {
		const r = defineModule({
			name: "r",
			contributes: {
				routes: [
					{
						mountPath: "/a",
						handler: stubHandler(),
						id: "self",
						before: ["does-not-exist"],
					},
				],
			},
		});
		try {
			validateManifests({
				modules: [r],
				bootstrapComponents: minBootstrap,
				contributionKinds: { routes: makeStubRouteCollector() as never },
			});
		} catch (e) {
			const err = e as BootError;
			expect(err.reason).toBe("route-order-target-missing");
			if (err.details.reason === "route-order-target-missing") {
				expect(err.details.id).toBe("does-not-exist");
				expect(err.details.referencedBy).toBe("self");
				expect(err.details.direction).toBe("before");
			}
			return;
		}
		expect.fail("should have thrown");
	});
});

// ---------------------------------------------------------------------------
// Step 13 — parsed config carried forward (MUST-FIX 1 regression test)
// ---------------------------------------------------------------------------

describe("validateManifests — step 13: parsed config carried forward in bootstrapComponents", () => {
	it("substitutes the parsed config (with Zod defaults applied) into bootstrapComponents", () => {
		// Use an independent namespace ("myModule") so the module schema adds a
		// new optional key with a default to the composed schema. The key is
		// absent from the input config; Zod applies the default during parse.
		// The returned bootstrapComponents.config must carry the parsed value
		// (with the default applied) so downstream stages see it.
		const defaultTimeout = 42;
		const m = defineModule({
			name: "cfg",
			configSchema: z.object({
				myModule: z
					.object({
						timeout: z.number().default(defaultTimeout),
					})
					.optional()
					.default({ timeout: defaultTimeout }),
			}),
		});
		// Pass a valid CoreConfigSchema-compatible config but omit "myModule".
		const result = validateManifests({
			modules: [m],
			bootstrapComponents: {
				config: {
					http: { port: 3000, trustProxy: false },
					oauth: {
						jwt: {},
						accessToken: { expiresIn: 3600 },
						refreshToken: { expiresIn: 86400 },
						grants: {},
					},
				} as never,
				pathResolver: (s: string) => s,
			},
		});
		const cfg = result.bootstrapComponents.config as {
			myModule?: { timeout?: number };
		};
		expect(cfg?.myModule?.timeout).toBe(defaultTimeout);
	});
});

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

describe("validateManifests — happy path", () => {
	it("returns well-formed ValidatedManifests for a minimal valid manifest", () => {
		const providerMod = defineModule({
			name: "provider",
			provides: { cfgA: () => ({ v: 1 }) },
		});
		const consumerMod = defineModule({
			name: "consumer",
			requires: ["cfgA"],
			contributes: { grants: { code: () => ({}) as never } },
		});
		const result = validateManifests({
			modules: [providerMod, consumerMod],
			bootstrapComponents: minBootstrap,
			contributionKinds: { grants: makeStubNameCollector() as never },
		});

		// byName index
		expect(result.byName.size).toBe(2);
		expect(result.byName.has("provider")).toBe(true);
		expect(result.byName.has("consumer")).toBe(true);

		// providers index
		expect(result.providers.has("cfgA")).toBe(true);
		expect(result.providers.get("cfgA")?.manifest.name).toBe("provider");

		// usedKinds
		expect(result.usedKinds.has("grants")).toBe(true);

		// modules in input order
		expect(result.modules[0].manifest.name).toBe("provider");
		expect(result.modules[1].manifest.name).toBe("consumer");
	});
});
