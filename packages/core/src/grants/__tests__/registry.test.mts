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
import { z } from "zod";
import { GrantRegistry, GrantRegistryError } from "#/grants/registry.mjs";
import type {
	GrantDependencies,
	GrantFactory,
	GrantHandler,
	GrantModule,
} from "#/grants/types.mjs";
import { createSymmetricKeyStore } from "#/keys/KeyStore.mjs";

const makeHandler = (_name: string): GrantHandler => ({
	handle: vi.fn().mockResolvedValue({
		result: { status: 200, tokens: {} },
	}),
	cleanup: vi.fn(),
});

const makeFactory = (name: string): GrantFactory => {
	return (_deps: GrantDependencies) => makeHandler(name);
};

const makeDeps = (
	grantOverrides: Record<string, { enabled?: boolean }> = {},
): GrantDependencies => ({
	config: {
		oauth: {
			jwt: { secret: "test-secret" },
			accessToken: { expiresIn: 3600 },
			refreshToken: { expiresIn: 86400 },
			grants: grantOverrides,
		},
	} as unknown as GrantDependencies["config"],
	keyStore: createSymmetricKeyStore("test-secret"),
});

describe("GrantRegistry.addModule", () => {
	it("registers enabled grants from a module", () => {
		const registry = new GrantRegistry();
		const module: GrantModule = {
			grants: {
				session: makeFactory("session"),
			},
		};
		const deps = makeDeps({ session: { enabled: true } });

		registry.addModule(module, deps);

		expect(registry.get("session")).toBeDefined();
	});

	it("skips grants where config.enabled is false", () => {
		const registry = new GrantRegistry();
		const module: GrantModule = {
			grants: {
				session: makeFactory("session"),
			},
		};
		const deps = makeDeps({ session: { enabled: false } });

		registry.addModule(module, deps);

		expect(registry.get("session")).toBeUndefined();
	});

	it("registers grants with no config entry (treated as enabled)", () => {
		const registry = new GrantRegistry();
		const module: GrantModule = {
			grants: {
				session: makeFactory("session"),
			},
		};
		const deps = makeDeps({}); // no session entry at all

		registry.addModule(module, deps);

		expect(registry.get("session")).toBeDefined();
	});

	it("registers multiple grants from a single module", () => {
		const registry = new GrantRegistry();
		const module: GrantModule = {
			grants: {
				session: makeFactory("session"),
				authorization: makeFactory("authorization"),
				refresh_token: makeFactory("refresh_token"),
			},
		};
		const deps = makeDeps({
			session: { enabled: true },
			authorization: { enabled: true },
			refresh_token: { enabled: true },
		});

		registry.addModule(module, deps);

		expect(registry.get("session")).toBeDefined();
		expect(registry.get("authorization")).toBeDefined();
		expect(registry.get("refresh_token")).toBeDefined();
	});

	it("applies configSchema defaults when config block is missing", () => {
		const registry = new GrantRegistry();
		let receivedDeps: GrantDependencies | undefined;
		const module: GrantModule = {
			grants: {
				custom: (deps) => {
					receivedDeps = deps;
					return makeHandler("custom");
				},
			},
			configSchema: z.object({
				custom: z
					.object({
						enabled: z.boolean().default(true),
						timeout: z.coerce.number().default(500),
					})
					.default({ enabled: true, timeout: 500 }),
			}),
		};
		// No "custom" entry in grants config
		const deps = makeDeps({});

		registry.addModule(module, deps);

		expect(registry.get("custom")).toBeDefined();
		expect(receivedDeps).toBeDefined();
		const grants = (receivedDeps as GrantDependencies).config.oauth.grants as Record<
			string,
			Record<string, unknown>
		>;
		expect(grants.custom.timeout).toBe(500);
		expect(grants.custom.enabled).toBe(true);
	});

	it("merges configSchema defaults with existing config values", () => {
		const registry = new GrantRegistry();
		let receivedDeps: GrantDependencies | undefined;
		const module: GrantModule = {
			grants: {
				custom: (deps) => {
					receivedDeps = deps;
					return makeHandler("custom");
				},
			},
			configSchema: z.object({
				custom: z
					.object({
						enabled: z.boolean().default(true),
						timeout: z.coerce.number().default(500),
					})
					.default({ enabled: true, timeout: 500 }),
			}),
		};
		// Partial config — timeout should get default, enabled is explicit
		const deps = makeDeps({ custom: { enabled: true } } as Record<string, { enabled?: boolean }>);

		registry.addModule(module, deps);

		expect(receivedDeps).toBeDefined();
		const grants = (receivedDeps as GrantDependencies).config.oauth.grants as Record<
			string,
			Record<string, unknown>
		>;
		expect(grants.custom.timeout).toBe(500);
	});

	it("skips configSchema application when not provided", () => {
		const registry = new GrantRegistry();
		let receivedDeps: GrantDependencies | undefined;
		const module: GrantModule = {
			grants: {
				session: (deps) => {
					receivedDeps = deps;
					return makeHandler("session");
				},
			},
			// No configSchema
		};
		const deps = makeDeps({ session: { enabled: true } });

		registry.addModule(module, deps);

		// deps passed through unmodified
		expect(receivedDeps).toBe(deps);
	});
});

describe("GrantRegistry.register (A6+A7 §2.1: throw on duplicate)", () => {
	it("registers a handler under a fresh name", () => {
		const registry = new GrantRegistry();
		registry.register("foo", makeHandler("a"));
		expect(registry.get("foo")).toBeDefined();
	});

	it("throws GrantRegistryError reason='duplicate' on duplicate name", () => {
		const registry = new GrantRegistry();
		registry.register("foo", makeHandler("a"));
		let caught: unknown;
		try {
			registry.register("foo", makeHandler("b"));
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(GrantRegistryError);
		if (caught instanceof GrantRegistryError) {
			expect(caught.reason).toBe("duplicate");
			expect(caught.grantType).toBe("foo");
			expect(caught.registered).toEqual(["foo"]);
		}
	});

	it("does NOT silently overwrite — original handler remains after duplicate throw", () => {
		const registry = new GrantRegistry();
		const original = makeHandler("original");
		registry.register("foo", original);
		expect(() => registry.register("foo", makeHandler("replacement"))).toThrow(GrantRegistryError);
		expect(registry.get("foo")).toBe(original);
	});
});

describe("GrantRegistry.replace (A6+A7 §2.2: explicit override)", () => {
	it("overwrites a registered handler (happy path)", () => {
		const registry = new GrantRegistry();
		const original = makeHandler("original");
		const replacement = makeHandler("replacement");
		registry.register("foo", original);
		registry.replace("foo", replacement);
		expect(registry.get("foo")).toBe(replacement);
	});

	it("throws GrantRegistryError reason='unknown' when name is not registered", () => {
		const registry = new GrantRegistry();
		let caught: unknown;
		try {
			registry.replace("absent", makeHandler("x"));
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(GrantRegistryError);
		if (caught instanceof GrantRegistryError) {
			expect(caught.reason).toBe("unknown");
			expect(caught.grantType).toBe("absent");
			expect(caught.registered).toEqual([]);
		}
	});

	it("throws GrantRegistryError reason='frozen' on a frozen registry", () => {
		const registry = new GrantRegistry();
		registry.register("foo", makeHandler("a"));
		registry.freeze();
		let caught: unknown;
		try {
			registry.replace("foo", makeHandler("b"));
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(GrantRegistryError);
		if (caught instanceof GrantRegistryError) {
			expect(caught.reason).toBe("frozen");
			expect(caught.grantType).toBe("foo");
		}
	});
});

describe("GrantRegistry.freeze (A6+A7 §2.3: activation boundary)", () => {
	it("blocks register on a frozen registry with reason='frozen'", () => {
		const registry = new GrantRegistry();
		registry.freeze();
		let caught: unknown;
		try {
			registry.register("foo", makeHandler("a"));
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(GrantRegistryError);
		if (caught instanceof GrantRegistryError) {
			expect(caught.reason).toBe("frozen");
		}
	});

	it("is idempotent (calling freeze twice is a no-op)", () => {
		const registry = new GrantRegistry();
		registry.freeze();
		expect(() => registry.freeze()).not.toThrow();
	});

	it("allows get on a frozen registry", () => {
		const registry = new GrantRegistry();
		registry.register("foo", makeHandler("a"));
		registry.freeze();
		expect(registry.get("foo")).toBeDefined();
	});

	it("frozen precedence: duplicate-after-freeze throws reason='frozen' (NOT 'duplicate')", () => {
		// Per A6+A7 §2.3: "After freeze(): register throws with reason='frozen'".
		// This is unconditional — when both freeze and duplicate conditions
		// hold, "frozen" wins. The frozen check runs before the duplicate
		// check in the impl to honour this precedence.
		const registry = new GrantRegistry();
		registry.register("foo", makeHandler("a"));
		registry.freeze();
		let caught: unknown;
		try {
			registry.register("foo", makeHandler("b"));
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(GrantRegistryError);
		if (caught instanceof GrantRegistryError) {
			expect(caught.reason).toBe("frozen");
			expect(caught.grantType).toBe("foo");
		}
	});
});

describe("GrantRegistry.addModule no-side-effect-leak (Codex review P1)", () => {
	it("throws BEFORE running ANY factory when a name conflict exists", () => {
		const registry = new GrantRegistry();
		registry.register("session", makeHandler("existing"));

		const factoryRan: string[] = [];
		const trackingFactory =
			(label: string): GrantFactory =>
			() => {
				factoryRan.push(label);
				return makeHandler(label);
			};
		const module: GrantModule = {
			grants: {
				// "fresh" comes first in iteration order. Pre-check phase
				// MUST detect the "session" duplicate before fresh's factory
				// runs.
				fresh: trackingFactory("fresh"),
				session: trackingFactory("session"),
			},
		};
		const deps = makeDeps({
			fresh: { enabled: true },
			session: { enabled: true },
		});

		expect(() => registry.addModule(module, deps)).toThrow(GrantRegistryError);
		// No factory should have run because pre-check caught the duplicate.
		expect(factoryRan).toEqual([]);
	});

	it("throws frozen when registry is already sealed (no factory runs)", () => {
		const registry = new GrantRegistry();
		registry.freeze();

		const factoryRan: string[] = [];
		const trackingFactory =
			(label: string): GrantFactory =>
			() => {
				factoryRan.push(label);
				return makeHandler(label);
			};
		const module: GrantModule = {
			grants: {
				newGrant: trackingFactory("newGrant"),
			},
		};
		const deps = makeDeps({ newGrant: { enabled: true } });

		expect(() => registry.addModule(module, deps)).toThrow(GrantRegistryError);
		expect(factoryRan).toEqual([]);
	});

	it("skips disabled grants in the pre-check (no false-positive duplicate)", () => {
		const registry = new GrantRegistry();
		registry.register("session", makeHandler("existing"));

		const module: GrantModule = {
			grants: {
				// session is in the module but disabled in config —
				// pre-check must skip it (no duplicate error).
				session: makeFactory("session"),
				other: makeFactory("other"),
			},
		};
		const deps = makeDeps({
			session: { enabled: false },
			other: { enabled: true },
		});

		// Should NOT throw because the disabled session entry is skipped.
		registry.addModule(module, deps);
		expect(registry.get("other")).toBeDefined();
	});
});

describe("GrantRegistryError (A6+A7 §2.4: error class shape)", () => {
	it("carries reason, grantType, and registered snapshot", () => {
		const err = new GrantRegistryError({
			reason: "duplicate",
			grantType: "foo",
			registered: ["foo", "bar"],
		});
		expect(err.reason).toBe("duplicate");
		expect(err.grantType).toBe("foo");
		expect(err.registered).toEqual(["foo", "bar"]);
		expect(err.name).toBe("GrantRegistryError");
		expect(err.message).toContain("duplicate");
		expect(err.message).toContain("foo");
	});

	it("formats unknown-reason message with empty registered list", () => {
		const err = new GrantRegistryError({
			reason: "unknown",
			grantType: "absent",
			registered: [],
		});
		expect(err.message).toContain("unknown");
		expect(err.message).toContain("absent");
	});

	it("formats frozen-reason message", () => {
		const err = new GrantRegistryError({
			reason: "frozen",
			grantType: "foo",
			registered: ["foo"],
		});
		expect(err.message).toContain("frozen");
	});
});
