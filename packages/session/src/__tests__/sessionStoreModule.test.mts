/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

// sessionStoreModule's manifest invokes the express-session middleware
// factory and forwards `BuilderContext.lifecycle` so the underlying session
// store registers its disposal callback. Tests exercise the route-contribution
// factory directly with mock deps, and boot the module through createApp for
// what its configSchema refuses and what it mounts.

import {
	type AppConfig,
	checkReplicaSafety,
	createApp,
	defineModule,
	type LifecycleRegistrar,
	MAX_DURATION_MS,
	type Module,
	replicaUnsafeReason,
	type SessionCookiePolicy,
} from "@o3co/auth-provider-core";
import { makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import express from "express";
import { createClient } from "redis";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { sessionStoreModule, sessionStoreModuleFor } from "../modules/sessionStoreModule.mjs";
import { withSessionCaptures, withStore } from "./_helpers/sections.mjs";

// The redis session-store builder dynamically imports these; mock them so the
// readiness-forwarding test below never opens a socket.
vi.mock("redis", () => ({
	createClient: vi.fn(() => ({
		connect: vi.fn().mockResolvedValue(undefined),
		quit: vi.fn().mockResolvedValue(undefined),
		ping: vi.fn().mockResolvedValue("PONG"),
		on: vi.fn(),
	})),
}));

vi.mock("connect-redis", async () => {
	const { EventEmitter } = await import("node:events");
	// express-session subscribes to store events, so the fake must be an
	// EventEmitter rather than a plain object.
	return {
		RedisStore: class MockRedisStore extends EventEmitter {
			constructor(_opts: { client: unknown }) {
				super();
			}
			get(): unknown {
				return undefined;
			}
			set(): void {}
			destroy(): void {}
		},
	};
});

interface SessionLikeConfig {
	"session-store": {
		secret: string;
		name: string;
		secure: boolean;
		maxAge: number;
		sameSite: "lax" | "strict" | "none";
		domain: string;
		storage: { type: string };
	};
}

const baseConfig: SessionLikeConfig = {
	"session-store": {
		secret: "test-secret-at-least-32-chars-long!",
		name: "test.sid",
		secure: false,
		maxAge: 3600_000,
		sameSite: "lax",
		domain: "",
		storage: { type: "memory" },
	},
};

function makeRegistrar(): LifecycleRegistrar & { calls: Array<() => Promise<void>> } {
	const calls: Array<() => Promise<void>> = [];
	return {
		register: (cleanup) => {
			calls.push(cleanup);
		},
		calls,
	};
}

describe("sessionStoreModule", () => {
	it("declares lifecycleRegistrar and readinessRegistrar as optional, and reads its own section, not config", () => {
		const m = sessionStoreModule as unknown as Module;
		expect(m.name).toBe("session-store");
		expect(m.requires).not.toContain("config");
		expect(m.section?.at).toBeUndefined();
		expect(m.optional).toContain("lifecycleRegistrar");
		expect(m.optional).toContain("readinessRegistrar");
	});

	it("contributes a single route factory at mountPath '/' with id session-middleware", async () => {
		const m = sessionStoreModule as unknown as Module;
		expect(m.contributes?.routes).toHaveLength(1);
		const factory = m.contributes?.routes?.[0];
		if (typeof factory !== "function") {
			throw new Error("expected sessionStoreModule.contributes.routes[0] to be a factory");
		}
		const route = await factory({
			section: baseConfig["session-store"] as never,
			deploymentMode: "unset",
			lifecycleRegistrar: undefined,
		} as never);
		expect(route.id).toBe("session-middleware");
		expect(route.mountPath).toBe("/");
		// No `before` clause — its place follows declaration order (declarationIndex).
		expect(route.before).toBeUndefined();
		expect(typeof route.handler).toBe("function");
	});

	it("returns a route factory whose handler is callable (express middleware shape)", async () => {
		const m = sessionStoreModule as unknown as Module;
		const factory = m.contributes?.routes?.[0];
		if (typeof factory !== "function") throw new Error("not a factory");
		const route = await factory({
			section: baseConfig["session-store"] as never,
			deploymentMode: "unset",
			lifecycleRegistrar: undefined,
		} as never);
		// express middleware signature: (req, res, next) => void; verify it's a 3-arg function.
		const handler = route.handler as (req: unknown, res: unknown, next: unknown) => void;
		expect(handler.length).toBe(3);
	});

	it("forwards lifecycleRegistrar through createSessionStoreFactory (memory builder is a no-op)", async () => {
		const m = sessionStoreModule as unknown as Module;
		const factory = m.contributes?.routes?.[0];
		if (typeof factory !== "function") throw new Error("not a factory");
		const reg = makeRegistrar();
		const route = await factory({
			section: baseConfig["session-store"] as never,
			deploymentMode: "unset",
			lifecycleRegistrar: reg,
		} as never);
		// Route is constructed successfully even with a registrar present; the
		// memory builder doesn't register anything (no sub-resources to clean).
		// The redis builder path WOULD register `client.quit()` — that branch is
		// covered by the standalone smoke test when `session-store.storage.type` is
		// configured to "redis".
		expect(route.id).toBe("session-middleware");
		expect(reg.calls).toHaveLength(0);
	});

	it("forwards readinessRegistrar so the redis builder's probe reaches /readyz", async () => {
		// This is the only place the wiring is observable. Delete
		// `readiness: deps.readinessRegistrar` from the module and the
		// session-store probe silently disappears: /readyz answers 200 while the
		// session backend is unreachable, and every other test in the repo still
		// passes because the memory adapter registers nothing either way.
		const m = sessionStoreModule as unknown as Module;
		const factory = m.contributes?.routes?.[0];
		if (typeof factory !== "function") throw new Error("not a factory");

		const probes: Array<{ name: string; check: () => Promise<unknown> }> = [];
		await factory({
			section: {
				...baseConfig["session-store"],
				storage: { type: "redis", redis: { url: "redis://localhost:6379" } },
			} as never,
			deploymentMode: "unset",
			lifecycleRegistrar: makeRegistrar(),
			readinessRegistrar: { register: (probe: (typeof probes)[number]) => probes.push(probe) },
		} as never);

		expect(probes.map((probe) => probe.name)).toEqual(["session-store"]);
		await expect(probes[0]?.check()).resolves.toBe("PONG");
	});

	it("uses session.name as the express-session cookie name", async () => {
		const m = sessionStoreModule as unknown as Module;
		const factory = m.contributes?.routes?.[0];
		if (typeof factory !== "function") throw new Error("not a factory");
		const route = await factory({
			section: {
				...baseConfig["session-store"],
				name: "auth.sid",
				secure: false,
				domain: null,
			} as never,
			deploymentMode: "unset",
			lifecycleRegistrar: undefined,
		} as never);
		const app = express();
		app.use(route.handler);
		app.post("/touch", (req, res) => {
			(req.session as unknown as Record<string, unknown>).touched = true;
			res.status(200).json({ ok: true });
		});

		const res = await request(app).post("/touch");

		const cookie = res.headers["set-cookie"]?.[0] ?? "";
		expect(cookie).toMatch(/^auth\.sid=/);
	});

	it("rejects __Host- session names when secure/domain constraints are violated", async () => {
		const m = sessionStoreModule as unknown as Module;
		const factory = m.contributes?.routes?.[0];
		if (typeof factory !== "function") throw new Error("not a factory");

		await expect(
			factory({
				section: {
					...baseConfig["session-store"],
					name: "__Host-auth.session",
					secure: false,
					domain: null,
				} as never,
				deploymentMode: "unset",
				lifecycleRegistrar: undefined,
			} as never),
		).rejects.toThrow(/__Host-/);

		await expect(
			factory({
				section: {
					...baseConfig["session-store"],
					name: "__Host-auth.session",
					secure: true,
					domain: "example.com",
				} as never,
				deploymentMode: "unset",
				lifecycleRegistrar: undefined,
			} as never),
		).rejects.toThrow(/__Host-/);
	});
});

// ---------------------------------------------------------------------------
// `SESSION_STORAGE_TYPE=memory` under `core.deployment.mode = "multi"`.
// express-session's MemoryStore is per process like every other memory store
// the replica-safety guard refuses, but the storage type is config, which a
// static manifest cannot know. `sessionStoreModuleFor(config)` builds the
// manifest from the config the composition root already holds, so the guard
// reads the declaration at stage 1 like the others.
// ---------------------------------------------------------------------------

const memoryConfig = baseConfig;
const redisConfig: SessionLikeConfig = {
	"session-store": {
		...baseConfig["session-store"],
		storage: { type: "redis", redis: { url: "redis://localhost:6379" } } as { type: string },
	},
};

describe("sessionStoreModuleFor(config) — replica-safety declaration", () => {
	it("declares replica-unsafe state on the manifest when session-store.storage.type is memory", () => {
		const m = sessionStoreModuleFor(memoryConfig as never) as unknown as Module;
		expect(m.replicaSafety).toMatchObject({ unsafe: true });
		// The guard quotes this; it has to say what breaks, not "use redis".
		expect(replicaUnsafeReason(m)).toBeDefined();
		expect((replicaUnsafeReason(m) ?? "").length).toBeGreaterThan(40);
	});

	it("declares nothing when the store is redis — the state lives in a shared store", () => {
		const m = sessionStoreModuleFor(redisConfig as never) as unknown as Module;
		expect(m.replicaSafety).toBeUndefined();
		expect(replicaUnsafeReason(m)).toBeUndefined();
	});

	it("is otherwise the same module: name, slots, section and the one route", () => {
		const base = sessionStoreModule as unknown as Module;
		for (const m of [
			sessionStoreModuleFor(memoryConfig as never),
			sessionStoreModuleFor(redisConfig as never),
		]) {
			const built = m as unknown as Module;
			expect(built.name).toBe(base.name);
			expect(built.requires).toEqual(base.requires);
			expect(built.optional).toEqual(base.optional);
			expect(built.section).toBe(base.section);
			expect(built.contributes?.routes).toHaveLength(1);
		}
	});

	it('is refused by the replica-safety guard under core.deployment.mode = "multi", by name', () => {
		expect(() =>
			checkReplicaSafety({
				modules: [sessionStoreModuleFor(memoryConfig as never)],
				config: { core: { deployment: { mode: "multi" } } },
			}),
		).toThrow(
			expect.objectContaining({
				name: "BootError",
				reason: "replica-unsafe-adapter",
				details: { reason: "replica-unsafe-adapter", modules: ["session-store"] },
			}),
		);
	});

	it('is silent under core.deployment.mode = "single" and warns when the mode is unset', () => {
		const warn = vi.fn();
		const logger = { warn, info: vi.fn(), error: vi.fn(), debug: vi.fn() } as never;
		checkReplicaSafety({
			modules: [sessionStoreModuleFor(memoryConfig as never)],
			config: { core: { deployment: { mode: "single" } } },
			logger,
		});
		expect(warn).not.toHaveBeenCalled();
		checkReplicaSafety({
			modules: [sessionStoreModuleFor(memoryConfig as never)],
			config: {},
			logger,
		});
		expect(warn).toHaveBeenCalledWith(
			expect.objectContaining({ modules: ["session-store"] }),
			"replica_unsafe_adapters",
		);
	});

	it("passes the redis manifest through the guard under multi without complaint", () => {
		expect(() =>
			checkReplicaSafety({
				modules: [sessionStoreModuleFor(redisConfig as never)],
				config: { core: { deployment: { mode: "multi" } } },
			}),
		).not.toThrow();
	});
});

describe("sessionStoreModule (static manifest) — factory-time refusal under multi", () => {
	// A composition root that wires the static manifest has not told the
	// stage-1 guard anything, so the route factory — which is where the
	// storage type is first known for certain — refuses the same combination
	// with the same reason rather than mounting a per-process store. The mode
	// is the `deploymentMode` slot core fills from `core.deployment.mode`; the
	// configuration's own `deployment` is not read.
	const factoryOf = (m: unknown) => {
		const factory = (m as Module).contributes?.routes?.[0];
		if (typeof factory !== "function") throw new Error("not a factory");
		return factory;
	};

	it("requires the deploymentMode slot, as the configured module does", () => {
		expect(sessionStoreModule.requires).toContain("deploymentMode");
		expect(sessionStoreModuleFor(memoryConfig as never).requires).toContain("deploymentMode");
	});

	it('refuses memory storage when the slot says "multi"', async () => {
		await expect(
			factoryOf(sessionStoreModule)({
				section: memoryConfig["session-store"] as never,
				deploymentMode: "multi",
				lifecycleRegistrar: undefined,
			} as never),
		).rejects.toMatchObject({
			name: "BootError",
			reason: "replica-unsafe-adapter",
			details: { modules: ["session-store"] },
		});
	});

	it('mounts memory storage when the slot says "single" or "unset"', async () => {
		for (const deploymentMode of ["single", "unset"] as const) {
			const route = await factoryOf(sessionStoreModule)({
				section: memoryConfig["session-store"] as never,
				deploymentMode,
				lifecycleRegistrar: undefined,
			} as never);
			expect(route.id).toBe("session-middleware");
		}
	});

	it('mounts redis storage when the slot says "multi"', async () => {
		const route = await factoryOf(sessionStoreModule)({
			section: redisConfig["session-store"] as never,
			deploymentMode: "multi",
			lifecycleRegistrar: undefined,
		} as never);
		expect(route.id).toBe("session-middleware");
	});

	it("refuses a slot it cannot read, absent included, as a TypeError naming it", async () => {
		for (const deploymentMode of [undefined, "MULTI", null]) {
			await expect(
				factoryOf(sessionStoreModule)({
					section: redisConfig["session-store"] as never,
					deploymentMode,
					lifecycleRegistrar: undefined,
				} as never),
				String(deploymentMode),
			).rejects.toThrow(
				new TypeError('session-store: deploymentMode must be "single", "multi" or "unset"'),
			);
		}
	});

	it("decides by the slot, whatever the configuration's deployment says", async () => {
		await expect(
			factoryOf(sessionStoreModule)({
				config: { ...memoryConfig, core: { deployment: { mode: "single" } } } as never,
				section: memoryConfig["session-store"] as never,
				deploymentMode: "multi",
				lifecycleRegistrar: undefined,
			} as never),
		).rejects.toMatchObject({ reason: "replica-unsafe-adapter" });
		const route = await factoryOf(sessionStoreModule)({
			config: { ...memoryConfig, core: { deployment: { mode: "multi" } } } as never,
			section: memoryConfig["session-store"] as never,
			deploymentMode: "single",
			lifecycleRegistrar: undefined,
		} as never);
		expect(route.id).toBe("session-middleware");
	});

	it.each([
		["refused", "core.deployment.mode = multi", { mode: "multi" }],
		["mounted", "core.deployment.mode = single", { mode: "single" }],
		["mounted", "an empty deployment section", {}],
		["mounted", "no deployment section", undefined],
	] as const)(
		"through createApp, memory storage is %s under %s",
		async (outcome, _what, deployment) => {
			const base = makeValidAppConfig();
			const boot = createApp({
				modules: [sessionStoreModule],
				bootstrapComponents: {
					config: withSessionCaptures({
						...withStore(base, { storage: { type: "memory" } }),
						...(deployment === undefined ? {} : { core: { ...base.core, deployment } }),
					}),
					pathResolver: (p: string) => p,
				} as never,
			});
			if (outcome === "refused") {
				await expect(boot).rejects.toMatchObject({
					reason: "contribute-factory-failed",
					cause: { reason: "replica-unsafe-adapter", details: { modules: ["session-store"] } },
				});
				return;
			}
			const handle = await boot;
			try {
				expect(handle.routes.map((r) => r.contribution.id)).toContain("session-middleware");
			} finally {
				await handle.dispose();
			}
		},
	);
});

// ---------------------------------------------------------------------------
// The cookie the store mounts is the one its `sessionCookiePolicy` describes:
// the module's configSchema refuses at validation every section the policy
// refuses, and the route reuses the provider's policy.
// ---------------------------------------------------------------------------

describe("the session store refuses the cookie its sessionCookiePolicy refuses", () => {
	const HOST_PREFIX =
		"session-store.name with __Host- prefix requires session-store.secure=true and session-store.domain=null";
	const SECURE_PREFIX =
		"session-store.name with __Secure- prefix requires session-store.secure=true";
	const NOT_A_TOKEN = 'session-store.name "auth session" is not a cookie name (an RFC 6265 token)';
	const notADomain = (domain: string) =>
		`session-store.domain ${JSON.stringify(domain)} is not a cookie domain (a host name, one leading dot allowed)`;
	const CROSS_SITE =
		'session-store.sameSite = "none" requires session-store.secure = true (SESSION_STORE_SECURE=true): browsers drop a SameSite=None cookie that is not Secure';
	const LIFETIME = `session-store.maxAge must be a whole number of milliseconds from 1 to ${MAX_DURATION_MS}`;

	/** The session store's section of a configuration, as a route factory is handed it. */
	const storeOf = (config: object): never =>
		(config as { "session-store": unknown })["session-store"] as never;

	/** The fixture's configuration with `change` laid over its session store's section. */
	const configWith = (change: Record<string, unknown>) =>
		withSessionCaptures(withStore(makeValidAppConfig(), change));

	const FORMS = [
		["sessionStoreModuleFor(config)", (config: never) => sessionStoreModuleFor(config)],
		["sessionStoreModule", () => sessionStoreModule],
	] as const;

	/** Boots the session store's module alone: nothing requires the slot. */
	const bootAlone = (form: (typeof FORMS)[number][1], change: Record<string, unknown>) => {
		const config = configWith(change);
		return createApp({
			modules: [form(config as never)],
			bootstrapComponents: { config, pathResolver: (p: string) => p } as never,
		});
	};

	/** What a boot settles as: the refusal, or `undefined` once it booted and was disposed. */
	const settled = (boot: ReturnType<typeof bootAlone>): Promise<unknown> =>
		boot.then(
			async (handle) => {
				await handle.dispose();
				return undefined;
			},
			(err: unknown) => err,
		);

	/** A refusal the module's configSchema makes: [what, key, change, message]. */
	const REFUSED_BY_THE_STORE = [
		["a name that is not an RFC 6265 token", "name", { name: "auth session" }, NOT_A_TOKEN],
		[
			"an empty name",
			"name",
			{ name: "" },
			'session-store.name "" is not a cookie name (an RFC 6265 token)',
		],
		[
			"a __Secure- name that is not secure",
			"name",
			{ name: "__Secure-auth.session", secure: false },
			SECURE_PREFIX,
		],
		[
			"a __secure- name, in any case, that is not secure",
			"name",
			{ name: "__secure-auth.session", secure: false },
			SECURE_PREFIX,
		],
		["a __Host- name that is not secure", "name", { secure: false }, HOST_PREFIX],
		["a __Host- name with a domain", "name", { domain: "example.com" }, HOST_PREFIX],
		[
			"a __HOST- name, in any case, that is not secure",
			"name",
			{ name: "__HOST-auth.session", secure: false },
			HOST_PREFIX,
		],
		[
			"a domain that is a URL",
			"domain",
			{ name: "auth.session", domain: "https://auth.example.com" },
			notADomain("https://auth.example.com"),
		],
		[
			"a domain with a port",
			"domain",
			{ name: "auth.session", domain: "auth.example.com:8443" },
			notADomain("auth.example.com:8443"),
		],
	] as const;

	/** A refusal the schema's own leaves make, or the policy's, for SameSite: [what, key, change, the policy's message]. */
	const REFUSED_BY_THE_SCHEMA = [
		[
			"SameSite=None that is not secure",
			"secure",
			{ name: "auth.session", sameSite: "none", secure: false },
			CROSS_SITE,
		],
		["a lifetime of 0", "maxAge", { maxAge: 0 }, LIFETIME],
		["a fractional lifetime", "maxAge", { maxAge: 1.5 }, LIFETIME],
		["a lifetime above the ceiling", "maxAge", { maxAge: MAX_DURATION_MS + 1 }, LIFETIME],
	] as const;

	describe.each(FORMS)("through createApp, with %s installed alone", (_form, form) => {
		it.each(REFUSED_BY_THE_STORE)(
			"refuses %s at validation, its one issue naming session-store.%s with the policy's message",
			async (_what, key, change, message) => {
				expect(await settled(bootAlone(form, change))).toMatchObject({
					name: "BootError",
					reason: "config-validation-failed",
					stage: "validateManifests",
					details: {
						reason: "config-validation-failed",
						issues: [{ code: "custom", path: ["session-store", key], message }],
					},
				});
			},
		);

		it.each(REFUSED_BY_THE_SCHEMA)(
			"refuses %s at validation, naming session-store.%s",
			async (_what, key, change) => {
				expect(await settled(bootAlone(form, change))).toMatchObject({
					name: "BootError",
					reason: "config-validation-failed",
					stage: "validateManifests",
					details: {
						issues: expect.arrayContaining([
							expect.objectContaining({ path: ["session-store", key] }),
						]),
					},
				});
			},
		);

		it.each([
			["the fixture's __Host- cookie, secure and host-only", {}],
			["a __HOST- cookie, in any case, secure and host-only", { name: "__HOST-auth.session" }],
			[
				"a __Secure- cookie that is secure and names a domain",
				{ name: "__Secure-auth.session", secure: true, domain: "example.com" },
			],
			[
				"a cookie shared across subdomains, its domain after a leading dot",
				{ name: "auth.session", domain: ".example.com" },
			],
			["an unprefixed cookie over plain HTTP", { name: "auth.session", secure: false }],
			[
				"a cross-site cookie that is secure",
				{ name: "__Secure-auth.session", sameSite: "none", secure: true },
			],
			["a lifetime of 1 ms", { maxAge: 1 }],
			["a lifetime at the ceiling", { maxAge: MAX_DURATION_MS }],
		])("mounts %s", async (_what, change) => {
			const handle = await bootAlone(form, change);
			try {
				expect(handle.routes.map((r) => r.contribution.id)).toContain("session-middleware");
			} finally {
				await handle.dispose();
			}
		});
	});

	const factoryOf = (m: unknown) => {
		const factory = (m as Module).contributes?.routes?.[0];
		if (typeof factory !== "function") throw new Error("not a factory");
		return factory;
	};

	it.each([...REFUSED_BY_THE_STORE, ...REFUSED_BY_THE_SCHEMA])(
		"the route refuses %s itself, with the policy's message, for deps no parse validated",
		async (_what, _key, change, message) => {
			await expect(
				factoryOf(sessionStoreModule)({
					section: storeOf(configWith(change)),
					deploymentMode: "unset",
					lifecycleRegistrar: undefined,
				} as never),
			).rejects.toThrow(message);
		},
	);

	it("refuses before it opens the store's connection", async () => {
		const redis = { type: "redis", redis: { url: "redis://localhost:6379" } };
		vi.mocked(createClient).mockClear();
		await expect(
			factoryOf(sessionStoreModule)({
				section: storeOf(configWith({ name: "auth session", storage: redis })),
				deploymentMode: "unset",
				lifecycleRegistrar: undefined,
			} as never),
		).rejects.toThrow(NOT_A_TOKEN);
		expect(createClient).not.toHaveBeenCalled();

		await factoryOf(sessionStoreModule)({
			section: storeOf(configWith({ storage: redis })),
			deploymentMode: "unset",
			lifecycleRegistrar: undefined,
		} as never);
		expect(createClient).toHaveBeenCalledTimes(1);
	});

	it("mounts the cookie its provider built, though config's session-store changed after", async () => {
		const config = configWith({ name: "auth.session", secure: false }) as AppConfig;
		const seen: { policy?: SessionCookiePolicy } = {};
		const handle = await createApp({
			modules: [
				// Listed first, so its route factory runs after the providers and
				// before the store's route.
				defineModule({
					name: "test:session-section-mutator",
					requires: ["config"],
					contributes: {
						routes: [
							(deps) => {
								(deps.config as unknown as { "session-store": { name: string } })[
									"session-store"
								].name = "auth.other";
								return { id: "test:mutator", mountPath: "/mutator", handler: express.Router() };
							},
						],
					},
				}),
				sessionStoreModuleFor(config),
				defineModule({
					name: "test:session-cookie-policy-reader",
					requires: ["sessionCookiePolicy"],
					contributes: {
						routes: [
							(deps) => {
								seen.policy = deps.sessionCookiePolicy;
								const touch = express.Router();
								touch.post("/", (req, res) => {
									(req.session as unknown as Record<string, unknown>).touched = true;
									res.status(200).json({ ok: true });
								});
								return { id: "test:touch", mountPath: "/touch", handler: touch };
							},
						],
					},
				}),
			],
			bootstrapComponents: { config, pathResolver: (p: string) => p } as never,
		});
		try {
			const res = await request(express().use(handle.router)).post("/touch");
			expect(res.status).toBe(200);
			expect(seen.policy?.name).toBe("auth.session");
			expect(res.headers["set-cookie"]?.[0] ?? "").toMatch(/^auth\.session=/);
		} finally {
			await handle.dispose();
		}
	});

	it("sets the cookie the section describes: its name, Domain, SameSite and lifetime", async () => {
		const route = await factoryOf(sessionStoreModule)({
			section: storeOf(
				configWith({
					name: "auth.session",
					secure: false,
					sameSite: "strict",
					domain: "example.com",
					maxAge: 60_000,
				}),
			),
			deploymentMode: "unset",
			lifecycleRegistrar: undefined,
		} as never);
		const app = express();
		app.use(route.handler);
		app.post("/touch", (req, res) => {
			(req.session as unknown as Record<string, unknown>).touched = true;
			res.status(200).json({ ok: true });
		});

		const before = Date.now();
		const res = await request(app).post("/touch");

		const cookie = res.headers["set-cookie"]?.[0] ?? "";
		const attributes = cookie.split("; ");
		expect(attributes[0]).toMatch(/^auth\.session=/);
		expect(attributes).toEqual(
			expect.arrayContaining(["Domain=example.com", "Path=/", "HttpOnly", "SameSite=Strict"]),
		);
		expect(attributes).not.toContain("Secure");
		const expires = Date.parse(attributes.find((a) => a.startsWith("Expires="))?.slice(8) ?? "");
		// `Expires` has whole seconds.
		expect(expires).toBeGreaterThanOrEqual(Math.floor(before / 1000) * 1000 + 60_000 - 1000);
		expect(expires).toBeLessThanOrEqual(Date.now() + 60_000);
	});

	it("sets a host-only cookie for an empty domain", async () => {
		const route = await factoryOf(sessionStoreModule)({
			section: storeOf(configWith({ name: "auth.session", secure: false, domain: "" })),
			deploymentMode: "unset",
			lifecycleRegistrar: undefined,
		} as never);
		const app = express();
		app.use(route.handler);
		app.post("/touch", (req, res) => {
			(req.session as unknown as Record<string, unknown>).touched = true;
			res.status(200).json({ ok: true });
		});

		const res = await request(app).post("/touch");

		const cookie = res.headers["set-cookie"]?.[0] ?? "";
		expect(cookie).toMatch(/^auth\.session=/);
		expect(cookie).not.toMatch(/Domain=/);
	});
});
