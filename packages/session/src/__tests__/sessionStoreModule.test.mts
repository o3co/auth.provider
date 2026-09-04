/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

// D-5: sessionStoreModule manifest invokes the express-session middleware
// factory and forwards `BuilderContext.lifecycle` so the underlying session
// store registers its disposal callback. Tests exercise the route-contribution
// factory directly with mock deps — the boot planner integration path is
// covered by templates/standalone/src/__tests__/smoke.test.mts.

import {
	checkReplicaSafety,
	type LifecycleRegistrar,
	type Module,
	replicaUnsafeReason,
} from "@o3co/auth-provider-core";
import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { sessionStoreModule, sessionStoreModuleFor } from "../modules/sessionStoreModule.mjs";

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
	session: {
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
	session: {
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

describe("sessionStoreModule (D-5)", () => {
	it("declares lifecycleRegistrar and readinessRegistrar as optional and config as required", () => {
		const m = sessionStoreModule as unknown as Module;
		expect(m.name).toBe("sessionStoreModule");
		expect(m.requires).toContain("config");
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
			config: baseConfig as never,
			lifecycleRegistrar: undefined,
		} as never);
		expect(route.id).toBe("session-middleware");
		expect(route.mountPath).toBe("/");
		// No `before` clause — declarationIndex contract per D-5 calibration.
		expect(route.before).toBeUndefined();
		expect(typeof route.handler).toBe("function");
	});

	it("returns a route factory whose handler is callable (express middleware shape)", async () => {
		const m = sessionStoreModule as unknown as Module;
		const factory = m.contributes?.routes?.[0];
		if (typeof factory !== "function") throw new Error("not a factory");
		const route = await factory({
			config: baseConfig as never,
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
			config: baseConfig as never,
			lifecycleRegistrar: reg,
		} as never);
		// Route is constructed successfully even with a registrar present; the
		// memory builder doesn't register anything (no sub-resources to clean).
		// The redis builder path WOULD register `client.quit()` — that branch is
		// covered by the standalone smoke test when `session.storage.type` is
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
			config: {
				session: {
					...baseConfig.session,
					storage: { type: "redis", redis: { url: "redis://localhost:6379" } },
				},
			} as never,
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
			config: {
				session: {
					...baseConfig.session,
					name: "auth.sid",
					secure: false,
					domain: null,
				},
			} as never,
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
				config: {
					session: {
						...baseConfig.session,
						name: "__Host-auth.session",
						secure: false,
						domain: null,
					},
				} as never,
				lifecycleRegistrar: undefined,
			} as never),
		).rejects.toThrow(/__Host-/);

		await expect(
			factory({
				config: {
					session: {
						...baseConfig.session,
						name: "__Host-auth.session",
						secure: true,
						domain: "example.com",
					},
				} as never,
				lifecycleRegistrar: undefined,
			} as never),
		).rejects.toThrow(/__Host-/);
	});
});

// ---------------------------------------------------------------------------
// #474 — `SESSION_STORAGE_TYPE=memory` under `deployment.mode = "multi"` booted
// silently. express-session's MemoryStore is per process like every other
// memory store the replica-safety guard refuses, but this module's manifest
// carried no `replicaSafety`: the storage type is config, and the static
// manifest could not know it. `sessionStoreModuleFor(config)` builds the
// manifest from the config the composition root already holds, so the guard
// reads the declaration at stage 1 like the others (#455).
// ---------------------------------------------------------------------------

const memoryConfig = baseConfig;
const redisConfig: SessionLikeConfig = {
	session: {
		...baseConfig.session,
		storage: { type: "redis", redis: { url: "redis://localhost:6379" } } as { type: string },
	},
};

describe("sessionStoreModuleFor(config) — replica-safety declaration (#474)", () => {
	it("declares replica-unsafe state on the manifest when session.storage.type is memory", () => {
		const m = sessionStoreModuleFor(memoryConfig as never) as unknown as Module;
		expect(m.replicaSafety?.unsafe).toBe(true);
		// The guard quotes this; it has to say what breaks, not "use redis".
		expect(replicaUnsafeReason(m)).toBeDefined();
		expect((replicaUnsafeReason(m) ?? "").length).toBeGreaterThan(40);
	});

	it("declares nothing when the store is redis — the state lives in a shared store", () => {
		const m = sessionStoreModuleFor(redisConfig as never) as unknown as Module;
		expect(m.replicaSafety).toBeUndefined();
		expect(replicaUnsafeReason(m)).toBeUndefined();
	});

	it("is otherwise the same module: name, slots, configSchema and the one route", () => {
		const base = sessionStoreModule as unknown as Module;
		for (const m of [
			sessionStoreModuleFor(memoryConfig as never),
			sessionStoreModuleFor(redisConfig as never),
		]) {
			const built = m as unknown as Module;
			expect(built.name).toBe(base.name);
			expect(built.requires).toEqual(base.requires);
			expect(built.optional).toEqual(base.optional);
			expect(built.configSchema).toBe(base.configSchema);
			expect(built.contributes?.routes).toHaveLength(1);
		}
	});

	it('is refused by the replica-safety guard under deployment.mode = "multi", by name', () => {
		expect(() =>
			checkReplicaSafety({
				modules: [sessionStoreModuleFor(memoryConfig as never)],
				config: { deployment: { mode: "multi" } },
			}),
		).toThrow(
			expect.objectContaining({
				name: "BootError",
				reason: "replica-unsafe-adapter",
				details: { reason: "replica-unsafe-adapter", modules: ["sessionStoreModule"] },
			}),
		);
	});

	it('is silent under deployment.mode = "single" and warns when the mode is unset', () => {
		const warn = vi.fn();
		const logger = { warn, info: vi.fn(), error: vi.fn(), debug: vi.fn() } as never;
		checkReplicaSafety({
			modules: [sessionStoreModuleFor(memoryConfig as never)],
			config: { deployment: { mode: "single" } },
			logger,
		});
		expect(warn).not.toHaveBeenCalled();
		checkReplicaSafety({
			modules: [sessionStoreModuleFor(memoryConfig as never)],
			config: {},
			logger,
		});
		expect(warn).toHaveBeenCalledWith(
			expect.objectContaining({ modules: ["sessionStoreModule"] }),
			"replica_unsafe_adapters",
		);
	});

	it("passes the redis manifest through the guard under multi without complaint", () => {
		expect(() =>
			checkReplicaSafety({
				modules: [sessionStoreModuleFor(redisConfig as never)],
				config: { deployment: { mode: "multi" } },
			}),
		).not.toThrow();
	});
});

describe("sessionStoreModule (static manifest) — factory-time refusal under multi (#474)", () => {
	// A composition root that wires the static manifest has not told the
	// stage-1 guard anything, so the route factory — which is where the
	// storage type is first known for certain — refuses the same combination
	// with the same reason rather than mounting a per-process store.
	const factoryOf = (m: unknown) => {
		const factory = (m as Module).contributes?.routes?.[0];
		if (typeof factory !== "function") throw new Error("not a factory");
		return factory;
	};

	it('refuses memory storage under deployment.mode = "multi"', async () => {
		await expect(
			factoryOf(sessionStoreModule)({
				config: { ...memoryConfig, deployment: { mode: "multi" } } as never,
				lifecycleRegistrar: undefined,
			} as never),
		).rejects.toMatchObject({
			name: "BootError",
			reason: "replica-unsafe-adapter",
			details: { modules: ["sessionStoreModule"] },
		});
	});

	it('mounts memory storage under deployment.mode = "single" and when the mode is unset', async () => {
		for (const deployment of [{ mode: "single" }, undefined]) {
			const route = await factoryOf(sessionStoreModule)({
				config: { ...memoryConfig, ...(deployment ? { deployment } : {}) } as never,
				lifecycleRegistrar: undefined,
			} as never);
			expect(route.id).toBe("session-middleware");
		}
	});

	it('mounts redis storage under deployment.mode = "multi"', async () => {
		const route = await factoryOf(sessionStoreModule)({
			config: { ...redisConfig, deployment: { mode: "multi" } } as never,
			lifecycleRegistrar: undefined,
		} as never);
		expect(route.id).toBe("session-middleware");
	});
});
