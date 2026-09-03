/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * Issue #271 — `rateLimiter.adapter` and `userSessionStores.adapter` default
 * to `"memory"`, and nothing noticed when the service was scaled to multiple
 * replicas. User-session state forked per replica, so back-channel logout
 * reached only one of them and a "logged out" session stayed valid on the
 * others; rate limits multiplied by replica count. No boot signal fired.
 *
 * The guard reads the *installed modules* rather than the config: that is what
 * is actually wired, it survives a hand-built config, and it covers stores the
 * config switches do not name — a memory access-token denylist means a revoked
 * token stays valid on every other replica.
 */

import { describe, expect, it, vi } from "vitest";
import {
	checkReplicaSafety,
	REPLICA_UNSAFE_MODULES,
	replicaUnsafeReason,
} from "#/boot/replica-safety.mjs";
import type { BootstrapMap } from "#/boot/types.mjs";
import { BootError } from "#/boot/types.mjs";
import { createApp, defineModule } from "#/index.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";
import { memorySessionStoresModule } from "#/user-sessions/modules/memory.mjs";

const modules = (...names: string[]) => names.map((name) => ({ name }));

/**
 * #455: a module that says so on its own manifest, the way a composition
 * root's module does — the guard has never heard its name.
 */
const declaring = (name: string, reason = `${name} forks per replica — a test consequence`) => ({
	name,
	replicaSafety: { unsafe: true as const, reason },
});

const logger = () => {
	const warn = vi.fn();
	return { logger: { warn } as never, warn };
};

describe("checkReplicaSafety — multi mode fails closed", () => {
	it("throws when a replica-unsafe module is wired in multi mode", () => {
		const { logger: log } = logger();
		expect(() =>
			checkReplicaSafety({
				modules: modules("memorySessionStores", "oauth"),
				config: { deployment: { mode: "multi" } },
				logger: log,
			}),
		).toThrow(BootError);
	});

	it("names every offending module, not just the first", () => {
		const { logger: log } = logger();
		try {
			checkReplicaSafety({
				modules: modules("memorySessionStores", "core-rate-limiter-memory", "oauth"),
				config: { deployment: { mode: "multi" } },
				logger: log,
			});
			expect.unreachable("should have thrown");
		} catch (err) {
			expect(err).toBeInstanceOf(BootError);
			const details = (err as BootError).details;
			expect(details.reason).toBe("replica-unsafe-adapter");
			// Narrow through the discriminant rather than casting: if the union
			// member is ever renamed this fails to compile instead of silently
			// asserting nothing.
			if (details.reason !== "replica-unsafe-adapter") expect.unreachable("wrong reason");
			expect(details.modules).toEqual(
				expect.arrayContaining(["memorySessionStores", "core-rate-limiter-memory"]),
			);
		}
	});

	it("boots cleanly in multi mode when nothing replica-unsafe is wired", () => {
		const { logger: log, warn } = logger();
		expect(() =>
			checkReplicaSafety({
				modules: modules("redisSessionStores", "redis-rate-limiter", "oauth"),
				config: { deployment: { mode: "multi" } },
				logger: log,
			}),
		).not.toThrow();
		expect(warn).not.toHaveBeenCalled();
	});
});

describe("checkReplicaSafety — three states", () => {
	it("warns when the mode is unset", () => {
		// The operator has not said which shape this deployment is. That is the
		// state the issue's 3am scenario starts from, so it is the one that has
		// to be loud.
		const { logger: log, warn } = logger();
		checkReplicaSafety({
			modules: modules("memorySessionStores"),
			config: {},
			logger: log,
		});
		expect(warn).toHaveBeenCalledOnce();
		const [, message] = warn.mock.calls[0] as [unknown, string];
		expect(message).toBe("replica_unsafe_adapters");
	});

	it("stays silent when the operator declared single mode", () => {
		// An explicit declaration is an answer. Warning anyway would train
		// operators to ignore the warning that matters.
		const { logger: log, warn } = logger();
		checkReplicaSafety({
			modules: modules("memorySessionStores"),
			config: { deployment: { mode: "single" } },
			logger: log,
		});
		expect(warn).not.toHaveBeenCalled();
	});

	it("stays silent when the mode is unset but nothing unsafe is wired", () => {
		const { logger: log, warn } = logger();
		checkReplicaSafety({ modules: modules("redisSessionStores"), config: {}, logger: log });
		expect(warn).not.toHaveBeenCalled();
	});

	it("warns once, listing every offending module together", () => {
		const { logger: log, warn } = logger();
		checkReplicaSafety({
			modules: modules("memorySessionStores", "core-access-token-denylist-memory"),
			config: {},
			logger: log,
		});
		expect(warn).toHaveBeenCalledOnce();
		const [fields] = warn.mock.calls[0] as [{ modules: string[] }, string];
		expect(fields.modules).toHaveLength(2);
	});

	it("does not treat an inherited Object key as a replica-unsafe module", () => {
		// `name in reasons` walks the prototype chain, so a module named
		// "toString" or "constructor" would match and then carry a function
		// where the reason text should be.
		const { logger: log, warn } = logger();
		checkReplicaSafety({
			modules: modules("toString", "constructor", "valueOf", "hasOwnProperty"),
			config: {},
			logger: log,
		});
		expect(warn).not.toHaveBeenCalled();
	});

	it("does not fail boot in multi mode on an inherited Object key", () => {
		const { logger: log } = logger();
		expect(() =>
			checkReplicaSafety({
				modules: modules("toString"),
				config: { deployment: { mode: "multi" } },
				logger: log,
			}),
		).not.toThrow();
	});

	it("does not require a logger", () => {
		expect(() =>
			checkReplicaSafety({ modules: modules("memorySessionStores"), config: {} }),
		).not.toThrow();
	});
});

describe("REPLICA_UNSAFE_MODULES", () => {
	it("covers the stores whose divergence is a security failure, not just a nuisance", () => {
		// The issue named the session stores and the rate limiter. These two are
		// worse and were not named: a revoked access token staying valid on
		// other replicas, and DPoP proof-replay detection forking per replica.
		expect(REPLICA_UNSAFE_MODULES).toContain("core-access-token-denylist-memory");
		expect(REPLICA_UNSAFE_MODULES).toContain("core-replay-seen-set-memory");
	});

	it("covers the two the issue named", () => {
		expect(REPLICA_UNSAFE_MODULES).toContain("memorySessionStores");
		expect(REPLICA_UNSAFE_MODULES).toContain("core-rate-limiter-memory");
	});
});

// ---------------------------------------------------------------------------
// #455: the declaration lives on the manifest, not in a table of names
// ---------------------------------------------------------------------------

describe("checkReplicaSafety — modules that declare replicaSafety on their manifest (#455)", () => {
	// The standalone template wires its own in-memory modules
	// (`standalone:in-memory-session-stores`, …) under names the core table
	// had never heard of, so `deployment.mode = "multi"` booted with them.
	// A module's manifest is where it says what it holds; the guard reads it.

	it("refuses a declaring module in multi mode, naming it", () => {
		const { logger: log } = logger();
		try {
			checkReplicaSafety({
				modules: [declaring("standalone:in-memory-session-stores"), ...modules("oauth")],
				config: { deployment: { mode: "multi" } },
				logger: log,
			});
			expect.unreachable("should have thrown");
		} catch (err) {
			expect(err).toBeInstanceOf(BootError);
			const details = (err as BootError).details;
			if (details.reason !== "replica-unsafe-adapter") expect.unreachable("wrong reason");
			expect(details.modules).toEqual(["standalone:in-memory-session-stores"]);
		}
	});

	it("quotes the declared reason into the refusal, like a table entry's", () => {
		const { logger: log } = logger();
		expect(() =>
			checkReplicaSafety({
				modules: [declaring("test:holds-state", "authorization codes are not shared")],
				config: { deployment: { mode: "multi" } },
				logger: log,
			}),
		).toThrow(/test:holds-state: authorization codes are not shared/);
	});

	it("warns about a declaring module when the mode is unset", () => {
		const { logger: log, warn } = logger();
		checkReplicaSafety({
			modules: [declaring("test:holds-state", "a consequence an operator can act on")],
			config: {},
			logger: log,
		});
		expect(warn).toHaveBeenCalledOnce();
		const [fields, message] = warn.mock.calls[0] as [
			{ modules: string[]; reasons: string[] },
			string,
		];
		expect(message).toBe("replica_unsafe_adapters");
		expect(fields.modules).toEqual(["test:holds-state"]);
		expect(fields.reasons).toEqual(["test:holds-state: a consequence an operator can act on"]);
	});

	it("stays silent about a declaring module in single mode", () => {
		const { logger: log, warn } = logger();
		checkReplicaSafety({
			modules: [declaring("test:holds-state")],
			config: { deployment: { mode: "single" } },
			logger: log,
		});
		expect(warn).not.toHaveBeenCalled();
	});

	it("names declaring modules and bundled modules together, in manifest order", () => {
		const { logger: log } = logger();
		try {
			checkReplicaSafety({
				modules: [
					...modules("memorySessionStores"),
					declaring("standalone:in-memory-code-repository"),
					...modules("oauth"),
				],
				config: { deployment: { mode: "multi" } },
				logger: log,
			});
			expect.unreachable("should have thrown");
		} catch (err) {
			const details = (err as BootError).details;
			if (details.reason !== "replica-unsafe-adapter") expect.unreachable("wrong reason");
			expect(details.modules).toEqual([
				"memorySessionStores",
				"standalone:in-memory-code-repository",
			]);
		}
	});

	it("does not refuse a module whose manifest carries no declaration", () => {
		const { logger: log, warn } = logger();
		expect(() =>
			checkReplicaSafety({
				modules: [{ name: "redis-federation-token-store" }],
				config: { deployment: { mode: "multi" } },
				logger: log,
			}),
		).not.toThrow();
		expect(warn).not.toHaveBeenCalled();
	});
});

describe("replicaUnsafeReason — reads the manifest (#455)", () => {
	it("returns the declared reason for a declaring module", () => {
		expect(replicaUnsafeReason(declaring("test:holds-state", "codes are not shared"))).toBe(
			"codes are not shared",
		);
	});

	it("returns the bundled module's own declaration", () => {
		// The nine bundled modules carry their reason on themselves now, so a
		// composition root reusing the wording gets it from the manifest.
		expect(replicaUnsafeReason(memorySessionStoresModule)).toBe(
			memorySessionStoresModule.replicaSafety?.reason,
		);
		expect(replicaUnsafeReason(memorySessionStoresModule)).toMatch(/back-channel logout/);
	});

	it("is undefined for a module that declares nothing", () => {
		expect(replicaUnsafeReason({ name: "redis-federation-token-store" })).toBeUndefined();
		expect(replicaUnsafeReason({ name: "toString" })).toBeUndefined();
	});
});

// ---------------------------------------------------------------------------
// The seam: the guard has to actually run during boot, not merely exist
// ---------------------------------------------------------------------------

describe("checkReplicaSafety — wired into boot", () => {
	const boot = (mode?: "single" | "multi", logger?: unknown) =>
		({
			config: {
				...makeValidCoreConfig(),
				...(mode === undefined ? {} : { deployment: { mode } }),
			} as never,
			pathResolver: (s: string) => s,
			...(logger === undefined ? {} : { logger }),
		}) satisfies Record<string, unknown> as BootstrapMap;

	it("fails boot in multi mode when a memory session-store module is installed", async () => {
		await expect(
			createApp({
				modules: [memorySessionStoresModule],
				bootstrapComponents: boot("multi"),
			}),
		).rejects.toMatchObject({ reason: "replica-unsafe-adapter" });
	});

	it("boots in single mode with the same modules", async () => {
		await expect(
			createApp({
				modules: [memorySessionStoresModule],
				bootstrapComponents: boot("single"),
			}),
		).resolves.toBeDefined();
	});

	it("warns through the bootstrap logger when the mode is unset", async () => {
		const warn = vi.fn();
		await createApp({
			modules: [memorySessionStoresModule],
			bootstrapComponents: boot(undefined, {
				warn,
				info: vi.fn(),
				error: vi.fn(),
				debug: vi.fn(),
				trace: vi.fn(),
				fatal: vi.fn(),
				child: vi.fn(),
			}),
		});
		expect(warn).toHaveBeenCalledWith(
			expect.objectContaining({ modules: ["memorySessionStores"] }),
			"replica_unsafe_adapters",
		);
	});

	// #455: a composition root's own module, under a name core has never
	// seen, declaring what it holds. Exactly the shape the standalone's
	// `standalone:in-memory-session-stores` takes.
	const holdsStateModule = defineModule({
		name: "test:holds-state",
		replicaSafety: {
			unsafe: true,
			reason:
				"authorization codes are not shared — a code issued on one replica is unknown to the others",
		},
	});

	it("fails boot in multi mode when a module declaring replicaSafety is installed", async () => {
		await expect(
			createApp({
				modules: [holdsStateModule],
				bootstrapComponents: boot("multi"),
			}),
		).rejects.toMatchObject({
			reason: "replica-unsafe-adapter",
			details: { modules: ["test:holds-state"] },
		});
	});

	it("boots the declaring module in single mode", async () => {
		await expect(
			createApp({
				modules: [holdsStateModule],
				bootstrapComponents: boot("single"),
			}),
		).resolves.toBeDefined();
	});

	it("warns about the declaring module through the bootstrap logger when the mode is unset", async () => {
		const warn = vi.fn();
		await createApp({
			modules: [holdsStateModule],
			bootstrapComponents: boot(undefined, {
				warn,
				info: vi.fn(),
				error: vi.fn(),
				debug: vi.fn(),
				trace: vi.fn(),
				fatal: vi.fn(),
				child: vi.fn(),
			}),
		});
		expect(warn).toHaveBeenCalledWith(
			expect.objectContaining({
				modules: ["test:holds-state"],
				reasons: [expect.stringContaining("authorization codes are not shared")],
			}),
			"replica_unsafe_adapters",
		);
	});
});
