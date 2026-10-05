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
 * The replica-safety guard. `rateLimiter.adapter` and
 * `userSessionStores.adapter` default to `"memory"`, whose state forks per
 * replica: back-channel logout reaches only one replica and a "logged out"
 * session stays valid on the others, and rate limits multiply by replica
 * count.
 *
 * The guard reads the *installed modules* rather than the config: that is what
 * is actually wired, it survives a hand-built config, and it covers stores the
 * config switches do not name (a memory access-token denylist means a revoked
 * token stays valid on every other replica).
 */

import { describe, expect, it, vi } from "vitest";
import { z } from "zod";
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
 * A module that says so on its own manifest, the way a composition root's
 * module does: the guard has never heard its name.
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
				modules: modules("core-session-stores-memory", "oauth"),
				config: { core: { deployment: { mode: "multi" } } },
				logger: log,
			}),
		).toThrow(BootError);
	});

	it("names every offending module, not just the first", () => {
		const { logger: log } = logger();
		try {
			checkReplicaSafety({
				modules: modules("core-session-stores-memory", "core-rate-limiter-memory", "oauth"),
				config: { core: { deployment: { mode: "multi" } } },
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
				expect.arrayContaining(["core-session-stores-memory", "core-rate-limiter-memory"]),
			);
		}
	});

	it("boots cleanly in multi mode when nothing replica-unsafe is wired", () => {
		const { logger: log, warn } = logger();
		expect(() =>
			checkReplicaSafety({
				modules: modules("redis-session-stores", "redis-rate-limiter", "oauth"),
				config: { core: { deployment: { mode: "multi" } } },
				logger: log,
			}),
		).not.toThrow();
		expect(warn).not.toHaveBeenCalled();
	});
});

describe("checkReplicaSafety — three states", () => {
	it("warns when the mode is unset", () => {
		// The operator has not said which shape this deployment is. That is the
		// state an unnoticed scale-out starts from, so it is the one that has to
		// be loud.
		const { logger: log, warn } = logger();
		checkReplicaSafety({
			modules: modules("core-session-stores-memory"),
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
			modules: modules("core-session-stores-memory"),
			config: { core: { deployment: { mode: "single" } } },
			logger: log,
		});
		expect(warn).not.toHaveBeenCalled();
	});

	it("stays silent when the mode is unset but nothing unsafe is wired", () => {
		const { logger: log, warn } = logger();
		checkReplicaSafety({ modules: modules("redis-session-stores"), config: {}, logger: log });
		expect(warn).not.toHaveBeenCalled();
	});

	it("warns once, listing every offending module together", () => {
		const { logger: log, warn } = logger();
		checkReplicaSafety({
			modules: modules("core-session-stores-memory", "core-access-token-denylist-memory"),
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
				config: { core: { deployment: { mode: "multi" } } },
				logger: log,
			}),
		).not.toThrow();
	});

	it("does not require a logger", () => {
		expect(() =>
			checkReplicaSafety({ modules: modules("core-session-stores-memory"), config: {} }),
		).not.toThrow();
	});
});

describe("REPLICA_UNSAFE_MODULES", () => {
	it("covers the stores whose divergence is a security failure, not just a nuisance", () => {
		// Worse than the session stores and the rate limiter: a revoked access
		// token staying valid on other replicas, and DPoP proof-replay detection
		// forking per replica.
		expect(REPLICA_UNSAFE_MODULES).toContain("core-access-token-denylist-memory");
		expect(REPLICA_UNSAFE_MODULES).toContain("core-replay-seen-set-memory");
	});

	it("covers the two the issue named", () => {
		expect(REPLICA_UNSAFE_MODULES).toContain("core-session-stores-memory");
		expect(REPLICA_UNSAFE_MODULES).toContain("core-rate-limiter-memory");
	});
});

// ---------------------------------------------------------------------------
// The declaration lives on the manifest, not in a table of names
// ---------------------------------------------------------------------------

describe("checkReplicaSafety — modules that declare replicaSafety on their manifest", () => {
	// A composition root wires its own in-memory modules (the standalone
	// template's `standalone-in-memory-session-stores`, …) under names core has
	// never heard of. A module's manifest is where it says what it holds; the
	// guard reads it.

	it("refuses a declaring module in multi mode, naming it", () => {
		const { logger: log } = logger();
		try {
			checkReplicaSafety({
				modules: [declaring("standalone-in-memory-session-stores"), ...modules("oauth")],
				config: { core: { deployment: { mode: "multi" } } },
				logger: log,
			});
			expect.unreachable("should have thrown");
		} catch (err) {
			expect(err).toBeInstanceOf(BootError);
			const details = (err as BootError).details;
			if (details.reason !== "replica-unsafe-adapter") expect.unreachable("wrong reason");
			expect(details.modules).toEqual(["standalone-in-memory-session-stores"]);
		}
	});

	it("quotes the declared reason into the refusal, like a table entry's", () => {
		const { logger: log } = logger();
		expect(() =>
			checkReplicaSafety({
				modules: [declaring("test:holds-state", "authorization codes are not shared")],
				config: { core: { deployment: { mode: "multi" } } },
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
			config: { core: { deployment: { mode: "single" } } },
			logger: log,
		});
		expect(warn).not.toHaveBeenCalled();
	});

	it("names declaring modules and bundled modules together, in manifest order", () => {
		const { logger: log } = logger();
		try {
			checkReplicaSafety({
				modules: [
					...modules("core-session-stores-memory"),
					declaring("standalone-in-memory-code-repository"),
					...modules("oauth"),
				],
				config: { core: { deployment: { mode: "multi" } } },
				logger: log,
			});
			expect.unreachable("should have thrown");
		} catch (err) {
			const details = (err as BootError).details;
			if (details.reason !== "replica-unsafe-adapter") expect.unreachable("wrong reason");
			expect(details.modules).toEqual([
				"core-session-stores-memory",
				"standalone-in-memory-code-repository",
			]);
		}
	});

	it("does not refuse a module whose manifest carries no declaration", () => {
		const { logger: log, warn } = logger();
		expect(() =>
			checkReplicaSafety({
				modules: [{ name: "redis-federation-token-store" }],
				config: { core: { deployment: { mode: "multi" } } },
				logger: log,
			}),
		).not.toThrow();
		expect(warn).not.toHaveBeenCalled();
	});
});

describe("replicaUnsafeReason — reads the manifest", () => {
	it("returns the declared reason for a declaring module", () => {
		expect(replicaUnsafeReason(declaring("test:holds-state", "codes are not shared"))).toBe(
			"codes are not shared",
		);
	});

	it("returns the bundled module's own declaration", () => {
		// The bundled modules carry their reason on themselves, so a
		// composition root reusing the wording gets it from the manifest.
		expect(memorySessionStoresModule.replicaSafety).toMatchObject({
			unsafe: true,
			reason: replicaUnsafeReason(memorySessionStoresModule),
		});
		expect(replicaUnsafeReason(memorySessionStoresModule)).toMatch(/back-channel logout/);
		// The reason states what forks, with no issue number.
		expect(replicaUnsafeReason(memorySessionStoresModule)).not.toMatch(/#\d/);
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
				...(mode === undefined ? {} : { core: { deployment: { mode } } }),
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
			expect.objectContaining({ modules: ["core-session-stores-memory"] }),
			"replica_unsafe_adapters",
		);
	});

	// A composition root's own module, under a name core has never seen,
	// declaring what it holds. Exactly the shape the standalone's
	// `standalone-in-memory-session-stores` takes.
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

// ---------------------------------------------------------------------------
// A declaration made from the module's own section
// ---------------------------------------------------------------------------

describe("replicaSafety declared from the module's own section", () => {
	// A module whose storage is configuration declares the replica safety of
	// the store its section selects: unsafe for one value, nothing for another.
	const StoreSection = z.object({ enabled: z.boolean().optional(), store: z.string() }).strict();
	const MEMORY_REASON =
		"the store is in this process's memory — a value written on one replica is unknown to the others";

	const selecting = (
		replicaSafety: (
			section: z.output<typeof StoreSection>,
		) => { readonly unsafe: true; readonly reason: string } | undefined = (section) =>
			section.store === "memory" ? { unsafe: true, reason: MEMORY_REASON } : undefined,
	) =>
		defineModule({
			name: "section-store",
			section: {
				schema: StoreSection,
				isEnabled: (section) => section.enabled !== false,
			},
			replicaSafety,
		});

	const bootWith = (
		section: Record<string, unknown>,
		mode?: "single" | "multi",
		logger?: unknown,
	): BootstrapMap =>
		({
			config: {
				...makeValidCoreConfig(),
				...(mode === undefined ? {} : { core: { deployment: { mode } } }),
				"section-store": section,
			} as never,
			pathResolver: (s: string) => s,
			...(logger === undefined ? {} : { logger }),
		}) satisfies Record<string, unknown> as BootstrapMap;

	const bootLogger = (warn: ReturnType<typeof vi.fn>) => ({
		warn,
		info: vi.fn(),
		error: vi.fn(),
		debug: vi.fn(),
		trace: vi.fn(),
		fatal: vi.fn(),
		child: vi.fn(),
	});

	it("refuses boot in multi mode for the section value it declares unsafe, quoting its reason", async () => {
		await expect(
			createApp({
				modules: [selecting()],
				bootstrapComponents: bootWith({ store: "memory" }, "multi"),
			}),
		).rejects.toMatchObject({
			reason: "replica-unsafe-adapter",
			details: { modules: ["section-store"] },
			message: expect.stringContaining(`section-store: ${MEMORY_REASON}`),
		});
	});

	it("boots in multi mode for the section value it declares nothing for", async () => {
		const handle = await createApp({
			modules: [selecting()],
			bootstrapComponents: bootWith({ store: "shared" }, "multi"),
		});
		await handle.dispose();
	});

	it("warns, as a static declaration does, when the mode is unset", async () => {
		const warn = vi.fn();
		const handle = await createApp({
			modules: [selecting()],
			bootstrapComponents: bootWith({ store: "memory" }, undefined, bootLogger(warn)),
		});
		expect(warn).toHaveBeenCalledWith(
			{ modules: ["section-store"], reasons: [`section-store: ${MEMORY_REASON}`] },
			"replica_unsafe_adapters",
		);
		await handle.dispose();
	});

	it("is silent, as a static declaration is, in single mode", async () => {
		const warn = vi.fn();
		const handle = await createApp({
			modules: [selecting()],
			bootstrapComponents: bootWith({ store: "memory" }, "single", bootLogger(warn)),
		});
		expect(warn).not.toHaveBeenCalledWith(expect.anything(), "replica_unsafe_adapters");
		await handle.dispose();
	});

	it("is handed the parsed section, once", async () => {
		const declare = vi.fn((_section: z.output<typeof StoreSection>) => undefined);
		const handle = await createApp({
			modules: [selecting(declare)],
			bootstrapComponents: bootWith({ store: "shared" }, "multi"),
		});
		expect(declare).toHaveBeenCalledOnce();
		expect(declare).toHaveBeenCalledWith({ store: "shared" });
		await handle.dispose();
	});

	it("is not called for a module its section switches off", async () => {
		const declare = vi.fn((_section: z.output<typeof StoreSection>) => ({
			unsafe: true as const,
			reason: MEMORY_REASON,
		}));
		const handle = await createApp({
			modules: [selecting(declare)],
			bootstrapComponents: bootWith({ enabled: false, store: "memory" }, "multi"),
		});
		expect(declare).not.toHaveBeenCalled();
		await handle.dispose();
	});

	it("refuses boot naming the module when it throws, in any mode", async () => {
		for (const mode of ["single", "multi", undefined] as const) {
			await expect(
				createApp({
					modules: [
						selecting(() => {
							throw new Error("cannot tell");
						}),
					],
					bootstrapComponents: bootWith({ store: "memory" }, mode),
				}),
			).rejects.toMatchObject({
				reason: "config-validation-failed",
				details: { modules: [{ module: "section-store", schemaPath: "section-store" }] },
				message: expect.stringMatching(
					/module "section-store"'s replicaSafety .*it threw: .*cannot tell/,
				),
			});
		}
	});

	it.each([
		["a string", "unsafe"],
		["null", null],
		["no reason", { unsafe: true }],
		["an empty reason", { unsafe: true, reason: "" }],
		["unsafe false", { unsafe: false, reason: MEMORY_REASON }],
	])("refuses boot naming the module when it answers %s", async (_label, answer) => {
		await expect(
			createApp({
				modules: [selecting(() => answer as never)],
				bootstrapComponents: bootWith({ store: "memory" }, "single"),
			}),
		).rejects.toMatchObject({
			reason: "config-validation-failed",
			details: { modules: [{ module: "section-store", schemaPath: "section-store" }] },
			message: expect.stringContaining(`module "section-store"'s replicaSafety`),
		});
	});

	it("hands a module without a section undefined", async () => {
		const declare = vi.fn(() => ({ unsafe: true as const, reason: MEMORY_REASON }));
		await expect(
			createApp({
				modules: [defineModule({ name: "sectionless-store", replicaSafety: declare })],
				bootstrapComponents: bootWith({ store: "shared" }, "multi"),
			}),
		).rejects.toMatchObject({
			reason: "replica-unsafe-adapter",
			details: { modules: ["sectionless-store"] },
		});
		expect(declare).toHaveBeenCalledExactlyOnceWith(undefined);
	});

	it("replicaUnsafeReason answers for the section it is handed", () => {
		const module = selecting();
		expect(replicaUnsafeReason(module, { store: "memory" })).toBe(MEMORY_REASON);
		expect(replicaUnsafeReason(module, { store: "shared" })).toBeUndefined();
	});
});
