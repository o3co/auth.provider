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
 * Orchestrator-level tests for `createApp`: a minimal manifest resolves to an
 * `AppHandle`, and each stage's representative error reaches the caller with
 * the correct `stage` (validateManifests, planBoot, materializeComponents,
 * applyContributions, assembleApp).
 */

import { describe, expect, it, vi } from "vitest";
import { createAdapterFactory, type LifecycleRegistrar } from "#/adapters/AdapterFactory.mjs";
import type { Logger } from "#/logging/Logger.mjs";
import { defineModule } from "../../modules/manifest/index.mjs";
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import { createApp, mergeWithBuiltins } from "../create-app.mjs";
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

/**
 * Build an adapter through a real `AdapterFactory` on the boot planner's
 * registrar, as an adapter that opens a connection does, whose registered
 * cleanup (the connection's close) throws.
 */
async function buildAdapterWhoseCloseThrows(
	lifecycle: LifecycleRegistrar | undefined,
): Promise<number> {
	const factory = createAdapterFactory<{ readonly name: string }>("Mock", {
		...(lifecycle === undefined ? {} : { lifecycle }),
	});
	factory.register("closing", (_config, ctx) => {
		ctx.lifecycle?.register(async () => {
			throw new Error("close failed", { cause: new Error("socket gone") });
		});
		return { name: "closing" };
	});
	await factory.create({ type: "closing" });
	return 1;
}

/** The `loggableError` projection of `buildAdapterWhoseCloseThrows`' failure. */
const projectedCloseFailure = expect.objectContaining({
	name: "Error",
	detail: "close failed",
	cause: expect.objectContaining({ name: "Error", detail: "socket gone" }),
});

/** A module whose adapter registers a close that throws. */
const adapterWhoseCloseThrowsModule = () =>
	defineModule<never, "lifecycleRegistrar">({
		name: "AdapterMod-close-throws",
		optional: ["lifecycleRegistrar"],
		provides: {
			slotCA: (deps) => buildAdapterWhoseCloseThrows(deps.lifecycleRegistrar),
		},
		lifecycle: { slotCA: { eager: true } },
	});

/** A module whose provider throws at stage 3, so boot fails after the adapter was built. */
const failingModule = () =>
	defineModule({
		name: "FailMod",
		provides: {
			slotCB: async () => {
				throw new Error("stage-3-boom");
			},
		},
		lifecycle: { slotCB: { eager: true } },
	});

/** A spy for every `Logger` method, so a test can say nothing was logged at another level. */
function spyLogger() {
	return {
		trace: vi.fn(),
		debug: vi.fn(),
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		fatal: vi.fn(),
		child: vi.fn(),
	};
}

/** Silenced spies on every console method a `consoleLogger` level routes to. */
function spyConsole() {
	const spies = {
		error: vi.spyOn(console, "error").mockImplementation(() => {}),
		warn: vi.spyOn(console, "warn").mockImplementation(() => {}),
		info: vi.spyOn(console, "info").mockImplementation(() => {}),
		debug: vi.spyOn(console, "debug").mockImplementation(() => {}),
		log: vi.spyOn(console, "log").mockImplementation(() => {}),
	};
	return {
		...spies,
		restore: () => {
			for (const spy of Object.values(spies)) spy.mockRestore();
		},
	};
}

/**
 * The one line a failed adapter cleanup logs, at error: object-first, the
 * event name, the phase that drained it and the projected error — and
 * nothing after.
 */
function expectOneCleanupFailureLine(
	calls: readonly unknown[][],
	phase: "boot_failure" | "dispose",
): void {
	expect(calls).toHaveLength(1);
	const [fields, event, ...rest] = calls[0] as unknown[];
	expect(event).toBe("adapter_lifecycle_cleanup_failed");
	expect(rest).toEqual([]);
	expect(fields).toEqual({ phase, cleanupIndex: 0, err: projectedCloseFailure });
	expect((fields as { err: unknown }).err).not.toBeInstanceOf(Error);
}

// Per ADR 2026-04-30-config-schema-strict-defaults-from-hocon, defaults live
// in HOCON and validateAndComposeConfig parses CoreConfigSchema, so the
// fixture supplies a minimal schema-valid baseline (it diverges from
// reference.conf on purpose; see makeValidCoreConfig).
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

/**
 * Stub ContributionCollectorMap for tests that do not exercise contribution
 * kinds. `mfaFactors` and `sessionRequirements` are left to the built-in
 * collectors: a host collector for either is refused by `createApp` before
 * the kinds are merged (`session-requirement-kind-guarded`; see ADR
 * 2026-09-28-session-admission). So are `auditHooks`, `federations` and
 * `federationRedirectPolicies`, the planner's own (`contribution-kind-guarded`).
 */
function makeStubCollectors(): ContributionCollectorMap {
	return {
		grants: makeStubNameCollector(),
		tokenExchangeValidators: makeStubNameCollector(),
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
		// AppHandle is frozen
		expect(Object.isFrozen(handle)).toBe(true);
		// components map is accessible and contains the bootstrap keys
		expect(handle.components).toBeDefined();
		// config is the parsed (CoreConfigSchema-validated) result, not the raw
		// bootstrap reference (see validateAndComposeConfig). The refresh-token
		// lifetime comes from the makeValidCoreConfig fixture: the schema carries
		// no default.
		expect(
			(handle.components.config as { oauth: { refreshToken: { expiresIn: number } } }).oauth
				.refreshToken.expiresIn,
		).toBe(86400);
		expect(handle.components.pathResolver).toBe(minBoot.pathResolver);
		// The slot provided by the module is materialised (eager activation)
		expect(handle.components.slotCA).toBe(42);
		expect(handle.router).toBeDefined();
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
		// config is the parsed (CoreConfigSchema-validated) result, not the raw
		// bootstrap reference (see validateAndComposeConfig). The refresh-token
		// lifetime comes from the makeValidCoreConfig fixture: the schema carries
		// no default.
		expect(
			(handle.components.config as { oauth: { refreshToken: { expiresIn: number } } }).oauth
				.refreshToken.expiresIn,
		).toBe(86400);
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

// ---------------------------------------------------------------------------
// 6b. A refusal after stage 3 runs the providers' lifecycle cleanups once
// ---------------------------------------------------------------------------

describe("createApp — 6b. a refusal after stage 3 runs the providers' lifecycle cleanups", () => {
	/**
	 * Two providers whose lifecycle cleanups record their names, materialised
	 * A then B (B requires A's slot).
	 */
	function providersWithCleanups(cleaned: string[]): ReturnType<typeof defineModule>[] {
		return [
			defineModule({
				name: "ProvA",
				provides: { slotCA: () => 1 },
				lifecycle: { slotCA: { eager: true, cleanup: () => void cleaned.push("A") } },
			}),
			defineModule({
				name: "ProvB",
				requires: ["slotCA"] as never,
				provides: { slotCB: () => "b" },
				lifecycle: { slotCB: { eager: true, cleanup: () => void cleaned.push("B") } },
			}),
		];
	}

	const routeOf = (id: string, before: string) => ({
		mountPath: `/${id}`,
		handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
		id,
		before: [before],
	});

	it.each([
		{
			stage: "assembleApp",
			reason: "route-order-cycle",
			modules: [
				defineModule({
					name: "RoutesCycleMod",
					contributes: {
						routes: [routeOf("route-a", "route-b"), routeOf("route-b", "route-a")],
					},
				}),
			],
		},
		{
			stage: "applyContributions",
			reason: "override-target-missing",
			// Stage 1 sees the target contributed; the pre-scan finds it switched off.
			modules: [
				defineModule({
					name: "GrantsOwner",
					contributes: { grants: { "urn:off": () => null } },
				}),
				defineModule({
					name: "Overrider",
					overrides: {
						grants: { "urn:off": () => ({ handle: async () => ({}) }) as never },
					},
				}),
			],
		},
		{
			stage: "applyContributions",
			reason: "contribute-factory-failed",
			modules: [
				defineModule({
					name: "FailContribMod",
					contributes: {
						grants: {
							"urn:fail-grant": () => {
								throw new Error("contribution boom");
							},
						},
					},
				}),
			],
		},
	])("$stage $reason: each cleanup runs once, in reverse", async ({ stage, reason, modules }) => {
		const cleaned: string[] = [];

		const promise = createApp({
			modules: [...providersWithCleanups(cleaned), ...modules],
			bootstrapComponents: minBoot,
		});

		await expect(promise).rejects.toMatchObject({ reason, stage });
		expect(cleaned).toEqual(["B", "A"]);
	});
});

// ---------------------------------------------------------------------------
// 7. Boot-failure LifecycleRegistrar drain
// ---------------------------------------------------------------------------

describe("createApp — 7. boot-failure LifecycleRegistrar drain", () => {
	it("registered cleanups run when a later stage fails", async () => {
		let cleanupRan = false;

		// Module A: registers a cleanup with the lifecycle registrar via
		// optional dep, then succeeds. Module B: throws at materialization
		// time, triggering the boot-failure path. Use the same `slotCA`/`slotCB`
		// keys declared at the top of this file.
		const okMod = defineModule<never, "lifecycleRegistrar">({
			name: "OkMod-with-cleanup",
			optional: ["lifecycleRegistrar"],
			provides: {
				slotCA: async (deps) => {
					deps.lifecycleRegistrar?.register(async () => {
						cleanupRan = true;
					});
					return 1;
				},
			},
			lifecycle: {
				slotCA: { eager: true },
			},
		});
		const failMod = defineModule({
			name: "FailMod",
			provides: {
				slotCB: async () => {
					throw new Error("stage-3-boom");
				},
			},
			lifecycle: {
				slotCB: { eager: true },
			},
		});

		const promise = createApp({
			modules: [okMod, failMod],
			bootstrapComponents: minBoot,
			contributionKinds: makeStubCollectors(),
		});

		await expect(promise).rejects.toBeInstanceOf(BootError);
		// The boot-failure path drained the registrar even though assembleApp
		// was never reached.
		expect(cleanupRan).toBe(true);
	});

	it("logs a cleanup that throws once, through the bootstrap logger, marked boot_failure", async () => {
		// A composition root that has a logger hands it in as a bootstrap
		// component, and it is there when a later stage throws.
		const logger = spyLogger();
		const console_ = spyConsole();
		try {
			await expect(
				createApp({
					modules: [adapterWhoseCloseThrowsModule(), failingModule()],
					bootstrapComponents: { ...minBoot, logger: logger as unknown as Logger },
					contributionKinds: makeStubCollectors(),
				}),
			).rejects.toBeInstanceOf(BootError);

			expectOneCleanupFailureLine(logger.error.mock.calls, "boot_failure");
			for (const level of ["trace", "debug", "info", "warn", "fatal"] as const) {
				expect(logger[level]).not.toHaveBeenCalled();
			}
			for (const method of ["error", "warn", "info", "debug", "log"] as const) {
				expect(console_[method]).not.toHaveBeenCalled();
			}
		} finally {
			console_.restore();
		}
	});

	it("logs it through consoleLogger when no bootstrap logger was given: one console.error, object-first", async () => {
		const console_ = spyConsole();
		try {
			await expect(
				createApp({
					modules: [adapterWhoseCloseThrowsModule(), failingModule()],
					bootstrapComponents: minBoot,
					contributionKinds: makeStubCollectors(),
				}),
			).rejects.toBeInstanceOf(BootError);

			expectOneCleanupFailureLine(console_.error.mock.calls, "boot_failure");
			for (const method of ["warn", "info", "debug", "log"] as const) {
				expect(console_[method]).not.toHaveBeenCalled();
			}
		} finally {
			console_.restore();
		}
	});

	it("logs it through a logger handed in as an override", async () => {
		// `dispose()` logs through an override logger; a failed boot must too.
		// (A logger in both channels is refused at stage 1, before any adapter
		// is built.)
		const logger = spyLogger();
		const console_ = spyConsole();
		try {
			await expect(
				createApp({
					modules: [adapterWhoseCloseThrowsModule(), failingModule()],
					bootstrapComponents: minBoot,
					overrideComponents: { logger: logger as unknown as Logger },
					contributionKinds: makeStubCollectors(),
				}),
			).rejects.toBeInstanceOf(BootError);

			expectOneCleanupFailureLine(logger.error.mock.calls, "boot_failure");
			for (const level of ["trace", "debug", "info", "warn", "fatal"] as const) {
				expect(logger[level]).not.toHaveBeenCalled();
			}
			for (const method of ["error", "warn", "info", "debug", "log"] as const) {
				expect(console_[method]).not.toHaveBeenCalled();
			}
		} finally {
			console_.restore();
		}
	});

	it("runs every remaining cleanup and rethrows the error that failed boot when the logger itself throws", async () => {
		// A logger that cannot log must not cost a cleanup, nor replace the
		// boot failure the caller is owed with its own.
		const ran: string[] = [];
		const logger = spyLogger();
		logger.error.mockImplementation(() => {
			throw new Error("log sink down");
		});
		const twoCleanupsModule = defineModule<never, "lifecycleRegistrar">({
			name: "TwoCleanupsMod",
			optional: ["lifecycleRegistrar"],
			provides: {
				slotCA: async (deps) => {
					deps.lifecycleRegistrar?.register(async () => {
						ran.push("registered-first");
					});
					deps.lifecycleRegistrar?.register(async () => {
						throw new Error("close failed");
					});
					return 1;
				},
			},
			lifecycle: { slotCA: { eager: true } },
		});

		const failure = await createApp({
			modules: [twoCleanupsModule, failingModule()],
			bootstrapComponents: { ...minBoot, logger: logger as unknown as Logger },
			contributionKinds: makeStubCollectors(),
		}).then(
			() => undefined,
			(err: unknown) => err,
		);

		expect(failure).toBeInstanceOf(BootError);
		expect((failure as BootError).reason).toBe("provides-factory-failed");
		expect(((failure as BootError).cause as Error).message).toBe("stage-3-boom");
		// LIFO: the throwing close ran first; the one registered before it still ran.
		expect(ran).toEqual(["registered-first"]);
		expect(logger.error).toHaveBeenCalledTimes(1);
	});
});

// ---------------------------------------------------------------------------
// 7b. dispose drains the LifecycleRegistrar through the logger component
// ---------------------------------------------------------------------------

describe("createApp — 7b. dispose logs a failed adapter cleanup through the logger component", () => {
	it("once at error, object-first with the event name, marked dispose, and the projected error", async () => {
		const logger = spyLogger();
		const loggerMod = defineModule({
			name: "LoggerMod",
			provides: { logger: () => logger as unknown as Logger },
			lifecycle: { logger: { eager: true } },
		});
		const handle = await createApp({
			modules: [loggerMod, adapterWhoseCloseThrowsModule()],
			bootstrapComponents: minBoot,
			contributionKinds: makeStubCollectors(),
		});

		await expect(handle.dispose()).rejects.toBeInstanceOf(AggregateError);

		expectOneCleanupFailureLine(logger.error.mock.calls, "dispose");
		for (const level of ["trace", "debug", "info", "warn", "fatal"] as const) {
			expect(logger[level]).not.toHaveBeenCalled();
		}
	});

	it("through consoleLogger when no logger component is wired: one console.error, object-first", async () => {
		const console_ = spyConsole();
		try {
			const handle = await createApp({
				modules: [adapterWhoseCloseThrowsModule()],
				bootstrapComponents: minBoot,
				contributionKinds: makeStubCollectors(),
			});

			await expect(handle.dispose()).rejects.toBeInstanceOf(AggregateError);

			expectOneCleanupFailureLine(console_.error.mock.calls, "dispose");
			for (const method of ["warn", "info", "debug", "log"] as const) {
				expect(console_[method]).not.toHaveBeenCalled();
			}
		} finally {
			console_.restore();
		}
	});
});

// ---------------------------------------------------------------------------
// 7c. The cleanup allowance a module's builder declares
// ---------------------------------------------------------------------------

describe("createApp — 7c. the cleanup allowance a module registers", () => {
	/** A module whose builder registers one cleanup with `tailMs`, recording that it ran. */
	const tailedModule = (tailMs: number, ran: string[] = []) =>
		defineModule<never, "lifecycleRegistrar">({
			name: "TailedMod",
			optional: ["lifecycleRegistrar"],
			provides: {
				slotCA: (deps) => {
					deps.lifecycleRegistrar?.register(
						async () => {
							ran.push("closed");
						},
						{ tailMs },
					);
					return 1;
				},
			},
			lifecycle: { slotCA: { eager: true } },
		});

	it("is the longest tail a module registered through lifecycleRegistrar", async () => {
		const handle = await createApp({
			modules: [tailedModule(45_000)],
			bootstrapComponents: minBoot,
			contributionKinds: makeStubCollectors(),
		});
		expect(handle.cleanupAllowanceMs).toBe(45_000);
		await handle.dispose();
	});

	it("is absent when no cleanup declared a tail", async () => {
		const handle = await createApp({
			modules: [],
			bootstrapComponents: minBoot,
			contributionKinds: makeStubCollectors(),
		});
		expect(handle.cleanupAllowanceMs).toBeUndefined();
		await handle.dispose();
	});

	it("refuses boot on a tail no timer can wait, and still runs the cleanup registered with it", async () => {
		const ran: string[] = [];
		await expect(
			createApp({
				modules: [tailedModule(Number.POSITIVE_INFINITY, ran)],
				bootstrapComponents: minBoot,
				contributionKinds: makeStubCollectors(),
			}),
		).rejects.toMatchObject({
			name: "BootError",
			stage: "materializeComponents",
			cause: expect.objectContaining({ name: "RangeError" }),
		});
		expect(ran).toEqual(["closed"]);
	});
});

// ---------------------------------------------------------------------------
// 8. ReadinessRegistrar seeding
// ---------------------------------------------------------------------------

describe("createApp — 8. ReadinessRegistrar seeding", () => {
	it("surfaces probes registered by a module on the handle", async () => {
		// The connection a probe pings is held by the builder that opened it and
		// is never exposed as a component, so registration has to happen there.
		const probeMod = defineModule<never, "readinessRegistrar">({
			name: "ProbeMod",
			optional: ["readinessRegistrar"],
			provides: {
				slotCA: async (deps) => {
					deps.readinessRegistrar?.register({
						name: "redis",
						check: async () => "PONG",
					});
					return 1;
				},
			},
			lifecycle: { slotCA: { eager: true } },
		});

		const handle = await createApp({
			modules: [probeMod],
			bootstrapComponents: minBoot,
			contributionKinds: makeStubCollectors(),
		});

		expect(handle.readinessProbes.map((p) => p.name)).toEqual(["redis"]);
	});

	it("exposes an empty probe list when no module registered one", async () => {
		const plainMod = defineModule({
			name: "PlainMod",
			provides: { slotCA: async () => 1 },
			lifecycle: { slotCA: { eager: true } },
		});

		const handle = await createApp({
			modules: [plainMod],
			bootstrapComponents: minBoot,
			contributionKinds: makeStubCollectors(),
		});

		expect(handle.readinessProbes).toEqual([]);
	});
});

describe("the sessionRequirements collector", () => {
	it("refuses replace outright, known name or not: a requirement is switched off by not installing it", () => {
		const collector = mergeWithBuiltins(undefined).sessionRequirements;
		expect(collector).toBeDefined();
		const requirement = { name: "a" } as never;
		collector?.register("a", requirement);
		expect(() => collector?.replace("a", requirement)).toThrow(/refuses replace of "a"/);
		expect(() => collector?.replace("b", requirement)).toThrow(/refuses replace of "b"/);
		expect(collector?.get("a")).toBe(requirement);
	});
});
