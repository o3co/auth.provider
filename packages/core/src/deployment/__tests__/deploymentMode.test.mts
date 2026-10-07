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
 * The `deploymentMode` slot: how many replicas the operator says
 * this deployment runs — `single`, `multi`, or `unset` when nothing was
 * said. Core fills it from the configuration's `core.deployment.mode` before any
 * provider runs, for every composition, and reserves the key; the
 * replica-safety guard reads the same value. The one reading
 * (`deploymentModeOf`) and the check a reader holds a value to
 * (`checkDeploymentMode`), both on core's root. Its contract suite, run over
 * what core fills; a test fills the slot with the literal, so there is no
 * double.
 */

import { describe, expect, expectTypeOf, it, vi } from "vitest";
import type { BootError, BootstrapMap } from "#/boot/types.mjs";
import type { DeploymentMode } from "#/deployment/types.mjs";
import * as core from "#/index.mjs";
import { createApp, defineModule, type ProviderDeps } from "#/index.mjs";
import type { ComponentMap } from "#/modules/manifest/component-map.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";
import { deploymentModeContract } from "./deploymentMode.contract.mjs";

const RULE = "the mode is single, multi or unset";

/** The names of the cases a mode fails. */
const failing = async (mode: unknown): Promise<string[]> => {
	const failed: string[] = [];
	for (const { name, run } of deploymentModeContract({ build: () => mode as DeploymentMode })) {
		try {
			await run();
		} catch {
			failed.push(name);
		}
	}
	return failed;
};

describe("the deploymentMode slot", () => {
	it("is optional, and holds one of the three answers to how many replicas run", () => {
		expectTypeOf<ComponentMap["deploymentMode"]>().toEqualTypeOf<DeploymentMode | undefined>();
		expectTypeOf<
			ProviderDeps<"deploymentMode">["deploymentMode"]
		>().toEqualTypeOf<DeploymentMode>();
		expectTypeOf<DeploymentMode>().toEqualTypeOf<"single" | "multi" | "unset">();
		expect(true).toBe(true);
	});
});

describe("deploymentModeContract", () => {
	it("names its rule", () => {
		expect(deploymentModeContract({ build: () => "single" }).map((c) => c.name)).toEqual([RULE]);
	});

	it.each(["single", "multi", "unset"] as const)("keeps it for %s", async (mode) => {
		expect(await failing(mode)).toEqual([]);
	});

	it("fails it for anything else: another spelling, absence, the configuration's own words", async () => {
		for (const mode of ["Multi", "", undefined, null, "multiple", { mode: "multi" }]) {
			expect(await failing(mode)).toEqual([RULE]);
		}
	});
});

// ---------------------------------------------------------------------------
// Core fills it
// ---------------------------------------------------------------------------

/** Every `core.deployment` core's schema accepts, and the mode it states. */
const ACCEPTED: readonly (readonly [
	string,
	Record<string, unknown> | undefined,
	DeploymentMode,
])[] = [
	["core.deployment.mode = single", { mode: "single" }, "single"],
	["core.deployment.mode = multi", { mode: "multi" }, "multi"],
	["an empty deployment section", {}, "unset"],
	["no deployment section", undefined, "unset"],
];

const spyLogger = () => {
	const warn = vi.fn();
	const logger = {
		warn,
		info: vi.fn(),
		error: vi.fn(),
		debug: vi.fn(),
		trace: vi.fn(),
		fatal: vi.fn(),
		child: vi.fn(),
	};
	return { logger, warn };
};

/** A valid core configuration with `core.deployment` as given, and whatever else `extra` holds. */
const bootstrap = (
	deployment: Record<string, unknown> | undefined,
	extra: Record<string, unknown> = {},
): BootstrapMap =>
	({
		config: {
			...makeValidCoreConfig(),
			...(deployment === undefined ? {} : { core: { deployment } }),
		},
		pathResolver: (s: string) => s,
		...extra,
	}) as unknown as BootstrapMap;

const noopRoute = (id: string) => ({
	id,
	mountPath: `/__${id}__`,
	handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
});

/**
 * A provider that requires the slot and records what it is handed, and a
 * route that requires what it provides, so that the provider runs at boot.
 */
const providerReading = (seen: unknown[]) => [
	defineModule({
		name: "test:provider-reading-deployment-mode",
		requires: ["deploymentMode"] as const,
		provides: {
			auditSink: ({ deploymentMode }) => {
				seen.push(deploymentMode);
				return { kind: "test", record: async () => {} };
			},
		},
	}),
	defineModule({
		name: "test:route-requiring-audit-sink",
		requires: ["auditSink"] as const,
		contributes: { routes: [() => noopRoute("test-route-requiring-audit-sink")] },
	}),
];

describe("core fills deploymentMode from the configuration's core.deployment.mode", () => {
	it.each(ACCEPTED)(
		"hands a provider that requires it the mode %s states",
		async (_what, deployment, mode) => {
			const seen: unknown[] = [];
			const handle = await createApp({
				modules: providerReading(seen),
				bootstrapComponents: bootstrap(deployment),
			});
			try {
				expect(seen).toEqual([mode]);
				expect(handle.components.deploymentMode).toBe(mode);
			} finally {
				await handle.dispose();
			}
		},
	);

	it("fills it in a composition whose modules name it nowhere", async () => {
		const handle = await createApp({
			modules: [],
			bootstrapComponents: bootstrap({ mode: "single" }),
		});
		try {
			expect(handle.components.deploymentMode).toBe("single");
		} finally {
			await handle.dispose();
		}
	});

	it("hands a contribution factory that lists it as optional the same mode", async () => {
		const seen: unknown[] = [];
		const handle = await createApp({
			modules: [
				defineModule({
					name: "test:route-reading-deployment-mode",
					optional: ["deploymentMode"] as const,
					contributes: {
						routes: [
							(deps) => {
								seen.push(deps.deploymentMode);
								return noopRoute("test-route-reading-deployment-mode");
							},
						],
					},
				}),
			],
			bootstrapComponents: bootstrap({ mode: "multi" }),
		});
		try {
			expect(seen).toEqual(["multi"]);
		} finally {
			await handle.dispose();
		}
	});

	it.each(ACCEPTED)("keeps the slot's contract for %s", async (_what, deployment) => {
		const handle = await createApp({ modules: [], bootstrapComponents: bootstrap(deployment) });
		try {
			const filled = handle.components.deploymentMode;
			for (const { name, run } of deploymentModeContract({
				build: () => filled as DeploymentMode,
			})) {
				await expect(run(), name).resolves.toBeUndefined();
			}
		} finally {
			await handle.dispose();
		}
	});
});

describe("the replica-safety guard reads the mode core fills the slot with", () => {
	const holdsState = defineModule({
		name: "test:holds-state",
		replicaSafety: { unsafe: true, reason: "codes are not shared — a test consequence" },
	});

	/** What the guard does with an in-process module under `deployment`. */
	const guardOutcome = async (
		deployment: Record<string, unknown> | undefined,
	): Promise<"refused" | "warned" | "silent"> => {
		const { logger, warn } = spyLogger();
		try {
			const handle = await createApp({
				modules: [holdsState],
				bootstrapComponents: bootstrap(deployment, { logger }),
			});
			await handle.dispose();
		} catch (err) {
			expect((err as BootError).reason).toBe("replica-unsafe-adapter");
			return "refused";
		}
		return warn.mock.calls.some(([, event]) => event === "replica_unsafe_adapters")
			? "warned"
			: "silent";
	};

	it.each(ACCEPTED)(
		"refuses under multi, is silent under single and warns when unset, for %s",
		async (_what, deployment, mode) => {
			const handle = await createApp({ modules: [], bootstrapComponents: bootstrap(deployment) });
			const filled = handle.components.deploymentMode;
			await handle.dispose();
			const expected = { multi: "refused", single: "silent", unset: "warned" } as const;
			expect(filled).toBe(mode);
			expect(await guardOutcome(deployment)).toBe(expected[filled as DeploymentMode]);
		},
	);
});

// ---------------------------------------------------------------------------
// The key is reserved
// ---------------------------------------------------------------------------

describe("the deploymentMode key is reserved", () => {
	it("refuses a module that provides it, naming the module", async () => {
		const provider = defineModule({
			name: "test:provides-deployment-mode",
			provides: { deploymentMode: () => "multi" as const },
		});
		await expect(
			createApp({ modules: [provider], bootstrapComponents: bootstrap({ mode: "single" }) }),
		).rejects.toMatchObject({
			name: "BootError",
			reason: "synthetic-key-collision",
			details: {
				reason: "synthetic-key-collision",
				componentKey: "deploymentMode",
				source: "module-provides",
				module: "test:provides-deployment-mode",
			},
		});
	});

	it("refuses bootstrapComponents that set it", async () => {
		await expect(
			createApp({
				modules: [],
				bootstrapComponents: bootstrap({ mode: "single" }, { deploymentMode: "multi" }),
			}),
		).rejects.toMatchObject({
			name: "BootError",
			reason: "synthetic-key-collision",
			details: {
				reason: "synthetic-key-collision",
				componentKey: "deploymentMode",
				source: "bootstrapComponents",
			},
		});
	});

	it("refuses overrideComponents that set it", async () => {
		await expect(
			createApp({
				modules: [],
				bootstrapComponents: bootstrap({ mode: "single" }),
				overrideComponents: { deploymentMode: "multi" },
			}),
		).rejects.toMatchObject({
			name: "BootError",
			reason: "synthetic-key-collision",
			details: {
				reason: "synthetic-key-collision",
				componentKey: "deploymentMode",
				source: "overrideComponents",
			},
		});
	});

	it("tells whoever set it to set core.deployment.mode instead, from every source", async () => {
		const provider = defineModule({
			name: "test:provides-deployment-mode",
			provides: { deploymentMode: () => "multi" as const },
		});
		for (const boot of [
			createApp({ modules: [provider], bootstrapComponents: bootstrap({ mode: "single" }) }),
			createApp({
				modules: [],
				bootstrapComponents: bootstrap({ mode: "single" }, { deploymentMode: "multi" }),
			}),
			createApp({
				modules: [],
				bootstrapComponents: bootstrap({ mode: "single" }),
				overrideComponents: { deploymentMode: "multi" },
			}),
		]) {
			const err = (await boot.catch((thrown: unknown) => thrown)) as Error;
			expect(err.message).toContain(
				"Set core.deployment.mode in the configuration instead: boot fills deploymentMode from it.",
			);
		}
	});

	it("keeps the other synthetic keys' message as it is", async () => {
		const err = (await createApp({
			modules: [],
			bootstrapComponents: bootstrap({ mode: "single" }, { grantHandlerResolver: {} }),
		}).catch((thrown: unknown) => thrown)) as Error;
		expect(err.message).toBe(
			'bootstrapComponents contains synthetic key "grantHandlerResolver", which is reserved for the boot planner.',
		);
	});
});

// ---------------------------------------------------------------------------
// The one reading, and the check a reader holds a value to
// ---------------------------------------------------------------------------

describe("deploymentModeOf, on core's root", () => {
	it("reads single and multi as the configuration states them at core.deployment.mode", () => {
		expect(core.deploymentModeOf({ core: { deployment: { mode: "single" } } })).toBe("single");
		expect(core.deploymentModeOf({ core: { deployment: { mode: "multi" } } })).toBe("multi");
	});

	it("reads nothing at deployment.mode, the path it moved from", () => {
		expect(core.deploymentModeOf({ deployment: { mode: "multi" } })).toBe("unset");
	});

	it("reads unset for absence and for every value core's schema refuses, never single or multi", () => {
		for (const config of [
			undefined,
			null,
			42,
			"multi",
			{},
			{ core: null },
			{ core: { deployment: null } },
			{ core: { deployment: "multi" } },
			{ core: { deployment: {} } },
			{ core: { deployment: { mode: "MULTI" } } },
			{ core: { deployment: { mode: "Single" } } },
			{ core: { deployment: { mode: 42 } } },
			{ core: { deployment: { mode: null } } },
			{ core: { deployment: { mode: "" } } },
		]) {
			expect(core.deploymentModeOf(config), JSON.stringify(config)).toBe("unset");
		}
	});
});

describe("checkDeploymentMode, on core's root", () => {
	it("answers each of the three values as it is given", () => {
		for (const mode of ["single", "multi", "unset"] as const) {
			expect(core.checkDeploymentMode(mode, "deploymentMode")).toBe(mode);
		}
	});

	it("throws a TypeError naming the value's source for anything else, absence included", () => {
		for (const value of [undefined, null, "MULTI", "Single", "", 1, {}, ["multi"]]) {
			expect(
				() => core.checkDeploymentMode(value, "the routes' deploymentMode"),
				JSON.stringify(value),
			).toThrow(new TypeError(`the routes' deploymentMode must be "single", "multi" or "unset"`));
		}
	});
});
