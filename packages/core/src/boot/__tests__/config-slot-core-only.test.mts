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
 * The `config` slot — the whole configuration — is read by core's own
 * modules alone. A module that is not one of the manifest objects core ships
 * and lists `config` in its `requires` or its `optional` refuses boot at
 * stage 1 (`reserved-component-key`), switched on or not and before any
 * factory runs: it reads its own section as `deps.section`, and what another
 * module owns through a slot. Core's modules are known by identity, so a
 * module named as one of them, or a copy of one, is not one.
 */

import { describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { CONFIG_READING_CORE_MODULES } from "#/boot/config-slot.mjs";
import * as core from "#/index.mjs";
import {
	BootError,
	type BootstrapMap,
	createApp,
	defaultRefreshTokenFamilyRevocationModule,
	defaultRefreshTokenFamilyRotationModule,
	defineModule,
	type Module,
	memoryFederationTokenStoreModule,
	memoryRefreshTokenFamilyStoreModule,
	memorySessionStoresModule,
	sessionLifecycleModule,
} from "#/index.mjs";
import { coreConfigForTests, makeValidCoreConfig } from "#/testing/index.mjs";

const boot = (): BootstrapMap =>
	({
		config: {
			...makeValidCoreConfig(),
			// No sweep timer: the session lifecycle starts none at 0.
			core: coreConfigForTests({ sessionLifecycleSweepIntervalSeconds: 0 }).core,
		} as never,
		pathResolver: (s: string) => s,
	}) satisfies Record<string, unknown> as BootstrapMap;

/** What `createApp` refused with, or a failure when it booted. */
async function refusal(modules: readonly Module[]): Promise<BootError> {
	let handle: Awaited<ReturnType<typeof createApp>> | undefined;
	try {
		handle = await createApp({ modules, bootstrapComponents: boot() });
	} catch (err) {
		expect(err).toBeInstanceOf(BootError);
		return err as BootError;
	}
	await handle.dispose();
	throw new Error("expected boot to be refused");
}

/** Whether a manifest lists `config`, in its `requires` or its `optional`. */
const listsConfig = (m: Module): boolean =>
	(m.requires as readonly string[] | undefined)?.includes("config") === true ||
	(m.optional as readonly string[] | undefined)?.includes("config") === true;

describe("a module outside core that lists config refuses boot", () => {
	it("refuses one that requires it, naming the module and the slot, and pointing at deps.section", async () => {
		const factory = vi.fn(() => ({}));
		const reader = defineModule({
			name: "acme-reader",
			requires: ["config"] as never,
			provides: { "acme.reader": factory } as never,
			lifecycle: { "acme.reader": { eager: true } } as never,
		});

		const err = await refusal([reader]);

		expect(err.reason).toBe("reserved-component-key");
		expect(err.stage).toBe("validateManifests");
		expect(err.details).toEqual({
			reason: "reserved-component-key",
			componentKey: "config",
			source: "module-requires",
			module: "acme-reader",
		});
		expect(err.message).toContain('Module "acme-reader"');
		expect(err.message).toContain('"config"');
		expect(err.message).toContain("deps.section");
		expect(factory).not.toHaveBeenCalled();
	});

	it("refuses one that reads it optionally", async () => {
		const reader = defineModule({
			name: "acme-optional-reader",
			optional: ["config"] as never,
		});

		const err = await refusal([reader]);

		expect(err.reason).toBe("reserved-component-key");
		expect(err.details).toEqual({
			reason: "reserved-component-key",
			componentKey: "config",
			source: "module-optional",
			module: "acme-optional-reader",
		});
		expect(err.message).toContain('Module "acme-optional-reader"');
		expect(err.message).toContain("deps.section");
	});

	it("refuses one its own section switches off: the manifest is refused, not what it would register", async () => {
		const reader = defineModule({
			name: "acme-switched-off",
			requires: ["config"] as never,
			section: {
				schema: z.object({ enabled: z.boolean() }),
				isEnabled: (section: { enabled: boolean }) => section.enabled,
			},
		} as never);

		const err = await refusal([reader]);

		expect(err.reason).toBe("reserved-component-key");
		expect(err.details).toMatchObject({ componentKey: "config", module: "acme-switched-off" });
	});

	it("refuses a module named as one of core's that is not core's object", async () => {
		const lookalike = defineModule({
			name: defaultRefreshTokenFamilyRotationModule.name,
			requires: ["refreshTokenFamilyStore", "config"] as never,
			provides: { refreshTokenFamilyRotation: () => ({}) } as never,
		});

		const err = await refusal([memoryRefreshTokenFamilyStoreModule, lookalike]);

		expect(err.reason).toBe("reserved-component-key");
		expect(err.details).toEqual({
			reason: "reserved-component-key",
			componentKey: "config",
			source: "module-requires",
			module: "core-default-refresh-token-family-rotation",
		});
	});

	it("refuses a copy of core's module: the object, not its shape, is core's", async () => {
		const copy: Module = { ...defaultRefreshTokenFamilyRevocationModule };

		const err = await refusal([memoryRefreshTokenFamilyStoreModule, copy]);

		expect(err.reason).toBe("reserved-component-key");
		expect(err.details).toMatchObject({
			componentKey: "config",
			module: "core-default-refresh-token-family-revocation",
		});
	});
});

/**
 * A module whose lists gain `config` after stage 1 read them: `grow` appends
 * it to the list named, from the hook given, and `seen` records the deps its
 * factory is handed.
 */
function growingModule(
	name: string,
	list: "requires" | "optional",
	hook: "isEnabled" | "schema" | "provider",
	seen: { deps?: Record<string, unknown> },
): readonly Module[] {
	const requires: string[] = [];
	const optional: string[] = [];
	const grow = () => {
		(list === "requires" ? requires : optional).push("config");
	};
	const reader = defineModule({
		name,
		requires: requires as never,
		optional: optional as never,
		section: {
			schema: z.object({}).transform((value) => {
				if (hook === "schema") grow();
				return value;
			}),
			isEnabled: () => {
				if (hook === "isEnabled") grow();
				return true;
			},
		},
		provides: {
			[`${name}.slot`]: (deps: Record<string, unknown>) => {
				seen.deps = { ...deps };
				return {};
			},
		},
		lifecycle: { [`${name}.slot`]: { eager: true } },
	} as never);
	if (hook !== "provider") return [reader];
	// A provider that runs first, and grows the reader's list as it does.
	const earlier = defineModule({
		name: `${name}-earlier`,
		provides: {
			[`${name}.earlier`]: () => {
				grow();
				return {};
			},
		},
		lifecycle: { [`${name}.earlier`]: { eager: true } },
	} as never);
	return [earlier, reader];
}

describe("the lists stage 1 checked are the lists boot uses", () => {
	for (const list of ["requires", "optional"] as const) {
		for (const hook of ["isEnabled", "schema", "provider"] as const) {
			it(`hands no config to a module whose ${list} gains it from its ${hook} after the check`, async () => {
				const seen: { deps?: Record<string, unknown> } = {};
				const name = `acme-grows-${list}-${hook}`;
				let handle: Awaited<ReturnType<typeof createApp>> | undefined;
				try {
					handle = await createApp({
						modules: growingModule(name, list, hook, seen),
						bootstrapComponents: {
							...boot(),
							config: { ...(boot().config as object), [name]: {} },
						} as never,
					});
				} catch (err) {
					// A refusal is as good: the configuration was not handed over.
					expect(err).toBeInstanceOf(BootError);
					expect(seen.deps?.config).toBeUndefined();
					return;
				}
				try {
					expect(seen.deps).toBeDefined();
					expect(seen.deps).not.toHaveProperty("config");
				} finally {
					await handle.dispose();
				}
			});
		}
	}
});

describe("core's own modules read config", () => {
	it("boots every module core ships that lists config", async () => {
		const notifier = defineModule({
			name: "test-notifier",
			contributes: {
				sessionCloseNotifiers: { "test-notifier": () => ({ notify: async () => undefined }) },
			},
		});
		const activator = defineModule({
			name: "config-readers-activator",
			requires: ["sessionLifecycle", "refreshTokenFamilyRotation"] as never,
			contributes: {
				routes: [
					{
						mountPath: "/__test_noop__",
						id: "test-noop",
						handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
					},
				],
			},
		});

		const handle = await createApp({
			modules: [
				memorySessionStoresModule,
				memoryRefreshTokenFamilyStoreModule,
				defaultRefreshTokenFamilyRotationModule,
				defaultRefreshTokenFamilyRevocationModule,
				memoryFederationTokenStoreModule,
				sessionLifecycleModule,
				notifier,
				activator,
			],
			bootstrapComponents: boot(),
		});
		try {
			expect(handle.components.sessionLifecycle).toBeDefined();
			expect(handle.components.refreshTokenFamilyRotation).toBeDefined();
			expect(handle.components.refreshTokenFamilyRevocation).toBeDefined();
		} finally {
			await handle.dispose();
		}
	});

	it("holds exactly the modules core exports that list config", () => {
		const exported = Object.values(core).filter(
			(value): value is Module =>
				typeof value === "object" &&
				value !== null &&
				typeof (value as { name?: unknown }).name === "string" &&
				(Array.isArray((value as Module).requires) || Array.isArray((value as Module).optional)),
		);
		// The scan reads module objects at all: not vacuously passing.
		expect(exported.length).toBeGreaterThan(5);

		// By identity: the reader objects core exports are the allow-list's
		// objects, both ways, and each still lists config.
		const readers = new Set(exported.filter(listsConfig));
		const allowed = new Set(CONFIG_READING_CORE_MODULES);
		expect([...readers].filter((m) => !allowed.has(m)).map((m) => m.name)).toEqual([]);
		expect([...allowed].filter((m) => !readers.has(m)).map((m) => m.name)).toEqual([]);
		expect(readers.size).toBe(CONFIG_READING_CORE_MODULES.length);
	});
});
