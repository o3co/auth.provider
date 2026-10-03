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
 * The notices stage 1 gives about configuration no loaded module reads. A
 * package's `reference.conf` is layered whenever any of its modules is
 * loaded, so it sets the sections of siblings that are not; with the
 * configuration's defaults (`bootstrapComponents.configDefaults`) boot tells
 * a section left as that file sets it (silent) from one the operator's files
 * or the environment changed (`config_sections_not_loaded`) and from one no
 * loaded package sets at all (`config_sections_ignored`). A variable the
 * resolution captured set that no loaded module declares renamed is named as
 * `environment_variables_not_applied`. Each notice names, never values.
 */

import { fileURLToPath } from "node:url";
import { parseFile, parseString } from "@o3co/ts.hocon";
import { describe, expect, it, vi } from "vitest";
import { createApp } from "#/boot/create-app.mjs";
import { BootError, type BootstrapMap } from "#/boot/types.mjs";
import type { AppConfig } from "#/config/application.schema.mjs";
import { coreReference } from "#/config/references.mjs";
import { RENAMED_VARIABLES_SECTION } from "#/config/removed-keys.mjs";
import type { Logger } from "#/logging/Logger.mjs";
import type { Module } from "#/modules/manifest/module-spec.mjs";
import { memoryRateLimiterModule } from "#/ratelimit/module.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";

/** A logger whose every method is a spy. */
function recordingLogger(): Logger & { readonly warn: ReturnType<typeof vi.fn> } {
	return {
		trace: vi.fn(),
		debug: vi.fn(),
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		fatal: vi.fn(),
	} as unknown as Logger & { readonly warn: ReturnType<typeof vi.fn> };
}

/** A resolved configuration: core's sections, plus whatever `extra` adds at the top. */
const resolved = (extra: Record<string, unknown> = {}): Record<string, unknown> => ({
	...makeValidCoreConfig(),
	...extra,
});

/** The notices of `name` the boot logged at warn, each call's fields. */
const noticesOf = (logger: ReturnType<typeof recordingLogger>, name: string): unknown[] =>
	logger.warn.mock.calls.filter(([, message]) => message === name).map(([fields]) => fields);

/**
 * Boots `modules` on `config`, with `configDefaults` as an own key when it is
 * passed — `undefined` included — and answers the logger.
 */
async function boot(
	modules: readonly Module[],
	config: Record<string, unknown>,
	...configDefaults: [] | [unknown]
): Promise<ReturnType<typeof recordingLogger>> {
	const logger = recordingLogger();
	const handle = await createApp({
		modules,
		bootstrapComponents: {
			config: config as unknown as AppConfig,
			pathResolver: (s: string) => s,
			logger,
			...(configDefaults.length === 0 ? {} : { configDefaults: configDefaults[0] }),
		} as BootstrapMap,
	});
	await handle.dispose();
	return logger;
}

/** A sibling module's section, as its package's `reference.conf` sets it. */
const SIBLING_DEFAULT = { keyPrefix: "sib:", ttlSeconds: 60 };

describe("a section no loaded module owns, with the configuration's defaults", () => {
	it("is not named when it equals its default", async () => {
		const logger = await boot([], resolved({ "sibling-store": { ...SIBLING_DEFAULT } }), {
			"sibling-store": { ...SIBLING_DEFAULT },
		});
		expect(noticesOf(logger, "config_sections_ignored")).toEqual([]);
		expect(noticesOf(logger, "config_sections_not_loaded")).toEqual([]);
	});

	it("is named once as not loaded when the operator changed it, naming no value", async () => {
		const logger = await boot(
			[],
			resolved({
				"sibling-store": { ...SIBLING_DEFAULT, keyPrefix: "secret-prefix-7f3a:" },
				"other-sibling": { enabled: true },
			}),
			{ "sibling-store": { ...SIBLING_DEFAULT }, "other-sibling": {} },
		);
		expect(noticesOf(logger, "config_sections_not_loaded")).toEqual([
			{ sections: ["other-sibling", "sibling-store"] },
		]);
		expect(noticesOf(logger, "config_sections_ignored")).toEqual([]);
		expect(JSON.stringify(logger.warn.mock.calls)).not.toContain("secret-prefix-7f3a");
	});

	it("names as not loaded a section a variable set to a number's default: a variable carries a string", async () => {
		const logger = await boot(
			[],
			resolved({ "sibling-store": { ...SIBLING_DEFAULT, ttlSeconds: "60" } }),
			{
				"sibling-store": { ...SIBLING_DEFAULT },
			},
		);
		expect(noticesOf(logger, "config_sections_not_loaded")).toEqual([
			{ sections: ["sibling-store"] },
		]);
	});

	it("names a section its defaults do not set as ignored, beside one not loaded", async () => {
		const logger = await boot(
			[],
			resolved({
				"sibling-store": { ...SIBLING_DEFAULT, ttlSeconds: 5 },
				typoSection: { enabled: true },
			}),
			{ "sibling-store": { ...SIBLING_DEFAULT } },
		);
		expect(noticesOf(logger, "config_sections_ignored")).toEqual([{ sections: ["typoSection"] }]);
		expect(noticesOf(logger, "config_sections_not_loaded")).toEqual([
			{ sections: ["sibling-store"] },
		]);
	});

	it("names nothing for a section that sets nothing, whatever its default", async () => {
		const logger = await boot([], resolved({ "sibling-store": {} }), {
			"sibling-store": { ...SIBLING_DEFAULT },
		});
		expect(noticesOf(logger, "config_sections_ignored")).toEqual([]);
		expect(noticesOf(logger, "config_sections_not_loaded")).toEqual([]);
	});

	it("compares a section holding lists element by element", async () => {
		const sibling = { hosts: ["a.test", "b.test"], routes: [{ path: "/x" }] };
		const silent = await boot([], resolved({ "sibling-store": structuredClone(sibling) }), {
			"sibling-store": structuredClone(sibling),
		});
		expect(noticesOf(silent, "config_sections_not_loaded")).toEqual([]);
		const changed = await boot(
			[],
			resolved({ "sibling-store": { ...structuredClone(sibling), hosts: ["a.test"] } }),
			{ "sibling-store": structuredClone(sibling) },
		);
		expect(noticesOf(changed, "config_sections_not_loaded")).toEqual([
			{ sections: ["sibling-store"] },
		]);
	});

	it("reads configDefaults handed as undefined as none handed", async () => {
		const logger = await boot([], resolved({ "sibling-store": { ...SIBLING_DEFAULT } }), undefined);
		expect(noticesOf(logger, "config_sections_ignored")).toEqual([{ sections: ["sibling-store"] }]);
	});

	it("is never a component: neither the component map nor the config slot holds it", async () => {
		const handle = await createApp({
			modules: [],
			bootstrapComponents: {
				config: resolved() as unknown as AppConfig,
				pathResolver: (s: string) => s,
				configDefaults: { "sibling-store": { ...SIBLING_DEFAULT } },
			} as BootstrapMap,
		});
		expect(Object.hasOwn(handle.components, "configDefaults")).toBe(false);
		const config = handle.components.config as unknown as Record<string, unknown>;
		expect(Object.hasOwn(config, "configDefaults")).toBe(false);
		expect(Object.hasOwn(config, "sibling-store")).toBe(false);
		await handle.dispose();
	});
});

describe("configDefaults that boot cannot read as plain data", () => {
	/** What boot refused `configDefaults` with. */
	const refusedWith = async (configDefaults: unknown): Promise<BootError> => {
		try {
			await boot([], resolved(), configDefaults);
		} catch (err) {
			expect(err).toBeInstanceOf(BootError);
			return err as BootError;
		}
		return expect.fail("boot should have been refused");
	};

	it.each([
		["null", null],
		["a list", [{ "sibling-store": {} }]],
		["a string", "not-an-object"],
		["an instance", new Map([["sibling-store", {}]])],
	])("refuses %s: it is not an object of sections", async (_label, value) => {
		const err = await refusedWith(value);
		expect(err.reason).toBe("config-defaults-invalid");
		expect(err.details).toEqual({
			reason: "config-defaults-invalid",
			path: [],
			problem: expect.stringContaining("not an object of sections"),
		});
	});

	it("refuses a getter that throws, naming its path and no value", async () => {
		const section = {};
		Object.defineProperty(section, "keyPrefix", {
			enumerable: true,
			get() {
				throw new Error("getter-secret-3b1e");
			},
		});
		const err = await refusedWith({ "sibling-store": section });
		expect(err.reason).toBe("config-defaults-invalid");
		expect(err.details).toMatchObject({ path: ["sibling-store", "keyPrefix"] });
		expect(err.message).toContain("sibling-store.keyPrefix");
		expect(err.message).not.toContain("getter-secret-3b1e");
	});

	it("refuses an accessor even when it answers: plain data is read once, never through a getter", async () => {
		const section = {};
		Object.defineProperty(section, "keyPrefix", { enumerable: true, get: () => "sib:" });
		const err = await refusedWith({ "sibling-store": section });
		expect(err.details).toMatchObject({
			reason: "config-defaults-invalid",
			path: ["sibling-store", "keyPrefix"],
		});
	});

	it("refuses a value inside a section that is not plain data, naming its path", async () => {
		const err = await refusedWith({ "sibling-store": { expiresAt: new Date(0) } });
		expect(err.details).toEqual({
			reason: "config-defaults-invalid",
			path: ["sibling-store", "expiresAt"],
			problem: expect.stringContaining("not plain data"),
		});
	});

	it("refuses an accessor in a list, naming its index", async () => {
		const hosts = ["a.test"];
		Object.defineProperty(hosts, "0", { enumerable: true, get: () => "a.test" });
		const err = await refusedWith({ "sibling-store": { hosts } });
		expect(err.details).toMatchObject({
			reason: "config-defaults-invalid",
			path: ["sibling-store", "hosts", "0"],
		});
	});

	it("refuses a Proxy that throws as its kind is read, at the top", async () => {
		const throwing = new Proxy(
			{},
			{
				getPrototypeOf() {
					throw new Error("proxy-secret-5a90");
				},
			},
		);
		const err = await refusedWith(throwing);
		expect(err.details).toEqual({
			reason: "config-defaults-invalid",
			path: [],
			problem: "threw as it was read",
		});
		expect(err.message).not.toContain("proxy-secret-5a90");
	});

	it("refuses a Proxy whose traps throw, at the level it was read", async () => {
		const throwing = new Proxy(
			{},
			{
				ownKeys() {
					throw new Error("proxy-secret-c07d");
				},
			},
		);
		const err = await refusedWith({ "sibling-store": throwing });
		expect(err.details).toMatchObject({
			reason: "config-defaults-invalid",
			path: ["sibling-store"],
		});
		expect(err.message).not.toContain("proxy-secret-c07d");
	});

	it("reads a Proxy that answers as plain data once, as the data it answered", async () => {
		const get = vi.fn((target: Record<string, unknown>, key: string | symbol) =>
			Reflect.get(target, key),
		);
		const defaults = new Proxy({ "sibling-store": { ...SIBLING_DEFAULT } }, { get });
		const logger = await boot([], resolved({ "sibling-store": { ...SIBLING_DEFAULT } }), defaults);
		expect(noticesOf(logger, "config_sections_ignored")).toEqual([]);
		expect(noticesOf(logger, "config_sections_not_loaded")).toEqual([]);
	});
});

describe("configDefaults, a reserved name", () => {
	/** What boot refused `modules` and `overrideComponents` with. */
	const refusedWith = async (
		modules: readonly Module[],
		overrideComponents?: Record<string, unknown>,
	): Promise<BootError> => {
		try {
			const handle = await createApp({
				modules,
				bootstrapComponents: {
					config: resolved() as unknown as AppConfig,
					pathResolver: (s: string) => s,
				} as BootstrapMap,
				...(overrideComponents === undefined ? {} : { overrideComponents }),
			});
			await handle.dispose();
		} catch (err) {
			expect(err).toBeInstanceOf(BootError);
			return err as BootError;
		}
		return expect.fail("boot should have been refused");
	};

	it("refuses a module that provides a component of that name", async () => {
		const provider = {
			name: "provider",
			provides: { configDefaults: () => ({}) },
		} as unknown as Module;
		const err = await refusedWith([provider]);
		expect(err.reason).toBe("reserved-component-key");
		expect(err.details).toEqual({
			reason: "reserved-component-key",
			componentKey: "configDefaults",
			source: "module-provides",
			module: "provider",
		});
	});

	it.each([
		["requires", "module-requires"],
		["optional", "module-optional"],
	])("refuses a module whose %s names it", async (field, source) => {
		const reader = { name: "reader", [field]: ["configDefaults"] } as unknown as Module;
		const err = await refusedWith([reader]);
		expect(err.details).toEqual({
			reason: "reserved-component-key",
			componentKey: "configDefaults",
			source,
			module: "reader",
		});
	});

	it("refuses an overrideComponents entry of that name", async () => {
		const err = await refusedWith([], { configDefaults: {} });
		expect(err.details).toEqual({
			reason: "reserved-component-key",
			componentKey: "configDefaults",
			source: "overrideComponents",
		});
	});
});

describe("a section no loaded module owns, without the configuration's defaults", () => {
	it("is named as ignored when it sets something, equal to a default or not", async () => {
		const logger = await boot([], resolved({ "sibling-store": { ...SIBLING_DEFAULT } }));
		expect(noticesOf(logger, "config_sections_ignored")).toEqual([{ sections: ["sibling-store"] }]);
		expect(noticesOf(logger, "config_sections_not_loaded")).toEqual([]);
	});
});

describe("the JWKS module's section, which core's reference.conf sets, with the module not loaded", () => {
	/** Core's reference resolved under `env`, over `operator`. */
	const resolve = (env: Record<string, string>, operator = ""): Record<string, unknown> =>
		parseString(operator, { env })
			.withFallback(parseFile(fileURLToPath(coreReference()), { env }))
			.toObject() as Record<string, unknown>;

	/** Boots no module with the JWKS section as resolved under `env`, and core's defaults. */
	const bootWith = (env: Record<string, string>, operator = "") =>
		boot([], resolved({ jwks: resolve(env, operator).jwks }), resolve({}));

	it("names nothing while its variables are unset", async () => {
		const logger = await bootWith({});
		expect(noticesOf(logger, "config_sections_ignored")).toEqual([]);
		expect(noticesOf(logger, "config_sections_not_loaded")).toEqual([]);
	});

	it("is named once as not loaded when JWKS_PATH is set", async () => {
		const logger = await bootWith({ JWKS_PATH: "/keys/jwks.json" });
		expect(noticesOf(logger, "config_sections_not_loaded")).toEqual([{ sections: ["jwks"] }]);
		expect(noticesOf(logger, "config_sections_ignored")).toEqual([]);
	});

	it("is named once as not loaded when the operator writes jwks.path", async () => {
		const logger = await bootWith({}, 'jwks.path = "/keys/jwks.json"\n');
		expect(noticesOf(logger, "config_sections_not_loaded")).toEqual([{ sections: ["jwks"] }]);
	});
});

describe("environment_variables_not_applied — a captured variable no loaded module declares", () => {
	/** The configuration with `captures` laid over core's own captures. */
	const withCaptures = (captures: Record<string, string | null>): Record<string, unknown> => {
		const config = resolved();
		return {
			...config,
			[RENAMED_VARIABLES_SECTION]: {
				...(config[RENAMED_VARIABLES_SECTION] as Record<string, unknown>),
				...captures,
			},
		};
	};

	it("names RATE_LIMIT_FAIL_MODE, set with the in-process limiter, once", async () => {
		const logger = await boot(
			[memoryRateLimiterModule],
			withCaptures({ RATE_LIMIT_FAIL_MODE: "open", REDIS_RATE_LIMITER_FAIL_MODE: null }),
		);
		expect(noticesOf(logger, "environment_variables_not_applied")).toEqual([
			{ variables: ["RATE_LIMIT_FAIL_MODE"] },
		]);
	});

	it("names every one set, sorted, and never a value", async () => {
		const logger = await boot(
			[],
			withCaptures({
				RATE_LIMIT_FAIL_MODE: null,
				REDIS_RATE_LIMITER_FAIL_MODE: "marker-value-91c2",
				OLD_SIBLING_TTL: "",
			}),
		);
		expect(noticesOf(logger, "environment_variables_not_applied")).toEqual([
			{ variables: ["OLD_SIBLING_TTL", "REDIS_RATE_LIMITER_FAIL_MODE"] },
		]);
		expect(JSON.stringify(logger.warn.mock.calls)).not.toContain("marker-value-91c2");
	});

	it("does not name a variable a loaded module declares renamed, by its old name or its new one", async () => {
		const logger = await boot(
			[memoryRateLimiterModule],
			withCaptures({
				MEMORY_RATE_LIMITER_MAX_BUCKETS: "500",
				CORE_RATE_LIMITER_MEMORY_MAX_BUCKETS: "500",
			}),
		);
		expect(noticesOf(logger, "environment_variables_not_applied")).toEqual([]);
	});

	it("does not name a variable core's own section declares renamed", async () => {
		const logger = await boot([], withCaptures({ CORE_DEPLOYMENT_MODE: "single" }));
		expect(noticesOf(logger, "environment_variables_not_applied")).toEqual([]);
	});

	it("logs nothing while every capture is unset", async () => {
		const logger = await boot(
			[],
			withCaptures({ RATE_LIMIT_FAIL_MODE: null, REDIS_RATE_LIMITER_FAIL_MODE: null }),
		);
		expect(noticesOf(logger, "environment_variables_not_applied")).toEqual([]);
	});
});
