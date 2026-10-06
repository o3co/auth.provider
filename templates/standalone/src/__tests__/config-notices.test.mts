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
 * Core's notices about configuration nothing loaded reads, through the
 * template's own reading: the template hands boot the configuration's
 * defaults (`configDefaultsFor`), and core alone decides what is named. A
 * section the template's `reference.conf` sets for a module the composition
 * does not load is silent while it is as that file sets it, and
 * `config_sections_not_loaded` once the operator's layer or the environment
 * changes it; a section no loaded package sets is `config_sections_ignored`;
 * a renamed variable no loaded module declares is
 * `environment_variables_not_applied`.
 */

import { fileURLToPath } from "node:url";
import { moduleReferences } from "@o3co/auth-provider-core";
import { parseFile } from "@o3co/ts.hocon";
import { afterEach, describe, expect, it, vi } from "vitest";
import { configDefaultsFor } from "#/configPath.mjs";
import {
	type ComposeOptions,
	type Composition,
	compose,
	composedModules,
	type RecordingLogger,
	resolveConfig,
	SINGLE_ENV,
} from "./all-modules-composition.fixture.mjs";

let current: Composition | undefined;

afterEach(async () => {
	await current?.handle.dispose();
	current = undefined;
	vi.unstubAllEnvs();
});

const boot = async (options: ComposeOptions): Promise<Composition> => {
	current = await compose(options);
	return current;
};

/** What each warn line named `event` names: its `sections` or `variables`. */
const named = (logger: RecordingLogger, event: string): unknown[] =>
	logger.lines
		.filter((line) => line.level === "warn" && line.args[1] === event)
		.map((line) => line.args[0]);

/** `redis-clients` is the template's module, which no store on Redis loads under SINGLE_ENV. */
const NOT_LOADED = "redis-clients";

describe("a section the template's reference.conf sets for a module the composition does not load", () => {
	it("is handed to boot and named by nothing while it is as that file sets it", async () => {
		const { logger, resolved, modules } = await boot({ env: SINGLE_ENV });
		expect(modules.map((m) => m.name)).not.toContain(NOT_LOADED);
		expect(resolved).toHaveProperty([NOT_LOADED]);
		expect(named(logger, "config_sections_not_loaded")).toEqual([]);
		expect(named(logger, "config_sections_ignored")).toEqual([]);
	});

	it("is config_sections_not_loaded once the operator's layer changes it", async () => {
		const { logger } = await boot({
			env: SINGLE_ENV,
			operatorHocon: `${NOT_LOADED}.url = "redis://elsewhere.test:6379"\n`,
		});
		expect(named(logger, "config_sections_not_loaded")).toEqual([{ sections: [NOT_LOADED] }]);
		expect(named(logger, "config_sections_ignored")).toEqual([]);
	});

	it("is config_sections_not_loaded once the environment changes it, and the variable environment_variables_not_applied", async () => {
		const { logger } = await boot({
			env: { ...SINGLE_ENV, REDIS_CLIENTS_URL: "redis://elsewhere.test:6379" },
		});
		expect(named(logger, "config_sections_not_loaded")).toEqual([{ sections: [NOT_LOADED] }]);
		expect(named(logger, "config_sections_ignored")).toEqual([]);
		expect(named(logger, "environment_variables_not_applied")).toEqual([
			{ variables: ["REDIS_CLIENTS_URL"] },
		]);
	});
});

describe("the limiter sections the template's reference.conf writes for both limiters", () => {
	it.each(["memory", "redis"] as const)(
		"are named by nothing with the %s limiter wired",
		async (rateLimiter) => {
			const { logger, modules } = await boot({
				env: { ...SINGLE_ENV, ADAPTERS_RATE_LIMITER: rateLimiter },
			});
			expect(modules.map((m) => m.name)).toContain(
				rateLimiter === "redis" ? "redis-rate-limiter" : "core-rate-limiter-memory",
			);
			expect(named(logger, "config_sections_not_loaded")).toEqual([]);
			expect(named(logger, "config_sections_ignored")).toEqual([]);
		},
	);
});

describe("a section no loaded package's reference.conf sets", () => {
	it("is config_sections_ignored: a misspelt section name", async () => {
		const { logger } = await boot({
			env: SINGLE_ENV,
			operatorHocon: 'redis-client.url = "redis://elsewhere.test:6379"\n',
		});
		expect(named(logger, "config_sections_ignored")).toEqual([{ sections: ["redis-client"] }]);
		expect(named(logger, "config_sections_not_loaded")).toEqual([]);
	});
});

describe("a renamed variable a loaded package captures and no loaded module declares", () => {
	it("is environment_variables_not_applied: RATE_LIMIT_FAIL_MODE with the Redis package loaded but not its rate limiter", async () => {
		const { logger, modules } = await boot({
			env: { ...SINGLE_ENV, ADAPTERS_CODE_REPOSITORY: "redis", RATE_LIMIT_FAIL_MODE: "closed" },
		});
		expect(modules.map((m) => m.name)).not.toContain("redis-rate-limiter");
		expect(named(logger, "environment_variables_not_applied")).toEqual([
			{ variables: ["RATE_LIMIT_FAIL_MODE"] },
		]);
		expect(named(logger, "config_sections_not_loaded")).toEqual([]);
		expect(named(logger, "config_sections_ignored")).toEqual([]);
	});
});

describe("configDefaultsFor", () => {
	const modules = composedModules(resolveConfig(SINGLE_ENV));

	it("is every loaded package's reference.conf, core's last, resolved with no environment", () => {
		const references = moduleReferences(modules).map((reference) =>
			parseFile(fileURLToPath(reference), { env: {} }),
		);
		const expected = references
			.slice(1)
			.reduce((config, next) => config.withFallback(next), references[0]);
		expect(configDefaultsFor(modules)).toEqual(expected?.toObject());
	});

	it("takes nothing from the process's environment", () => {
		vi.stubEnv("REDIS_CLIENTS_URL", "redis://operator.test:6379");
		expect(configDefaultsFor(modules)[NOT_LOADED]).toEqual({
			url: "redis://localhost:6379",
			assumeNoEviction: false,
		});
	});
});
