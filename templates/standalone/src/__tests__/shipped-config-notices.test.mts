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
 * The template's shipped files, read as `app.mts` reads them in each mode the
 * README documents, write no section for a module the mode does not load:
 * every top-level section handed to boot is a loaded module's, core's own
 * (`core`, `oauth`), one that sets nothing, or one equal to the
 * configuration's defaults (`configDefaultsFor`). That is checked here
 * directly, whatever core counts as read; booted, the same modes then have
 * core name nothing in `config_sections_ignored` or
 * `config_sections_not_loaded`.
 *
 * Redis is a stand-in: these boots read configuration, not stores.
 */

import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";
import { createApp, type Module } from "@o3co/auth-provider-core";
import { afterEach, describe, expect, it, vi } from "vitest";
import { buildModules } from "#/buildModules.mjs";
import {
	configDefaultsFor,
	readOwnLayers,
	readSwitches,
	resolveConfigPaths,
	resolveForBoot,
} from "#/configPath.mjs";
import { createRecordingLogger, type RecordingLogger } from "./all-modules-composition.fixture.mjs";

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
	// express-session subscribes to store events, so the stand-in is an emitter.
	return {
		RedisStore: class MockRedisStore extends EventEmitter {
			get(): unknown {
				return undefined;
			}
			set(): void {}
			destroy(): void {}
		},
	};
});

vi.mock("ioredis", () => {
	const explicit: Record<string, unknown> = {
		on: () => undefined,
		quit: async () => "OK",
		disconnect: () => undefined,
		ping: async () => "PONG",
	};
	const makeMockRedis = (): object =>
		new Proxy(
			{},
			{
				get(_target, prop) {
					// A function-valued `then` would make the instance a thenable.
					if (typeof prop !== "string" || prop === "then") return undefined;
					if (prop === "duplicate") return makeMockRedis;
					if (prop in explicit) return explicit[prop];
					return async () => null;
				},
			},
		);
	function MockRedis(): object {
		return makeMockRedis();
	}
	return { Redis: MockRedis, default: MockRedis };
});

const configDir = fileURLToPath(new URL("../../config", import.meta.url));

const handles: { dispose(): Promise<void> }[] = [];
afterEach(async () => {
	for (const handle of handles.splice(0)) await handle.dispose();
});

const signingKey = generateKeyPairSync("ed25519", {
	publicKeyEncoding: { type: "spki", format: "pem" },
	privateKeyEncoding: { type: "pkcs8", format: "pem" },
});
const clientsFile = (() => {
	const file = join(mkdtempSync(join(tmpdir(), "shipped-config-notices-")), "clients.yaml");
	writeFileSync(file, "");
	return file;
})();

/** What `.env.example` asks every deployment for, with the Store's user directory. */
const REQUIRED: Readonly<Record<string, string>> = {
	OAUTH_JWT_ISSUER: "https://auth.test",
	KEY_STORE_LOCAL_PRIVATE_KEY: signingKey.privateKey,
	KEY_STORE_LOCAL_PUBLIC_KEY: signingKey.publicKey,
	SESSION_STORE_SECRET: "shipped-config-notices-session.at-least-32-bytes.ok",
	REPOSITORIES_CLIENT_YAML_PATH: clientsFile,
	REPOSITORIES_USER_HTTP_AUTHENTICATE_URL: "https://store.auth.test/authenticate",
	REPOSITORIES_USER_HTTP_AUTHENTICATE_BY_TOKEN_URL: "https://store.auth.test/by-token",
};

/** What `docker-compose.yml` sets for the app beside the operator's `.env`, with `.env.example`'s Redis URLs. */
const COMPOSE: Readonly<Record<string, string>> = {
	SESSION_STORE_STORAGE_REDIS_URL: "redis://redis.test:6379",
	REDIS_CLIENTS_URL: "redis://redis.test:6379",
	ADAPTERS_USER_SESSION_STORES: "redis",
	ADAPTERS_MFA_FACTOR_STORE: "redis",
	ADAPTERS_MFA_TRANSACTION_STORE: "redis",
};

/** What MFA, on by default, needs outside development. */
const MFA_OUTSIDE_DEVELOPMENT: Readonly<Record<string, string>> = {
	MFA_ENCRYPTION_KEY: "bzNjbzptZmE6c2hpcHBlZC1jb25maWctbm90aWNlcyE=",
	STANDARD_SMTP_MAIL_SENDER_HOST: "smtp.auth.test",
	STANDARD_SMTP_MAIL_SENDER_FROM: "auth@auth.test",
};

/** One replica, as `docker-compose.production.yml` runs it. */
const PRODUCTION: Readonly<Record<string, string>> = {
	...REQUIRED,
	...COMPOSE,
	...MFA_OUTSIDE_DEVELOPMENT,
	CORE_DEPLOYMENT_MODE: "single",
	HTTP_TRUST_PROXY: "loopback",
};

/** The README's multi-replica checklist: every shared store on Redis. */
const MULTI: Readonly<Record<string, string>> = {
	...PRODUCTION,
	CORE_DEPLOYMENT_MODE: "multi",
	ADAPTERS_RATE_LIMITER: "redis",
	ADAPTERS_ATTEMPT_COUNTER: "redis",
	ADAPTERS_FEDERATION_TOKEN_STORE: "redis",
	REDIS_FEDERATION_TOKEN_STORE_ENCRYPTION_KEY: "bzNjbzpmZWRlcmF0aW9uLXRva2Vucy1ub3RpY2VzISE=",
};

/** Every store in memory, MFA off: one process of local work with no Redis. */
const IN_MEMORY: Readonly<Record<string, string>> = {
	...REQUIRED,
	MFA_MODE: "off",
	SESSION_STORE_STORAGE_TYPE: "memory",
	ADAPTERS_ACCESS_TOKEN_DENYLIST: "memory",
	ADAPTERS_REPLAY_SEEN_SET: "memory",
	ADAPTERS_CODE_REPOSITORY: "memory",
};

/** The composition's own files for `configEnv`, read as `app.mts` reads them, and what they choose. */
function readShipped(configEnv: string, env: Readonly<Record<string, string>>) {
	const { applicationConfPath, envConfPath } = resolveConfigPaths(configDir, configEnv);
	const own = readOwnLayers([envConfPath, applicationConfPath], { env });
	const switches = readSwitches(own);
	const modules = buildModules(switches, { environment: configEnv });
	return { own, switches, modules };
}

/** Boots the template's own files for `configEnv` under `env`, as `app.mts` does. */
async function bootShipped(
	configEnv: string,
	env: Readonly<Record<string, string>>,
): Promise<{ readonly logger: RecordingLogger; readonly modules: readonly string[] }> {
	const { own, switches, modules } = readShipped(configEnv, env);
	const logger = createRecordingLogger();
	const handle = await createApp({
		modules,
		bootstrapComponents: {
			config: resolveForBoot(own, modules, switches),
			configDefaults: configDefaultsFor(modules),
			pathResolver: (s: string) => s,
			logger,
		},
	});
	handles.push(handle);
	return { logger, modules: modules.map((module) => module.name) };
}

/** Core's own sections. */
const CORE_SECTIONS: readonly string[] = ["core", "oauth"];

/**
 * Removed by boot before it parses the configuration: what the resolution saw
 * of each renamed variable.
 */
const RENAMED_VARIABLES = "renamed-variables";

/** Whether `value` sets anything: a value, or a section with one somewhere under it. */
function setsAnything(value: unknown): boolean {
	if (typeof value !== "object" || value === null || Array.isArray(value)) return true;
	return Object.values(value).some(setsAnything);
}

/**
 * The top-level sections of what `resolveForBoot` hands boot that are no
 * loaded module's and not core's, set something, and differ from the
 * configuration's defaults: settings for a module the composition does not
 * load.
 */
function sectionsNothingLoadedReads(
	configEnv: string,
	env: Readonly<Record<string, string>>,
): string[] {
	const { own, switches, modules } = readShipped(configEnv, env);
	const resolved = resolveForBoot(own, modules, switches) as unknown as Record<string, unknown>;
	const defaults = configDefaultsFor(modules);
	const sections = new Set(
		modules.filter((module: Module) => module.section !== undefined).map((module) => module.name),
	);
	return Object.keys(resolved)
		.filter((name) => !sections.has(name) && !CORE_SECTIONS.includes(name))
		.filter((name) => name !== RENAMED_VARIABLES && setsAnything(resolved[name]))
		.filter((name) => !isDeepStrictEqual(resolved[name], defaults[name]))
		.sort();
}

/** What each warn line named `event` names. */
const named = (logger: RecordingLogger, event: string): unknown[] =>
	logger.lines
		.filter((line) => line.level === "warn" && line.args[1] === event)
		.map((line) => line.args[0]);

/** Each mode the README documents: its name, the configuration it selects, its environment. */
const MODES = [
	["development, as docker-compose.yml runs it", "development", { ...REQUIRED, ...COMPOSE }],
	["development, every store in memory", "development", IN_MEMORY],
	["production, one replica", "production", PRODUCTION],
	[
		"production, one replica, the Redis rate limiter",
		"production",
		{ ...PRODUCTION, ADAPTERS_RATE_LIMITER: "redis" },
	],
	["production, every store in memory", "production", IN_MEMORY],
	["production, more than one replica", "production", MULTI],
] as const;

describe("the shipped files write no section for a module the mode does not load", () => {
	it.each(MODES)("%s", (_mode, configEnv, env) => {
		expect(sectionsNothingLoadedReads(configEnv, env)).toEqual([]);
	});
});

describe("a boot of the shipped files that changes nothing of them names no section", () => {
	it.each(MODES)("%s", async (_mode, configEnv, env) => {
		const { logger, modules } = await bootShipped(configEnv, env);
		expect(modules).not.toContain("federation-grants");
		expect(named(logger, "config_sections_ignored")).toEqual([]);
		expect(named(logger, "config_sections_not_loaded")).toEqual([]);
	});
});
