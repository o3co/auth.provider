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
 * The template's own sections, through the template's own reading of the
 * full set: the operator's layer and environment read once, phase one's
 * switches, then the layers over every loaded package's `reference.conf`
 * handed to boot. `logging`, `http` (with its CORS list), `key-store`,
 * `redis-clients`, the code repositories and `audit-sink` each read the
 * section named after it; which adapter fills a slot is the composition
 * root's own `adapters`, which phase one reads alone. A path they moved from
 * refuses naming the new one, a key a section does not declare is refused,
 * and a variable renamed with them refuses while its old name is set,
 * whatever its new name holds.
 */

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { BootError } from "@o3co/auth-provider-core";
import {
	MULTI_ENV,
	SINGLE_ENV,
} from "@o3co/auth-provider-standalone/src/__tests__/all-modules-composition.fixture.mts";
import { afterAll, afterEach, describe, expect, it } from "vitest";
import { testRedis } from "../../../../packages/redis/__tests__/support/redis.mts";
import { composeFullSet, type FullSet, type FullSetOptions } from "./full-set.fixture.mts";

let current: FullSet | undefined;

afterEach(async () => {
	await current?.handle.dispose().catch(() => {});
	current = undefined;
});

/** Boots the full set, the operator's layer and environment as given, and remembers it. */
async function boot(options: FullSetOptions = {}): Promise<FullSet> {
	current = await composeFullSet(options);
	return current;
}

/** What boot refused the full set with. */
async function refused(options: FullSetOptions): Promise<BootError> {
	try {
		current = await composeFullSet(options);
	} catch (err) {
		if (err instanceof BootError) return err;
		throw err;
	}
	throw new Error("the full set booted");
}

/** The value at a dotted path of the configuration boot parsed. */
function parsedAt(composition: FullSet, path: string): unknown {
	let cursor: unknown = composition.config;
	for (const key of path.split(".")) {
		if (typeof cursor !== "object" || cursor === null) return undefined;
		cursor = (cursor as Record<string, unknown>)[key];
	}
	return cursor;
}

/** The environment of the shipped full set without the variables named. */
function without(...names: readonly string[]): Record<string, string> {
	return Object.fromEntries(Object.entries(SINGLE_ENV).filter(([name]) => !names.includes(name)));
}

/** The full set's signing key pair, as its environment carries it. */
const PRIVATE_KEY = SINGLE_ENV.KEY_STORE_LOCAL_PRIVATE_KEY as string;
const PUBLIC_KEY = SINGLE_ENV.KEY_STORE_LOCAL_PUBLIC_KEY as string;

/** The key pair in files, for the variables that name a path. */
const KEY_DIR = mkdtempSync(join(tmpdir(), "template-sections-"));
const PRIVATE_KEY_PATH = join(KEY_DIR, "private.pem");
const PUBLIC_KEY_PATH = join(KEY_DIR, "public.pem");
writeFileSync(PRIVATE_KEY_PATH, PRIVATE_KEY ?? "");
writeFileSync(PUBLIC_KEY_PATH, PUBLIC_KEY ?? "");
afterAll(() => rmSync(KEY_DIR, { recursive: true, force: true }));

/** An unreachable Redis: the shared socket dials it and boot does not wait. */
const REDIS_URL = "redis://127.0.0.1:9";

describe("the template's own modules' sections, read where they now sit", () => {
	it("logging.level, which LOGGING_LEVEL sets", async () => {
		const composition = await boot({ env: { ...SINGLE_ENV, LOGGING_LEVEL: "debug" } });

		expect(parsedAt(composition, "logging.level")).toBe("debug");
	});

	it("http.cors.allowedOrigins, which HTTP_CORS_ALLOWED_ORIGINS sets, is what httpSettings carries", async () => {
		const composition = await boot({
			env: {
				...SINGLE_ENV,
				HTTP_CORS_ALLOWED_ORIGINS: "https://app.example, http://localhost:5173",
			},
		});

		expect(parsedAt(composition, "http.cors.allowedOrigins")).toEqual([
			"https://app.example",
			"http://localhost:5173",
		]);
		expect(composition.handle.components.httpSettings?.cors.allowedOrigins).toEqual([
			"https://app.example",
			"http://localhost:5173",
		]);
	});

	it("key-store.local, which KEY_STORE_LOCAL_* set, is what the key store signs with", async () => {
		const composition = await boot({ env: { ...SINGLE_ENV, KEY_STORE_LOCAL_KID: "k-moved" } });

		expect(parsedAt(composition, "key-store.local.kid")).toBe("k-moved");
		expect(composition.handle.components.keyStore?.getSigningKidFallback()).toBe("k-moved");
	});

	it("redis-clients.url, which REDIS_CLIENTS_URL sets", async () => {
		const composition = await boot({
			shippedRefreshTokenFamilyStore: true,
			env: { ...SINGLE_ENV, REDIS_CLIENTS_URL: REDIS_URL },
		});

		expect(parsedAt(composition, "redis-clients.url")).toBe(REDIS_URL);
	});
});

describe("a path the template's own modules moved from, written in the operator's own layer", () => {
	/** Every key written at an old path, refused as moved. */
	async function relocatedBy(options: FullSetOptions): Promise<unknown> {
		const err = await refused(options);
		expect(err.reason).toBe("config-path-relocated");
		return (err.details as { relocated: unknown }).relocated;
	}

	it("cors: refused, naming http.cors.allowedOrigins and its variable", async () => {
		expect(
			await relocatedBy({ operatorHocon: 'cors.allowedOrigins = ["https://app.example"]\n' }),
		).toEqual([
			{
				module: "http",
				from: "cors.allowedOrigins",
				to: "http.cors.allowedOrigins",
				environmentVariable: "HTTP_CORS_ALLOWED_ORIGINS",
			},
		]);
	});

	it("oauth.jwt.signingKey: each key refused, naming its path under key-store and its variable", async () => {
		const relocated = await relocatedBy({
			operatorHocon: [
				"oauth.jwt.signingKey {",
				'  provider = "local"',
				'  local { algorithm = "HS256", kid = "k-old", secret = "old-secret" }',
				"}",
				"",
			].join("\n"),
		});

		expect(relocated).toHaveLength(4);
		expect(relocated).toEqual(
			expect.arrayContaining(
				(
					[
						["provider", "PROVIDER"],
						["local.algorithm", "LOCAL_ALGORITHM"],
						["local.kid", "LOCAL_KID"],
						["local.secret", "LOCAL_SECRET"],
					] as const
				).map(([key, variable]) => ({
					module: "key-store",
					from: `oauth.jwt.signingKey.${key}`,
					to: `key-store.${key}`,
					environmentVariable: `KEY_STORE_${variable}`,
				})),
			),
		);
	});

	it("refreshTokenFamilyStore.redis: each key refused, naming its path under redis-clients and its variable", async () => {
		expect(
			await relocatedBy({
				shippedRefreshTokenFamilyStore: true,
				operatorHocon: `refreshTokenFamilyStore.redis { url = "${REDIS_URL}", password = "p" }\n`,
			}),
		).toEqual([
			{
				module: "redis-clients",
				from: "refreshTokenFamilyStore.redis.url",
				to: "redis-clients.url",
				environmentVariable: "REDIS_CLIENTS_URL",
			},
			{
				module: "redis-clients",
				from: "refreshTokenFamilyStore.redis.password",
				to: "redis-clients.password",
				environmentVariable: "REDIS_CLIENTS_PASSWORD",
			},
		]);
	});
});

describe("a key a section of the template's own modules does not declare", () => {
	it.each([
		['logging.format = "json"', "format", false],
		["http.cors.credentials = true", "credentials", false],
		['http.host = "0.0.0.0"', "host", false],
		['key-store.local.privateKeyPth = "/keys/p.pem"', "privateKeyPth", false],
		["redis-clients.db = 2", "db", true],
	])("%s: refused, naming %s", async (hocon, key, redis) => {
		const err = await refused({
			operatorHocon: `${hocon}\n`,
			...(redis ? { shippedRefreshTokenFamilyStore: true } : {}),
		});

		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toContain(`"${key}"`);
	});
});

describe("a variable the template's own modules renamed, through the template's reading", () => {
	/** Each renamed variable: its module, old and new names, the path the new one binds, a value, and what boot parses of it. */
	const ROWS = [
		{
			module: "logging",
			from: "LOG_LEVEL",
			to: "LOGGING_LEVEL",
			path: "logging.level",
			value: "debug",
			parsed: "debug",
		},
		{
			module: "http",
			from: "CORS_ALLOWED_ORIGINS",
			to: "HTTP_CORS_ALLOWED_ORIGINS",
			path: "http.cors.allowedOrigins",
			value: "https://app.example",
			parsed: ["https://app.example"],
		},
		...(
			[
				["OAUTH_JWT_SIGNING_KEY_PROVIDER", "PROVIDER", "provider", "local"],
				["OAUTH_JWT_ALGORITHM", "LOCAL_ALGORITHM", "local.algorithm", "EdDSA"],
				["OAUTH_JWT_KID", "LOCAL_KID", "local.kid", "k-renamed"],
				[
					"OAUTH_JWT_SECRET",
					"LOCAL_SECRET",
					"local.secret",
					"template-sections-secret.at-least-32-bytes.ok",
				],
				[
					"OAUTH_JWT_PRIVATE_KEY_PATH",
					"LOCAL_PRIVATE_KEY_PATH",
					"local.privateKeyPath",
					PRIVATE_KEY_PATH,
				],
				[
					"OAUTH_JWT_PUBLIC_KEY_PATH",
					"LOCAL_PUBLIC_KEY_PATH",
					"local.publicKeyPath",
					PUBLIC_KEY_PATH,
				],
				["OAUTH_JWT_PRIVATE_KEY", "LOCAL_PRIVATE_KEY", "local.privateKey", PRIVATE_KEY],
				["OAUTH_JWT_PUBLIC_KEY", "LOCAL_PUBLIC_KEY", "local.publicKey", PUBLIC_KEY],
			] as const
		).map(([from, suffix, key, value]) => ({
			module: "key-store",
			from,
			to: `KEY_STORE_${suffix}`,
			path: `key-store.${key}`,
			value,
			parsed: value,
		})),
		...(
			[
				["URL", "url", REDIS_URL],
				["PASSWORD", "password", "renamed-redis-password"],
			] as const
		).map(([name, key, value]) => ({
			module: "redis-clients",
			from: `REFRESH_TOKEN_FAMILY_STORE_REDIS_${name}`,
			to: `REDIS_CLIENTS_${name}`,
			path: `redis-clients.${key}`,
			value,
			parsed: value,
			redis: true,
		})),
	];

	/** The options that load the module a row's variable belongs to. */
	const loading = (row: object): FullSetOptions =>
		"redis" in row && row.redis === true ? { shippedRefreshTokenFamilyStore: true } : {};

	it.each(ROWS)("$from set alone: refused, naming $to and $path", async (row) => {
		const { module, from, to, path, value } = row;
		const err = await refused({ ...loading(row), env: { ...without(to), [from]: value } });

		expect(err.details).toEqual({
			reason: "environment-variable-renamed",
			renamed: [{ module, from, to, path, state: "unset" }],
		});
	});

	it.each(ROWS)(
		"$from set beside $to at a different value: refused, naming neither value",
		async (row) => {
			const { from, to } = row;
			const err = await refused({
				...loading(row),
				env: { ...SINGLE_ENV, [from]: "old-value-5e2d", [to]: "new-value-c81a" },
			});

			expect(err.details).toMatchObject({ renamed: [{ from, to, state: "different" }] });
			for (const value of ["old-value-5e2d", "new-value-c81a"]) {
				expect(err.message).not.toContain(value);
				expect(JSON.stringify(err.details)).not.toContain(value);
			}
		},
	);

	it.each(ROWS)("$from set beside $to at the same value: refused all the same", async (row) => {
		const { from, to, value } = row;
		const err = await refused({
			...loading(row),
			env: { ...SINGLE_ENV, [from]: value, [to]: value },
		});

		expect(err.details).toMatchObject({ renamed: [{ from, to, state: "different" }] });
	});

	it.each(ROWS)("$to set alone: boots, $path parsed from it", async (row) => {
		const { to, path, value, parsed } = row;
		const composition = await boot({
			...loading(row),
			env: { ...SINGLE_ENV, [to]: value },
		});

		expect(parsedAt(composition, path)).toEqual(parsed);
	});
});

/**
 * What phase one refused the full set with, before any module was chosen: a
 * `BootError` under the reason boot raises for the same case.
 */
async function phaseOneRefused(options: FullSetOptions): Promise<BootError> {
	try {
		current = await composeFullSet(options);
	} catch (err) {
		if (err instanceof BootError) return err;
		throw err;
	}
	throw new Error("the full set booted");
}

describe("the composition root's adapters, read by phase one alone", () => {
	it("ADAPTERS_CONSENT_STORE=none leaves the consent stores out", async () => {
		const composition = await boot({ env: { ...SINGLE_ENV, ADAPTERS_CONSENT_STORE: "none" } });

		expect(composition.modules.map((module) => module.name)).not.toContain(
			"core-consent-store-memory",
		);
		expect(composition.config).not.toHaveProperty("adapters");
	});

	it("ADAPTERS_AUDIT_SINK=console builds core's console sink", async () => {
		const composition = await boot({ env: { ...SINGLE_ENV, ADAPTERS_AUDIT_SINK: "console" } });

		expect(composition.handle.components.auditSink?.kind).toBe("console");
	});

	it.each([
		[
			'rateLimiter.adapter = "memory"',
			"rateLimiter.adapter",
			"adapters.rateLimiter",
			"ADAPTERS_RATE_LIMITER",
		],
		[
			'oauth.code.adapter = "memory"',
			"oauth.code.adapter",
			"adapters.codeRepository",
			"ADAPTERS_CODE_REPOSITORY",
		],
		['audit.sink.type = "logger"', "audit.sink.type", "adapters.auditSink", "ADAPTERS_AUDIT_SINK"],
	])(
		"%s: refused before boot, naming %s's new path and variable",
		async (hocon, from, to, variable) => {
			const err = await phaseOneRefused({ operatorHocon: `${hocon}\n` });

			expect(err.reason).toBe("config-path-relocated");
			expect(err.details).toEqual({
				reason: "config-path-relocated",
				relocated: [{ module: "adapters", from, to, environmentVariable: variable }],
			});
			expect(err.message).toContain(`${from} has moved to ${to}`);
			expect(err.message).toContain(variable);
		},
	);

	it.each([
		["RATE_LIMITER_ADAPTER", "ADAPTERS_RATE_LIMITER"],
		["OAUTH_CODE_ADAPTER", "ADAPTERS_CODE_REPOSITORY"],
		["CLIENT_USER_TYPE", "ADAPTERS_USER_REPOSITORY"],
		["AUDIT_SINK_TYPE", "ADAPTERS_AUDIT_SINK"],
	])("%s set alone: refused before boot, naming %s", async (from, to) => {
		const err = await phaseOneRefused({ env: { ...without(to), [from]: "memory" } });

		expect(err.reason).toBe("environment-variable-renamed");
		expect(err.details).toMatchObject({
			renamed: [{ module: "adapters", from, to, state: "unset" }],
		});
		expect(err.message).toContain(`${from} was renamed ${to}`);
	});
});

describe("the code repositories' own sections", () => {
	it("standalone-in-memory-code-repository.defaultExpiresIn, which STANDALONE_IN_MEMORY_CODE_REPOSITORY_DEFAULT_EXPIRES_IN sets", async () => {
		const composition = await boot({
			env: { ...SINGLE_ENV, STANDALONE_IN_MEMORY_CODE_REPOSITORY_DEFAULT_EXPIRES_IN: "900" },
		});

		expect(parsedAt(composition, "standalone-in-memory-code-repository.defaultExpiresIn")).toBe(
			900,
		);
	});

	it("redis-code-repository, which REDIS_CODE_REPOSITORY_* set, on the shared socket", async () => {
		const redis = await testRedis();
		const url = `redis://${redis.host}:${redis.port}/${redis.db}`;
		const composition = await boot({
			env: {
				...MULTI_ENV,
				REDIS_CLIENTS_URL: url,
				SESSION_STORE_STORAGE_REDIS_URL: url,
				REDIS_CODE_REPOSITORY_KEY_PREFIX: "tenant-a:code:",
				REDIS_CODE_REPOSITORY_DEFAULT_EXPIRES_IN: "300",
			},
			shippedRefreshTokenFamilyStore: true,
			stores: "redis",
		});

		expect(parsedAt(composition, "redis-code-repository")).toEqual({
			keyPrefix: "tenant-a:code:",
			defaultExpiresIn: 300,
		});
	});

	it.each([
		[
			SINGLE_ENV,
			"standalone-in-memory-code-repository",
			"STANDALONE_IN_MEMORY_CODE_REPOSITORY_DEFAULT_EXPIRES_IN",
			"standalone-in-memory-code-repository.defaultExpiresIn",
		],
		[
			MULTI_ENV,
			"redis-code-repository",
			"REDIS_CODE_REPOSITORY_DEFAULT_EXPIRES_IN",
			"redis-code-repository.defaultExpiresIn",
		],
	])(
		"CLIENT_CODE_DEFAULT_EXPIRES_IN set alone: refused, naming %s's new variable",
		async (env, module, to, path) => {
			const err = await refused({
				env: { ...env, CLIENT_CODE_DEFAULT_EXPIRES_IN: "300" },
				...(env === MULTI_ENV
					? { shippedRefreshTokenFamilyStore: true, stores: "redis" as const }
					: {}),
			});

			expect(err.details).toEqual({
				reason: "environment-variable-renamed",
				renamed: [{ module, from: "CLIENT_CODE_DEFAULT_EXPIRES_IN", to, path, state: "unset" }],
			});
		},
	);
});

describe("the federations, under core.federations", () => {
	/** The environment the full set boots with, its federations' variables under their old names. */
	const withOldNames = (env: Readonly<Record<string, string>>): Record<string, string> =>
		Object.fromEntries(
			Object.entries(env).map(([name, value]) => [
				name.replace(/^CORE_FEDERATIONS_/, "FEDERATIONS_"),
				value,
			]),
		);

	it("reads the shipped OIDC federation from CORE_FEDERATIONS_OIDC_*, and boots it", async () => {
		const composition = await boot({});

		expect(parsedAt(composition, "core.federations.oidc.clientId")).toBe("oidc-client");
		expect(parsedAt(composition, "core.federations.oidc.enabled")).toBe(true);
		expect(composition.config).not.toHaveProperty("federations");
	});

	it("refuses, before any module is chosen, the variables under their old names alone", async () => {
		const err = await phaseOneRefused({ env: withOldNames(SINGLE_ENV) });

		expect(err.reason).toBe("environment-variable-renamed");
		for (const name of ["GOOGLE_ENABLED", "OIDC_ISSUER", "OIDC_CLIENT_ID"]) {
			expect(err.message).toContain(`FEDERATIONS_${name} was renamed CORE_FEDERATIONS_${name}`);
			expect(err.details).toMatchObject({
				renamed: expect.arrayContaining([
					expect.objectContaining({
						module: "core",
						from: `FEDERATIONS_${name}`,
						to: `CORE_FEDERATIONS_${name}`,
						state: "unset",
					}),
				]),
			});
		}
	});

	it("refuses, before any module is chosen, the old names beside the new ones at the same values", async () => {
		const err = await phaseOneRefused({ env: { ...SINGLE_ENV, ...withOldNames(SINGLE_ENV) } });

		expect(err.reason).toBe("environment-variable-renamed");
		expect(err.details).toMatchObject({
			renamed: expect.arrayContaining([
				expect.objectContaining({ from: "FEDERATIONS_OIDC_CLIENT_ID", state: "different" }),
			]),
		});
	});

	it("boots the new names alone", async () => {
		const composition = await boot({ env: SINGLE_ENV });

		expect(parsedAt(composition, "core.federations.oidc.clientId")).toBe("oidc-client");
	});

	it("refuses a key written at the top level, naming its path under core.federations and its variable", async () => {
		const err = await refused({
			operatorHocon: 'federations.oidc.clientUrl = "https://app.test/"\n',
		});

		expect(err.details).toMatchObject({
			reason: "config-path-relocated",
			relocated: [
				{
					module: "core",
					from: "federations.oidc.clientUrl",
					to: "core.federations.oidc.clientUrl",
					environmentVariable: "CORE_FEDERATIONS_OIDC_CLIENT_URL",
				},
			],
		});
	});
});
