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
 * The template's own modules' sections, through the template's own reading
 * of the full set: the operator's layer and environment read once, phase
 * one's switches, then the layers over every loaded package's
 * `reference.conf` handed to boot. `logging`, `http` (with its CORS list),
 * `key-store` and `redis-clients` each read the section named after it. A
 * path they moved from refuses boot naming the new one, a key a section does
 * not declare is refused, and a variable renamed with them refuses boot
 * unless its new name carries the same value.
 */

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { BootError } from "@o3co/auth-provider-core";
import { SINGLE_ENV } from "@o3co/auth-provider-standalone/src/__tests__/all-modules-composition.fixture.mts";
import { afterAll, afterEach, describe, expect, it } from "vitest";
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
			env: { ...SINGLE_ENV, HTTP_CORS_ALLOWED_ORIGINS: "https://app.example, http://localhost:5173" },
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
				["OAUTH_JWT_PRIVATE_KEY_PATH", "LOCAL_PRIVATE_KEY_PATH", "local.privateKeyPath", PRIVATE_KEY_PATH],
				["OAUTH_JWT_PUBLIC_KEY_PATH", "LOCAL_PUBLIC_KEY_PATH", "local.publicKeyPath", PUBLIC_KEY_PATH],
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
	const loading = (row: { readonly redis?: boolean }): FullSetOptions =>
		row.redis === true ? { shippedRefreshTokenFamilyStore: true } : {};

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

	it.each(ROWS)("$from set beside $to at the same value: boots, $path parsed from it", async (row) => {
		const { from, to, path, value, parsed } = row;
		const composition = await boot({ ...loading(row), env: { ...SINGLE_ENV, [from]: value, [to]: value } });

		expect(parsedAt(composition, path)).toEqual(parsed);
	});
});
