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
 * Every module with a section — each one the full set loads on memory stores
 * and on Redis, each sectioned module every workspace package exports, and
 * each one a package's exported module factory builds — refuses an unknown
 * key at every object level of its own section (core's
 * `sectionStrictnessProblems`), so a typo or a key an older version read
 * refuses boot naming its path instead of being dropped unread.
 *
 * Each section is sampled from the configuration the full set boots with
 * (the Redis set's for a module only it loads, the package's `reference.conf`
 * for one neither loads), and from the samples below for the levels and the
 * forms those leave out: every level a section's schema declares must be
 * reached. A level whose keys are open by design is exempt, with its reason.
 * A module not yet strict is on an allowlist pinned level by level, which may
 * only shrink: a level that comes to refuse, or a new level that keeps an
 * unknown key, fails, and so does any offender off the list.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { Module } from "@o3co/auth-provider-core";
import { sectionStrictnessProblems } from "@o3co/auth-provider-core/testing";
import { foundationMfaFactorStoreModule } from "@o3co/auth-provider-foundation";
import { MULTI_ENV } from "@o3co/auth-provider-standalone/src/__tests__/all-modules-composition.fixture.mts";
import { parseFile } from "@o3co/ts.hocon";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { testRedis } from "../../../../packages/redis/__tests__/support/redis.mts";
import { composeFullSet, type FullSet } from "./full-set.fixture.mjs";

/** The levels whose keys are open by design, each with why. */
const EXEMPT: Readonly<Record<string, string>> = {
	"audit-sink":
		"each key names a sink the deployment registers in the template's audit-sink module",
	"audit-sink.*": "each sink's builder holds its own options to its rules",
	"core-rate-limiter-memory.limits":
		"each key is a rate-limit prefix, named by the module that owns it or by the deployment",
	"redis-rate-limiter.limits":
		"each key is a rate-limit prefix, named by the module that owns it or by the deployment",
	"federation-grants.connections": "each key is a connection the deployment names",
	"federation-grants.connections.*.authorizationParams":
		"each key is an authorization request parameter the upstream defines; the module refuses the ones it sets itself",
};

/**
 * The modules whose sections still keep an unknown key, each with every level
 * that keeps one. A level leaves the list in the change that makes it strict,
 * and a module with it.
 */
const NOT_YET_STRICT: Readonly<Record<string, readonly string[]>> = {
	oauth: [
		"oauth",
		"oauth.accessToken",
		"oauth.authorize",
		"oauth.authorize.acrValues",
		"oauth.jwt",
		"oauth.nonce",
		"oauth.refreshToken",
		"oauth.resourceIndicator",
		"oauth.revocation",
	],
	webauthn: ["webauthn", "webauthn.rateLimit", "webauthn.rateLimit.authenticationOptions"],
	"session-store": ["session-store.storage"],
};

/**
 * Each module factory a workspace package exports, with the sectioned
 * modules it builds — none for a module without a section. A factory the
 * full sets do not call is built in `BUILT`.
 */
const FACTORIES: Readonly<Record<string, readonly string[]>> = {
	"@o3co/auth-provider-device-grant:deviceGrantModule": ["device-grant"],
	"@o3co/auth-provider-federation-apple:appleFederationTypeModule": [],
	"@o3co/auth-provider-federation-github:githubFederationTypeModule": [],
	"@o3co/auth-provider-federation-google:googleFederationTypeModule": [],
	"@o3co/auth-provider-federation-oidc:oidcFederationTypeModule": [],
	"@o3co/auth-provider-foundation:foundationMfaFactorStoreModule": ["foundation-mfa-factor-store"],
	"@o3co/auth-provider-mfa:mfaModule": ["mfa"],
	"@o3co/auth-provider-mfa:mfaModules": [
		"mfa",
		"mfa-totp-factor",
		"mfa-recovery-code-factor",
		"mfa-email-factor",
	],
	"@o3co/auth-provider-oauth:oauthAuthorizationModule": ["oauth-authorization"],
	"@o3co/auth-provider-oauth:oauthModule": ["oauth"],
	"@o3co/auth-provider-oauth:oauthSessionModule": ["oauth-session"],
	"@o3co/auth-provider-redis:redisFederationGrantStoreModuleFor": ["redis-federation-grant-store"],
	"@o3co/auth-provider-redis:redisFederationTokenStoreModuleFor": ["redis-federation-token-store"],
	"@o3co/auth-provider-session:sessionStoreModuleFor": ["session-store"],
	"@o3co/auth-provider-standard:standardDevelopmentMailSenderModule": [],
	"@o3co/auth-provider-webauthn:webauthnSessionSubjectModule": [],
};

/** The sectioned modules no full set loads, built from their exported factories. */
const BUILT: readonly Module[] = [foundationMfaFactorStoreModule({ storeTransport: {} })];

/** Every workspace package this workspace composes, but the template. */
const PACKAGES: readonly string[] = Object.keys(
	(
		JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")) as {
			devDependencies: Record<string, string>;
		}
	).devDependencies,
).filter(
	(name) => name.startsWith("@o3co/auth-provider-") && name !== "@o3co/auth-provider-standalone",
);

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value);

const isModule = (value: unknown): value is Module =>
	isPlainObject(value) && typeof value.name === "string";

/** Where `module`'s section sits. */
const sectionPath = (module: Module): string[] =>
	module.section?.at === undefined ? [module.name] : module.section.at.split(".");

function valueAt(tree: unknown, path: readonly string[]): unknown {
	let cursor: unknown = tree;
	for (const key of path) {
		if (!isPlainObject(cursor)) return undefined;
		cursor = cursor[key];
	}
	return cursor;
}

/** `base` with `value` at `path`, copied along the way. */
function withValue(base: unknown, path: readonly string[], value: unknown): unknown {
	if (path.length === 0) return value;
	const [head, ...rest] = path as [string, ...string[]];
	const object = isPlainObject(base) ? base : {};
	return { ...object, [head]: withValue(object[head], rest, value) };
}

/**
 * The samples for the levels and forms the configurations leave out, each
 * built over the section `base` the configuration holds.
 */
const SAMPLES: Readonly<Record<string, (base: unknown) => readonly unknown[]>> = {
	"audit-sink": () => [{ "splunk-hec": { url: "https://splunk.test/services/collector" } }],
	"core-rate-limiter-memory": (base) => [
		withValue(base, ["limits"], { login: { limit: 5, windowSeconds: 60 } }),
	],
	"redis-rate-limiter": (base) => [
		withValue(base, ["limits"], { login: { limit: 5, windowSeconds: 60 } }),
	],
	"federation-grants": (base) => {
		const connections = valueAt(base, ["connections"]);
		const name = isPlainObject(connections) ? Object.keys(connections)[0] : undefined;
		if (name === undefined)
			throw new Error("the full set configures no federation-grants connection");
		return [withValue(base, ["connections", name, "authorizationParams"], { prompt: "consent" })];
	},
	"key-store": (base) => [
		withValue(base, ["local"], {
			algorithm: "HS256",
			kid: "hs-2",
			secret: "a-shared-secret-of-at-least-32-bytes",
			previousSecrets: [
				{
					kid: "hs-1",
					secret: "an-older-secret-of-at-least-32-bytes",
					expiresAt: "2026-12-31T00:00:00Z",
				},
			],
		}),
		withValue(base, ["local"], {
			algorithm: "ES256",
			kid: "es-2",
			privateKeyPath: "/keys/es-2.pem",
			previousKeys: [
				{ kid: "es-1", publicKeyPath: "/keys/es-1.pub.pem", expiresAt: "2026-12-31T00:00:00Z" },
			],
		}),
	],
	mtls: (base) => [
		withValue(base, ["fullPki", "revocation"], { mode: "ocsp", onUnavailable: "reject" }),
	],
};

/** A module's section as its package's `reference.conf` resolves with no variable set. */
function shipped(module: Module): unknown {
	const reference = module.section?.reference;
	if (reference === undefined) return undefined;
	return valueAt(parseFile(fileURLToPath(reference), { env: {} }).toObject(), sectionPath(module));
}

describe("every module with a section refuses an unknown key in it", () => {
	let memory: FullSet;
	let onRedis: FullSet;
	let modules: readonly Module[];
	let samples: Record<string, readonly unknown[]>;
	const factories: string[] = [];

	beforeAll(async () => {
		memory = await composeFullSet();
		const redis = await testRedis();
		const url = `redis://${redis.host}:${redis.port}/${redis.db}`;
		onRedis = await composeFullSet({
			env: { ...MULTI_ENV, REDIS_CLIENTS_URL: url, SESSION_STORE_STORAGE_REDIS_URL: url },
			stores: "redis",
			shippedRefreshTokenFamilyStore: true,
		});
		const exported: Module[] = [];
		for (const name of PACKAGES) {
			const entry = (await import(name)) as Record<string, unknown>;
			for (const [key, value] of Object.entries(entry)) {
				if (isModule(value) && value.section !== undefined) exported.push(value);
				if (typeof value === "function" && /Modules?(For)?$/.test(key) && key !== "defineModule") {
					factories.push(`${name}:${key}`);
				}
			}
		}
		// Each module once, by name: the memory set's, then the Redis set's, then the rest.
		const byName = new Map<string, { module: Module; base: unknown }>();
		const add = (list: readonly Module[], baseOf: (module: Module) => unknown) => {
			for (const module of list) {
				if (module.section === undefined || byName.has(module.name)) continue;
				byName.set(module.name, { module, base: baseOf(module) });
			}
		};
		add(memory.modules, (module) => valueAt(memory.resolved, sectionPath(module)));
		add(onRedis.modules, (module) => valueAt(onRedis.resolved, sectionPath(module)));
		add([...exported, ...BUILT], shipped);
		modules = [...byName.values()].map(({ module }) => module);
		samples = Object.fromEntries(
			[...byName.values()].map(({ module, base }) => [
				module.name,
				[...(base === undefined ? [] : [base]), ...(SAMPLES[module.name]?.(base) ?? [])],
			]),
		);
	});

	afterAll(async () => {
		await memory?.handle.dispose();
		await onRedis?.handle.dispose();
	});

	const problemsOf = (checked: readonly Module[]): string[] =>
		sectionStrictnessProblems(checked, { samples, exempt: EXEMPT });

	it("knows every module factory a package exports, and checks each sectioned module one builds", () => {
		expect([...factories].sort()).toEqual(Object.keys(FACTORIES).sort());
		const names = modules.map((module) => module.name);
		for (const [factory, built] of Object.entries(FACTORIES)) {
			for (const name of built) expect(names, `${factory} builds ${name}`).toContain(name);
		}
	});

	it("checks the sections of every package's modules, on memory and on Redis (the guard is not vacuous)", () => {
		expect(modules.map((module) => module.name)).toEqual(
			expect.arrayContaining([
				"jwks",
				"session",
				"oauth-authorization",
				"device-grant",
				"webauthn",
				"mfa",
				"audit-sink",
				"key-store",
				"core-rate-limiter-memory",
				"redis-clients",
				"redis-rate-limiter",
				"redis-session-stores",
				"foundation-mfa-factor-store",
			]),
		);
	});

	it("finds no level keeping an unknown key, and none unreached, outside the allowlist", () => {
		expect(
			problemsOf(modules.filter((module) => !Object.hasOwn(NOT_YET_STRICT, module.name))),
		).toEqual([]);
	});

	it.each(Object.entries(NOT_YET_STRICT))(
		"finds in %s exactly the levels its entry lists, so the entry shrinks with each level made strict",
		(name, levels) => {
			const module = modules.find((candidate) => candidate.name === name);
			expect(module, `${name} is not a sectioned module of the full set`).toBeDefined();
			expect(problemsOf([module as Module])).toEqual(
				levels
					.map(
						(level) => `${level}: module "${name}"'s section schema does not refuse an unknown key`,
					)
					.sort(),
			);
		},
	);
});
