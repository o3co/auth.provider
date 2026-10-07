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
 * reached. A level whose keys are open by design is exempt, with its reason;
 * any other level that keeps an unknown key fails.
 *
 * The same sections fill no value of their own: a section's defaults are its
 * package's `reference.conf`, which the composition root layers beneath the
 * deployment's files, so a schema that also fills one (`.default`,
 * `.prefault`, `.catch`) keeps a second copy that can drift from the file.
 * A path whose default is also read where no `reference.conf` is layered is
 * on `DEFAULTS_KEPT`, with why; the list only shrinks.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { Module } from "@o3co/auth-provider-core";
import { sectionStrictnessProblems } from "@o3co/auth-provider-core/testing";
import { foundationMfaFactorStoreModule } from "@o3co/auth-provider-foundation";
import { MULTI_ENV } from "@o3co/auth-provider-standalone/src/__tests__/all-modules-composition.fixture.mts";
import { parseFile } from "@o3co/ts.hocon";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { z } from "zod";
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
	"oauth.authorize.acrValues": "each key is an acr value the deployment vouches for",
	"federation-grants.connections.*.authorizationParams":
		"each key is an authorization request parameter the upstream defines; the module refuses the ones it sets itself",
};

/**
 * The section paths (`<section>.<path>`, `*` for any record key or list
 * element) whose schema keeps a default, each with why: the value is also
 * read where no `reference.conf` is layered. Each is also in the file where
 * the file holds the path.
 */
const DEFAULTS_KEPT: Readonly<Record<string, string>> = {
	"redis-federation-grant-store":
		"resolveRedisFederationGrantStoreOptions, an exported function a composition root that builds the store itself calls, parses the section as the operator wrote it, with no reference.conf beneath",
	"redis-federation-grant-store.keyPrefix":
		"read by resolveRedisFederationGrantStoreOptions, which parses the section with no reference.conf beneath",
	"redis-federation-grant-intent-store":
		"resolveRedisFederationGrantIntentStoreOptions, an exported function a composition root that builds the store itself calls, parses the section as the operator wrote it, with no reference.conf beneath",
	"redis-federation-grant-intent-store.keyPrefix":
		"read by resolveRedisFederationGrantIntentStoreOptions, which parses the section with no reference.conf beneath",
	"mtls.fullPki.revocation.allowedHosts":
		"the revocation block is absent until the operator writes it, with its mode and onUnavailable, which have no default; reference.conf cannot hold the rest of the block without making it present",
	"mtls.fullPki.revocation.fetchTimeoutMs":
		"the revocation block is absent until the operator writes it; reference.conf cannot hold its defaults without making it present",
	"mtls.fullPki.revocation.cacheTtlSeconds":
		"the revocation block is absent until the operator writes it; reference.conf cannot hold its defaults without making it present",
	"mtls.fullPki.revocation.maxResponseBytes":
		"the revocation block is absent until the operator writes it; reference.conf cannot hold its defaults without making it present",
	"mtls.fullPki.revocation.ocspRequireNonce":
		"the revocation block is absent until the operator writes it; reference.conf cannot hold its defaults without making it present",
};

/** The definition every Zod v4 schema carries, as far as `filledPaths` reads it. */
interface ZodDef {
	readonly type: string;
	readonly innerType?: z.ZodType;
	readonly in?: z.ZodType;
	readonly out?: z.ZodType;
	readonly shape?: Readonly<Record<string, z.ZodType>>;
	readonly valueType?: z.ZodType;
	readonly element?: z.ZodType;
	readonly items?: readonly z.ZodType[];
	readonly options?: readonly z.ZodType[];
	readonly left?: z.ZodType;
	readonly right?: z.ZodType;
	readonly getter?: () => z.ZodType;
	readonly catchall?: z.ZodType;
	readonly rest?: z.ZodType | null;
}

const defOf = (schema: z.ZodType): ZodDef =>
	(schema as unknown as { _zod: { def: ZodDef } })._zod.def;

/** The wrappers that fill a value the input does not carry. */
const FILLING = new Set(["default", "prefault", "catch"]);

/** The wrappers that parse as their inner schema does. */
const PASSING = new Set(["optional", "nullable", "readonly", "nonoptional"]);

/**
 * Every path inside `schema` where a value is filled (`.default`,
 * `.prefault`, `.catch`), as keys (`*` for any record key or list element;
 * `[]` for the section itself): through objects, records, lists, tuples,
 * unions, intersections, both ends of a pipe and a lazy schema, each schema
 * entered once on its own way down.
 */
function filledPaths(schema: z.ZodType): string[][] {
	const found = new Map<string, string[]>();
	const walk = (node: z.ZodType, path: string[], ancestors: ReadonlySet<z.ZodType>) => {
		if (ancestors.has(node)) return;
		const within = new Set(ancestors).add(node);
		const def = defOf(node);
		const next = (child: z.ZodType | undefined, at: string[] = path) => {
			if (child !== undefined) walk(child, at, within);
		};
		if (FILLING.has(def.type)) {
			found.set(JSON.stringify(path), path);
			next(def.innerType);
		} else if (PASSING.has(def.type)) next(def.innerType);
		else if (def.type === "pipe") {
			next(def.in);
			next(def.out);
		} else if (def.type === "object") {
			for (const [key, child] of Object.entries(def.shape ?? {})) next(child, [...path, key]);
			if (def.catchall) next(def.catchall, [...path, "*"]);
		} else if (def.type === "record") next(def.valueType, [...path, "*"]);
		else if (def.type === "array") next(def.element, [...path, "*"]);
		else if (def.type === "tuple") {
			for (const item of def.items ?? []) next(item, [...path, "*"]);
			if (def.rest) next(def.rest, [...path, "*"]);
		}
		else if (def.type === "union") for (const option of def.options ?? []) next(option);
		else if (def.type === "intersection") {
			next(def.left);
			next(def.right);
		} else if (def.type === "lazy" && def.getter) next(def.getter());
	};
	walk(schema, [], new Set());
	return [...found.values()];
}

/**
 * Every section path where a module's schema fills a value and
 * `DEFAULTS_KEPT` does not name it, every entry of the list naming none, and
 * every entry with no reason: one line each, sorted.
 */
function defaultProblems(checked: readonly Module[]): string[] {
	const filled = new Set(
		checked.flatMap((module) =>
			module.section === undefined
				? []
				: filledPaths(module.section.schema).map((path) => [module.name, ...path].join(".")),
		),
	);
	return [
		...[...filled]
			.filter((path) => !Object.hasOwn(DEFAULTS_KEPT, path))
			.map((path) => `${path}: the section schema fills a default; reference.conf holds it`),
		...Object.entries(DEFAULTS_KEPT).flatMap(([path, reason]) => [
			...(filled.has(path) ? [] : [`${path}: kept on DEFAULTS_KEPT, but no schema fills it`]),
			...(reason.trim() === "" ? [`${path}: kept with no reason`] : []),
		]),
	].sort();
}

/**
 * Each module factory a workspace package exports, with the sectioned
 * modules it builds — none for a module without a section. A factory the
 * full sets do not call is built in `BUILT`.
 */
const FACTORIES: Readonly<Record<string, readonly string[]>> = {
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
	"@o3co/auth-provider-redis:redisFederationGrantStoreModuleFor": ["redis-federation-grant-store"],
	"@o3co/auth-provider-redis:redisFederationTokenStoreModuleFor": ["redis-federation-token-store"],
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

/** Where `module`'s section sits: at the module's name. */
const sectionPath = (module: Module): string[] => [module.name];

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
		withValue(base, ["limits"], { token: { limit: 5, windowSeconds: 60 } }),
	],
	"redis-rate-limiter": (base) => [
		withValue(base, ["limits"], { token: { limit: 5, windowSeconds: 60 } }),
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
	// The paths other sections moved from, which the oauth section accepts only
	// as an empty object.
	oauth: (base) => [
		[
			"grants",
			"code",
			"deviceAuthorization",
			"tokenExchange",
			"mtls",
			"dpop",
			"tokenBinding",
		].reduce(
			(sample, key) => withValue(sample, [key], {}),
			withValue(base, ["jwt", "signingKey"], {}),
		),
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

	it("finds no level keeping an unknown key, and none unreached", () => {
		expect(problemsOf(modules)).toEqual([]);
	});

	it("finds no default a section schema fills: each is its package's reference.conf's", () => {
		expect(defaultProblems(modules)).toEqual([]);
	});

	it("finds a default a section schema fills (the guard is not vacuous)", () => {
		const probe = {
			name: "default-probe",
			section: {
				schema: z.object({ list: z.array(z.object({ on: z.boolean().default(false) })) }).strict(),
			},
		} as unknown as Module;
		expect(defaultProblems([...modules, probe])).toEqual([
			"default-probe.list.*.on: the section schema fills a default; reference.conf holds it",
		]);
	});

	it("finds a default under an object's catchall or a tuple's rest", () => {
		const probe = {
			name: "default-probe",
			section: {
				schema: z
					.object({
						pair: z.tuple([z.string()]).rest(z.number().default(1)),
					})
					.catchall(z.string().default("x")),
			},
		} as unknown as Module;
		expect(defaultProblems([...modules, probe])).toEqual([
			"default-probe.*: the section schema fills a default; reference.conf holds it",
			"default-probe.pair.*: the section schema fills a default; reference.conf holds it",
		]);
	});
});
