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
 * The template reads its configuration in two phases, as `app.mts` does:
 *
 * 1. `readSwitches` — its own files over core's `reference.conf`, read with
 *    core's transitional reader — parses only `SWITCHES`, what the template
 *    reads before it knows its modules: the switches `buildModules` chooses
 *    them by, and the configuration's `core.sessionRequirements`, which
 *    `expectedSessionRequirements` reads beside `mfa.mode` — the one path it
 *    reads raw (`OWN_READS`, `readMfaMode`), until the MFA ADR's build-order
 *    step 20 (the log level is the `logging` module's section, which
 *    `readLogging` reads with that module's schema: `own-modules.test.mts`);
 * 2. `resolveForBoot` — its own files over the `reference.conf` of every
 *    package its modules come from, core's last — handed to `createApp`
 *    unparsed, which parses it once with every loaded module's schema.
 *
 * Phase one must read each switch as a parse of the same layers with
 * `AppConfigSchema` (through the HOCON library's Zod bridge) does, and nothing
 * but its switches, so that a section a package's reference completes (known
 * only in phase two) does not refuse it.
 */

import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
	type AppConfig,
	AppConfigSchema,
	coreReference,
	createApp,
	type Module,
} from "@o3co/auth-provider-core";
import {
	redisFederationGrantIntentStoreModule,
	redisFederationGrantStoreModule,
} from "@o3co/auth-provider-redis";
import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import { describe, expect, it } from "vitest";
import { buildModules } from "../buildModules.mjs";
import {
	expectedSessionRequirements,
	OWN_READS,
	readMfaMode,
	readOwnLayers,
	readSwitches,
	resolveConfigPaths,
	resolveForBoot,
	resolveLayers,
	SWITCHES,
} from "../configPath.mjs";
import { templateReference } from "../modules.mjs";

const configDir = fileURLToPath(new URL("../../config", import.meta.url));

const REQUIRED_ENV = {
	OAUTH_JWT_SECRET: "two-phase-config-secret.at-least-32-bytes.ok",
	OAUTH_JWT_ISSUER: "https://auth.test",
	SESSION_SECRET: "two-phase-config-session.at-least-32-bytes.ok",
};

/** The environments the template ships for: none but the secrets, and the Redis-backed production one. */
const ENVIRONMENTS: Readonly<Record<string, Readonly<Record<string, string>>>> = {
	"the secrets alone": REQUIRED_ENV,
	"every adapter on Redis, MFA optional": {
		...REQUIRED_ENV,
		CORE_DEPLOYMENT_MODE: "multi",
		SESSION_STORAGE_TYPE: "redis",
		SESSION_STORAGE_REDIS_URL: "redis://redis:6379",
		REFRESH_TOKEN_FAMILY_STORE_REDIS_URL: "redis://redis:6379",
		USER_SESSION_STORES_ADAPTER: "redis",
		RATE_LIMITER_ADAPTER: "redis",
		OAUTH_CODE_ADAPTER: "redis",
		HTTP_PORT: "8080",
		HTTP_TRUST_PROXY: "loopback",
		SESSION_SECURE: "false",
		MFA_MODE: "optional",
	},
};

const ownFiles = (environment: string): string[] => {
	const { applicationConfPath, envConfPath } = resolveConfigPaths(configDir, environment);
	return [envConfPath, applicationConfPath];
};

/** The layers parsed with `AppConfigSchema` through the bridge: how phase one must read each switch. */
function preParsed(environment: string, env: Readonly<Record<string, string>>): unknown {
	const read = (file: string) => parseFile(file, { env: { ...env } });
	const [top, application] = ownFiles(environment) as [string, string];
	return validate(
		read(top)
			.withFallback(read(application))
			.withFallback(read(fileURLToPath(templateReference())))
			.withFallback(read(fileURLToPath(coreReference()))),
		AppConfigSchema,
	);
}

/** The value at a dotted path, or `undefined`. */
function valueAt(tree: unknown, path: string): unknown {
	let cursor: unknown = tree;
	for (const key of path.split(".")) {
		if (typeof cursor !== "object" || cursor === null || !Object.hasOwn(cursor, key))
			return undefined;
		cursor = (cursor as Record<string, unknown>)[key];
	}
	return cursor;
}

/** An operator's own HOCON layer, as a file above the template's. */
function operatorLayer(text: string): string {
	const file = join(mkdtempSync(join(tmpdir(), "two-phase-config-")), "operator.conf");
	writeFileSync(file, text);
	return file;
}

/** `config`, recording every dotted path read off it. */
function recording(config: unknown): { readonly config: AppConfig; readonly reads: Set<string> } {
	const reads = new Set<string>();
	const wrap = (target: object, path: string): object =>
		new Proxy(target, {
			get(object, key, receiver) {
				const value: unknown = Reflect.get(object, key, receiver);
				if (typeof key !== "string" || !Object.hasOwn(object, key)) return value;
				const at = path === "" ? key : `${path}.${key}`;
				reads.add(at);
				return typeof value === "object" && value !== null ? wrap(value, at) : value;
			},
		});
	return { config: wrap(config as object, "") as AppConfig, reads };
}

describe("phase one reads each switch as the template's AppConfigSchema pre-parse read it", () => {
	for (const environment of ["development", "production"]) {
		for (const [name, env] of Object.entries(ENVIRONMENTS)) {
			it(`${environment}, ${name}`, () => {
				const before = preParsed(environment, env);
				const switches = readSwitches(readOwnLayers(ownFiles(environment), { env }));
				const changed = SWITCHES.filter(
					(path) =>
						JSON.stringify(valueAt(before, path)) !== JSON.stringify(valueAt(switches, path)),
				);
				expect(changed).toEqual([]);
			});
		}
	}

	it("reads mfa.mode raw, as the environment sets it, beside the switches core's reader parses", () => {
		expect(OWN_READS).toEqual(["mfa.mode"]);
		expect(SWITCHES).not.toContain("mfa.mode");
		for (const [name, env] of Object.entries(ENVIRONMENTS)) {
			expect(readMfaMode(readSwitches(readOwnLayers(ownFiles("production"), { env }))), name).toBe(
				env.MFA_MODE ?? "off",
			);
		}
	});
});

describe("phase one reads its switches and nothing else", () => {
	const env = ENVIRONMENTS["every adapter on Redis, MFA optional"] as Readonly<
		Record<string, string>
	>;

	it("accepts a section a package's reference completes, which only phase two layers", () => {
		// The device grant's and WebAuthn's references ship `windowSeconds`;
		// boot layers them, and accepts what the operator wrote.
		const partial = operatorLayer(
			"device-grant.rateLimit.limit = 10\nwebauthn.rateLimit.authenticationOptions.limit = 10\n",
		);
		expect(() =>
			readSwitches(readOwnLayers([partial, ...ownFiles("production")], { env })),
		).not.toThrow();
	});

	it("reads, before boot, only paths among its switches", () => {
		const { config, reads } = recording(
			readSwitches(readOwnLayers(ownFiles("production"), { env })),
		);
		// What `app.mts` reads of phase one: the modules, and what the
		// composition expects of session admission.
		expectedSessionRequirements(config);
		buildModules(config, { environment: "production" });
		const covered = (path: string) =>
			[...SWITCHES, ...OWN_READS].some(
				(switchPath) =>
					path === switchPath ||
					path.startsWith(`${switchPath}.`) ||
					switchPath.startsWith(`${path}.`),
			);
		expect(reads.size).toBeGreaterThan(10);
		expect([...reads].filter((path) => !covered(path))).toEqual([]);
	});

	it("still refuses a switch it reads that the schema refuses, naming it", () => {
		const bad = operatorLayer('rateLimiter.adapter = "carrier-pigeon"\n');
		expect(() => readSwitches(readOwnLayers([bad, ...ownFiles("production")], { env }))).toThrow(
			/rateLimiter\.adapter/,
		);
	});
});

describe("phase two: what createApp is handed", () => {
	const env = ENVIRONMENTS["the secrets alone"] as Readonly<Record<string, string>>;
	const own = readOwnLayers(ownFiles("development"), { env });
	const switches = readSwitches(own);

	/**
	 * A package the template does not load, shipping a reference.conf of its
	 * own: only its manifest's `section.reference` is read here, so the
	 * manifest carries nothing else.
	 */
	function widgetModule(): Module {
		const dir = mkdtempSync(join(tmpdir(), "two-phase-config-"));
		const reference = join(dir, "reference.conf");
		writeFileSync(
			reference,
			'widget { size = 3 }\naudit.sink.type = "widget-sink"\noauth.oidcMode = "widget-mode"\n',
		);
		return {
			name: "widget",
			section: { reference: pathToFileURL(reference) },
		} as unknown as Module;
	}

	it("layers each loaded module's reference beneath the template's own files, over core's", () => {
		const modules = [...buildModules(switches, { environment: "development" }), widgetModule()];
		const resolved = resolveForBoot(
			own,
			modules,
			expectedSessionRequirements(switches),
		) as unknown as Record<string, Record<string, unknown>>;
		// The package's own section, from its reference.
		expect(resolved.widget).toEqual({ size: 3 });
		// The template's application.conf wins over a package's reference…
		expect(resolved.audit?.sink).toEqual({ type: "logger" });
		// …and a package's reference over core's.
		expect(resolved.oauth?.oidcMode).toBe("widget-mode");
	});

	it("layers no reference a loaded module does not declare", () => {
		const modules = buildModules(switches, { environment: "development" });
		const resolved = resolveForBoot(
			own,
			modules,
			expectedSessionRequirements(switches),
		) as unknown as Record<string, unknown>;
		expect(resolved).not.toHaveProperty("widget");
	});

	it("hands the configuration over as resolved and unparsed, with what phase one says the composition expects: mfa beside the configuration's list under MFA_MODE=optional", () => {
		const optionalOwn = readOwnLayers(ownFiles("development"), {
			env: { ...env, MFA_MODE: "optional", HTTP_PORT: "8080" },
		});
		const optional = readSwitches(optionalOwn);
		const resolved = resolveForBoot(
			optionalOwn,
			buildModules(switches, { environment: "development" }),
			expectedSessionRequirements(optional),
		) as unknown as Record<string, Record<string, unknown>>;
		// An environment variable's string, as HOCON substituted it: createApp parses it.
		expect(resolved.http?.port).toBe("8080");
		expect(resolved.core?.sessionRequirements).toEqual({ expected: ["mfa"] });
	});
});

describe("phase two refuses the Redis grant store's key prefix moved while the intent store's is left at its default", () => {
	const env = ENVIRONMENTS["the secrets alone"] as Readonly<Record<string, string>>;
	const GRANT = "REDIS_FEDERATION_GRANT_STORE_KEY_PREFIX";
	const INTENT = "REDIS_FEDERATION_GRANT_INTENT_STORE_KEY_PREFIX";
	const BOTH_ON_REDIS = [redisFederationGrantStoreModule, redisFederationGrantIntentStoreModule];

	/** Phase two over the template's development files, the variables set beside the secrets. */
	const resolve = (
		variables: Readonly<Record<string, string>>,
		modules: readonly Module[] = BOTH_ON_REDIS,
		files: readonly string[] = ownFiles("development"),
	) => resolveForBoot(readOwnLayers(files, { env: { ...env, ...variables } }), modules, undefined);

	/** What phase two refused with. */
	const refusal = (...args: Parameters<typeof resolve>): RangeError => {
		try {
			resolve(...args);
		} catch (err) {
			if (err instanceof RangeError) return err;
			throw err;
		}
		throw new Error("phase two resolved");
	};

	it("the grant store's set and the intent store's left alone: refused, naming both keys and both variables and quoting no value", () => {
		const { message } = refusal({ [GRANT]: "t1:fg:" });
		expect(message).toContain(`redis-federation-grant-store.keyPrefix (${GRANT})`);
		expect(message).toContain(`redis-federation-grant-intent-store.keyPrefix (${INTENT})`);
		expect(message).not.toContain("fg:");
	});

	it("the grant store's written in the operator's own layer: refused the same", () => {
		const operator = operatorLayer('redis-federation-grant-store.keyPrefix = "t1:fg:"\n');
		const { message } = refusal({}, BOTH_ON_REDIS, [operator, ...ownFiles("development")]);
		expect(message).toContain(`redis-federation-grant-intent-store.keyPrefix (${INTENT})`);
		expect(message).not.toContain("fg:");
	});

	it.each([
		["both set to the same prefix", { [GRANT]: "t1:fg:", [INTENT]: "t1:fg:" }],
		["each set to a prefix of its own", { [GRANT]: "t1:fg:", [INTENT]: "t1:fgi:" }],
		["neither set", {}],
	])("%s: resolved", (_, variables) => {
		const resolved = resolve(variables) as unknown as Record<string, { keyPrefix?: unknown }>;
		expect(resolved["redis-federation-grant-store"]?.keyPrefix).toBe(variables[GRANT] ?? "fg:");
		expect(resolved["redis-federation-grant-intent-store"]?.keyPrefix).toBe(
			variables[INTENT] ?? "fg:",
		);
	});

	it("the grant store's set with the intent store not on Redis: resolved, as nothing of acquisition's is kept there", () => {
		expect(() => resolve({ [GRANT]: "t1:fg:" }, [redisFederationGrantStoreModule])).not.toThrow();
	});
});

describe("both phases read one snapshot of the composition's own layers", () => {
	const env = ENVIRONMENTS["the secrets alone"] as Readonly<Record<string, string>>;

	it("sees a file's first contents in both phases, though it is replaced between them", () => {
		// Mounted configuration is commonly replaced atomically: read twice,
		// boot could parse the Redis limiter while phase one chose the memory
		// one, and nothing would refuse the disagreement.
		const operator = operatorLayer('rateLimiter.adapter = "redis"\n');
		const own = readOwnLayers([operator, ...ownFiles("production")], { env });
		writeFileSync(operator, 'rateLimiter.adapter = "memory"\n');
		const switches = readSwitches(own);
		const resolved = resolveForBoot(own, [], expectedSessionRequirements(switches)) as unknown as {
			rateLimiter: { adapter: unknown };
		};
		expect(switches.rateLimiter?.adapter).toBe("redis");
		expect(resolved.rateLimiter.adapter).toBe("redis");
	});

	it("substitutes one snapshot of the environment in both phases", () => {
		const changing: Record<string, string> = { ...env, RATE_LIMITER_ADAPTER: "redis" };
		const own = readOwnLayers(ownFiles("production"), { env: changing });
		changing.RATE_LIMITER_ADAPTER = "memory";
		const switches = readSwitches(own);
		const resolved = resolveForBoot(own, [], expectedSessionRequirements(switches)) as unknown as {
			rateLimiter: { adapter: unknown };
		};
		expect(switches.rateLimiter?.adapter).toBe("redis");
		expect(resolved.rateLimiter.adapter).toBe("redis");
	});

	it("reads every switch as boot's parse has it, for the shipped environments", async () => {
		for (const environment of ["development", "production"]) {
			for (const [name, shipped] of Object.entries(ENVIRONMENTS)) {
				// `mfa.mode` off: the template declares `mfa` under another mode, and
				// installs no module that registers it, so boot refuses. Phase one's
				// reading of the mode is pinned against the pre-parse above.
				const variables = { ...shipped, MFA_MODE: "off" };
				const own = readOwnLayers(ownFiles(environment), { env: variables });
				const switches = readSwitches(own);
				const modules = buildModules(switches, { environment });
				const handle = await createApp({
					modules: [],
					bootstrapComponents: {
						config: resolveForBoot(own, modules, expectedSessionRequirements(switches)),
						pathResolver: (s: string) => s,
						...FEDERATION_STORES,
					} as never,
				});
				const parsed = handle.components.config;
				await handle.dispose();
				const differing = SWITCHES.filter(
					(path) =>
						JSON.stringify(valueAt(switches, path)) !== JSON.stringify(valueAt(parsed, path)),
				);
				expect(differing, `${environment}, ${name}`).toEqual([]);
			}
		}
	});

	it("resolves nothing from no files and no references", () => {
		expect(resolveLayers(readOwnLayers([], { env }), [])).toEqual({});
	});
});

/** The stores an enabled federation needs, which boot refuses a composition without. */
const FEDERATION_STORES = Object.fromEntries(
	[
		"userSessionStore",
		"sessionRPRegistry",
		"sessionFamilyIndex",
		"sessionFederationIndex",
		"federationTokenStore",
		"refreshTokenFamilyRevocation",
	].map((key) => [key, {}]),
);
