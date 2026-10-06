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
 * The template's own modules: each owns the section named after it, with its
 * defaults in the template's `config/reference.conf`, and reads it through
 * `deps.section`, never the whole configuration. What each section sets
 * reaches the process, for the shipped configuration and for an operator's
 * environment and HOCON overrides, through the template's real path:
 * `readOwnLayers`, then `resolveForBoot` over every loaded module's
 * reference, then `createApp`. A path a section moved from refuses boot
 * naming its new path, and a variable renamed with it refuses boot unless its
 * new name carries the same value.
 */

import { generateKeyPairSync } from "node:crypto";
import { once } from "node:events";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { type AddressInfo, createServer, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
	type AppHandle,
	BootError,
	createApp,
	DEFAULT_SIGNING_ALGORITHM,
	defineModule,
	InMemoryClientRepository,
	InMemoryUserRepository,
	type Logger,
	type Module,
	memoryRefreshTokenFamilyStoreModule,
	moduleReferences,
	supportsMfaEnrollmentWitness,
} from "@o3co/auth-provider-core";
import { httpSettingsContract, packageReferenceProblems } from "@o3co/auth-provider-core/testing";
import { HttpUserRepository } from "@o3co/auth-provider-foundation";
import { parseFile } from "@o3co/ts.hocon";
import express from "express";
import request from "supertest";
import { afterAll, describe, expect, it, vi } from "vitest";
import { ADAPTERS_SECTION } from "../adapters.mjs";
import { buildModules } from "../buildModules.mjs";
import {
	readLogging,
	readOwnLayers,
	readSwitches,
	resolveConfigPaths,
	resolveForBoot,
} from "../configPath.mjs";
import { createAppLogger } from "../logger.mjs";
import { MFA_SWITCH } from "../mfaSwitch.mjs";
import {
	auditSinkModuleFor,
	httpModule,
	inMemoryCodeRepositoryModule,
	keyStoreModule,
	loggingModule,
	repositoriesModuleFor,
	standaloneRedisClientsModule,
} from "../modules.mjs";
import { repositoriesSectionSchema } from "../sections.mjs";

const configDir = fileURLToPath(new URL("../../config", import.meta.url));
/** The template's own defaults: what its modules declare as their sections' reference. */
const TEMPLATE_REFERENCE = new URL("../../config/reference.conf", import.meta.url);

const signingKey = generateKeyPairSync("ed25519", {
	publicKeyEncoding: { type: "spki", format: "pem" },
	privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

/**
 * What the shipped configuration needs set to boot, every store in memory
 * but where a test asks for Redis: the issuer, an Ed25519 key pair inline for
 * the shipped algorithm, and the session secret.
 */
const BASE_ENV: Readonly<Record<string, string>> = {
	OAUTH_JWT_ISSUER: "https://auth.test",
	KEY_STORE_LOCAL_PRIVATE_KEY: signingKey.privateKey,
	KEY_STORE_LOCAL_PUBLIC_KEY: signingKey.publicKey,
	SESSION_STORE_SECRET: "own-modules-session-secret.at-least-32-bytes.ok",
	SESSION_STORE_SECURE: "false",
	SESSION_STORE_NAME: "auth.session",
	SESSION_STORE_STORAGE_TYPE: "memory",
	ADAPTERS_USER_REPOSITORY: "yaml",
	CORE_DEPLOYMENT_MODE: "single",
	ADAPTERS_CODE_REPOSITORY: "memory",
	ADAPTERS_ACCESS_TOKEN_DENYLIST: "memory",
	ADAPTERS_REPLAY_SEEN_SET: "memory",
};

/** A logger that writes nothing. */
const silentLogger = (): Logger => {
	const ignore = () => {};
	const logger = {
		trace: ignore,
		debug: ignore,
		info: ignore,
		warn: ignore,
		error: ignore,
		fatal: ignore,
		child: () => logger,
	};
	return logger as unknown as Logger;
};

/** In-memory repositories in place of the YAML files and the Store the shipped ones read. */
const testRepositoriesModule = defineModule({
	name: "test:repositories",
	provides: {
		clientRepository: () => new InMemoryClientRepository(new Map()),
		userRepository: () => new InMemoryUserRepository(new Map()),
	},
});

interface BootOptions {
	/** Variables laid over `BASE_ENV`; `undefined` unsets one. */
	readonly env?: Readonly<Record<string, string | undefined>>;
	/** HOCON an operator writes, a layer above the template's own files. */
	readonly hocon?: string;
	/** The composition's own files in place of the shipped ones (`withApplicationValues`). */
	readonly files?: readonly string[];
	/** Keep the shipped Redis refresh-token family store, and with it the shared Redis clients. */
	readonly redis?: boolean;
	/** Changes the resolved configuration before `createApp` parses it, as a hand-built root may. */
	readonly adjust?: (resolved: Record<string, unknown>) => Record<string, unknown>;
	/** Components a host lays over the modules' (`overrideComponents`). */
	readonly overrides?: Record<string, unknown>;
	/** Keep the template's own `repositories` module, reading its section, rather than in-memory ones. */
	readonly repositories?: boolean;
}

/** The directories the operator layers are written to, removed after the suite. */
const operatorDirs: string[] = [];
afterAll(() => {
	for (const dir of operatorDirs) rmSync(dir, { recursive: true, force: true });
});

/** The template's own files for the development environment, under an operator's layer when given. */
function ownFiles(hocon?: string): string[] {
	const { applicationConfPath, envConfPath } = resolveConfigPaths(configDir, "development");
	if (hocon === undefined) return [envConfPath, applicationConfPath];
	const dir = mkdtempSync(join(tmpdir(), "own-modules-"));
	operatorDirs.push(dir);
	const file = join(dir, "operator.conf");
	writeFileSync(file, hocon);
	return [file, envConfPath, applicationConfPath];
}

/** Boots the template as `app.mts` does, from its own files under `env` and `hocon`. */
async function bootTemplate(options: BootOptions = {}): Promise<AppHandle> {
	const env = Object.fromEntries(
		Object.entries({ ...BASE_ENV, ...options.env }).filter(
			(entry): entry is [string, string] => entry[1] !== undefined,
		),
	);
	const own = readOwnLayers(options.files ?? ownFiles(options.hocon), { env });
	const switches = readSwitches(own);
	const modules = buildModules(switches, {
		environment: "development",
		...(options.repositories ? {} : { repositoriesModule: testRepositoriesModule }),
		...(options.redis ? {} : { refreshTokenFamilyModules: [memoryRefreshTokenFamilyStoreModule] }),
	});
	const resolved = resolveForBoot(own, modules, switches);
	return createApp({
		modules,
		bootstrapComponents: {
			config: (options.adjust
				? options.adjust({ ...(resolved as unknown as Record<string, unknown>) })
				: resolved) as typeof resolved,
			pathResolver: (s: string) => s,
			logger: silentLogger(),
		},
		...(options.overrides === undefined
			? {}
			: {
					overrideComponents: options.overrides as Parameters<
						typeof createApp
					>[0]["overrideComponents"],
				}),
	});
}

/** The module in `modules` named `name`. */
const named = (modules: readonly Module[], name: string): Module => {
	const found = modules.find((module) => module.name === name);
	if (found === undefined) throw new Error(`no module named ${name}`);
	return found;
};

/** Every module whose section the template's reference holds. */
const REFERENCED_MODULES = [
	loggingModule,
	httpModule,
	keyStoreModule,
	standaloneRedisClientsModule,
	repositoriesModuleFor({ client: "yaml", user: "http" }),
	inMemoryCodeRepositoryModule,
	auditSinkModuleFor("logger"),
];

describe("the template's config/reference.conf", () => {
	it("holds only its own modules' sections and the composition root's adapters and mfaMode, each module's parsing its part without losing a path", () => {
		expect(
			packageReferenceProblems({
				reference: TEMPLATE_REFERENCE,
				modules: REFERENCED_MODULES,
				// `adapters` and `mfaMode` are the composition root's own,
				// which phase one reads with its own schema
				// (`adapters.test.mts`, `mfa-switch.test.mts`).
				read: (path, env) => {
					const {
						[ADAPTERS_SECTION]: _adapters,
						[MFA_SWITCH]: _mfaMode,
						...tree
					} = parseFile(path, {
						env: { ...env },
					}).toObject() as Record<string, unknown>;
					return tree;
				},
			}),
		).toEqual([]);
	});

	it.each(REFERENCED_MODULES)("is among the references $name alone brings", (module) => {
		expect(moduleReferences([module]).map((url) => url.href)).toContain(TEMPLATE_REFERENCE.href);
	});
});

describe("logging", () => {
	it("owns logging, and requires nothing", () => {
		expect(loggingModule.name).toBe("logging");
		expect(loggingModule.section?.at).toBeUndefined();
		expect(loggingModule.section?.reference?.href).toBe(TEMPLATE_REFERENCE.href);
		expect(loggingModule.requires ?? []).toEqual([]);
		expect(loggingModule.optional ?? []).toEqual([]);
	});

	it("is loaded by the shipped composition", () => {
		const own = readOwnLayers(ownFiles(), { env: BASE_ENV });
		const modules = buildModules(readSwitches(own), { environment: "development" });
		expect(named(modules, "logging")).toBe(loggingModule);
	});

	it("has boot refuse a level its schema does not know, naming logging.level", async () => {
		await expect(bootTemplate({ env: { LOGGING_LEVEL: "verbose" } })).rejects.toMatchObject({
			reason: "config-validation-failed",
			message: expect.stringMatching(/logging\.level/),
		});
	});

	it("is not among what phase one reads", () => {
		const own = readOwnLayers(ownFiles(), { env: BASE_ENV });
		expect(Object.keys(readSwitches(own))).not.toContain("logging");
	});

	it.each([
		["the shipped default", {}, undefined, "info"],
		["LOGGING_LEVEL", { LOGGING_LEVEL: "debug" }, undefined, "debug"],
		["HOCON an operator writes", {}, 'logging.level = "warn"\n', "warn"],
		["HOCON over LOGGING_LEVEL", { LOGGING_LEVEL: "debug" }, 'logging.level = "error"\n', "error"],
	])("gives the logger the level %s sets", (_name, env, hocon, level) => {
		const own = readOwnLayers(ownFiles(hocon), { env: { ...BASE_ENV, ...env } });
		expect(readLogging(own)).toEqual({ level });
		const logger = createAppLogger(readLogging(own)) as unknown as { readonly level: string };
		expect(logger.level).toBe(level);
	});

	it("refuses a level it does not know before boot, naming logging.level", () => {
		const own = readOwnLayers(ownFiles(), { env: { ...BASE_ENV, LOGGING_LEVEL: "verbose" } });
		expect(() => readLogging(own)).toThrow(/logging\.level/);
	});

	it("has boot refuse LOG_LEVEL set alone, naming LOGGING_LEVEL and logging.level", async () => {
		await expect(bootTemplate({ env: { LOG_LEVEL: "debug" } })).rejects.toMatchObject({
			details: {
				reason: "environment-variable-renamed",
				renamed: [
					{
						module: "logging",
						from: "LOG_LEVEL",
						to: "LOGGING_LEVEL",
						path: "logging.level",
						state: "unset",
					},
				],
			},
		});
	});

	it("boots with LOG_LEVEL beside LOGGING_LEVEL at the same value", async () => {
		const handle = await bootTemplate({ env: { LOG_LEVEL: "debug", LOGGING_LEVEL: "debug" } });
		await handle.dispose();
	});
});

/**
 * The template booted, and mounted as `app.mts` mounts it: `trust proxy` from
 * the `httpSettings` slot, the composed router, and a route answering the
 * address Express makes of the request, standing in for what every IP-keyed
 * limit reads.
 */
async function mountTemplate(options: BootOptions = {}) {
	const handle = await bootTemplate(options);
	const settings = handle.components.httpSettings;
	if (settings === undefined) throw new Error("booted without httpSettings");
	const app = express();
	app.set("trust proxy", settings.trustProxy);
	app.get("/__ip__", (req, res) => {
		res.json({ ip: req.ip });
	});
	app.use(handle.router);
	return { app, handle };
}

/** A CORS preflight for the token endpoint from `origin`. */
const preflight = (app: express.Express, origin: string) =>
	request(app)
		.options("/oauth/token")
		.set("Origin", origin)
		.set("Access-Control-Request-Method", "POST");

describe("http", () => {
	it("owns http, the CORS list included, and requires nothing", () => {
		expect(httpModule.name).toBe("http");
		expect(httpModule.section?.at).toBeUndefined();
		expect(httpModule.section?.reference?.href).toBe(TEMPLATE_REFERENCE.href);
		expect(httpModule.requires ?? []).toEqual([]);
		expect(httpModule.optional ?? []).toEqual([]);
	});

	it("provides core's httpSettings, authoritative, and the host's own settings, both eagerly", () => {
		expect(Object.keys(httpModule.provides ?? {}).sort()).toEqual([
			"httpHostSettings",
			"httpSettings",
		]);
		expect(httpModule.authoritative).toEqual(["httpSettings"]);
		expect(httpModule.lifecycle?.httpSettings?.eager).toBe(true);
		expect(httpModule.lifecycle?.httpHostSettings?.eager).toBe(true);
	});

	it("is loaded by the shipped composition, and no module owns a top-level cors", () => {
		const own = readOwnLayers(ownFiles(), { env: BASE_ENV });
		const modules = buildModules(readSwitches(own), { environment: "development" });
		expect(named(modules, "http")).toBe(httpModule);
		expect(modules.map((module) => module.name)).not.toContain("cors");
	});

	describe("the httpSettings it provides keeps the slot's contract", () => {
		for (const [name, env] of [
			["for the shipped configuration", {}],
			[
				"for an operator's overrides",
				{
					HTTP_TRUST_PROXY: "10.0.0.0/8,loopback",
					HTTP_CORS_ALLOWED_ORIGINS: "https://app.example.com,http://localhost:5173",
				},
			],
		] as const) {
			it(name, async () => {
				const handle = await bootTemplate({ env });
				try {
					const settings = handle.components.httpSettings;
					if (settings === undefined) throw new Error("booted without httpSettings");
					for (const contractCase of httpSettingsContract({ build: () => settings })) {
						await contractCase.run();
					}
				} finally {
					await handle.dispose();
				}
			});
		}
	});

	it.each([
		["the shipped defaults", {}, undefined, { port: 3000, readinessTimeoutMs: 1000 }],
		[
			"HTTP_PORT and HTTP_READINESS_TIMEOUT_MS",
			{ HTTP_PORT: "8080", HTTP_READINESS_TIMEOUT_MS: "1500" },
			undefined,
			{ port: 8080, readinessTimeoutMs: 1500 },
		],
		[
			"HOCON an operator writes",
			{ HTTP_PORT: "8080" },
			"http { port = 4000, readinessTimeoutMs = 2500 }\n",
			{ port: 4000, readinessTimeoutMs: 2500 },
		],
	])(
		"hands the host the port and the readiness deadline %s set",
		async (_name, env, hocon, host) => {
			const handle = await bootTemplate({ env, hocon });
			try {
				expect(handle.components.httpHostSettings).toEqual(host);
			} finally {
				await handle.dispose();
			}
		},
	);

	it.each([
		["the shipped default", {}, undefined, false],
		[
			"HTTP_TRUST_PROXY",
			{ HTTP_TRUST_PROXY: "10.0.0.0/8,loopback" },
			undefined,
			["10.0.0.0/8", "loopback"],
		],
		["HOCON an operator writes", {}, "http.trustProxy = 1\n", 1],
	])("trusts the forwarding hops %s names", async (_name, env, hocon, trustProxy) => {
		const handle = await bootTemplate({ env, hocon });
		try {
			expect(handle.components.httpSettings?.trustProxy).toEqual(trustProxy);
		} finally {
			await handle.dispose();
		}
	});

	it("makes req.ip the forwarded client address only through a trusted hop", async () => {
		const trusting = await mountTemplate({ env: { HTTP_TRUST_PROXY: "loopback" } });
		const shipped = await mountTemplate();
		try {
			const forwarded = await request(trusting.app)
				.get("/__ip__")
				.set("X-Forwarded-For", "203.0.113.9");
			expect(forwarded.body.ip).toBe("203.0.113.9");
			const direct = await request(shipped.app)
				.get("/__ip__")
				.set("X-Forwarded-For", "203.0.113.9");
			expect(direct.body.ip).not.toBe("203.0.113.9");
		} finally {
			await trusting.handle.dispose();
			await shipped.handle.dispose();
		}
	});

	it("refuses an exported-but-empty HTTP_PORT at boot, naming http.port and HTTP_PORT", async () => {
		const booting = bootTemplate({ env: { HTTP_PORT: "" } });
		await expect(booting).rejects.toThrow(/http\.port/);
		await expect(booting).rejects.toThrow(/HTTP_PORT/);
	});

	it("hands the host an explicit HTTP_PORT=0, the OS choosing a free port", async () => {
		const handle = await bootTemplate({ env: { HTTP_PORT: "0" } });
		try {
			expect(handle.components.httpHostSettings?.port).toBe(0);
		} finally {
			await handle.dispose();
		}
	});

	it("refuses a trust proxy entry that is not an address, a range or a named range at boot, naming http.trustProxy", async () => {
		await expect(bootTemplate({ env: { HTTP_TRUST_PROXY: "proxy.internal" } })).rejects.toThrow(
			/http\.trustProxy/,
		);
	});
});

describe("http.cors", () => {
	it("lets no origin read with the shipped default: no CORS headers, not even Vary", async () => {
		const { app, handle } = await mountTemplate();
		try {
			const res = await preflight(app, "https://app.example.com");
			expect(res.headers["access-control-allow-origin"]).toBeUndefined();
			expect(res.headers.vary ?? "").not.toMatch(/Origin/);
		} finally {
			await handle.dispose();
		}
	});

	it.each([
		[
			"HTTP_CORS_ALLOWED_ORIGINS",
			{ HTTP_CORS_ALLOWED_ORIGINS: "https://app.example.com" },
			undefined,
		],
		["HOCON an operator writes", {}, 'http.cors.allowedOrigins = ["https://app.example.com"]\n'],
	])(
		"lets the origin %s lists read the token endpoint, and no other",
		async (_name, env, hocon) => {
			const { app, handle } = await mountTemplate({ env, hocon });
			try {
				const listed = await preflight(app, "https://app.example.com");
				expect(listed.status).toBe(204);
				expect(listed.headers["access-control-allow-origin"]).toBe("https://app.example.com");
				const other = await preflight(app, "https://other.example.com");
				expect(other.headers["access-control-allow-origin"]).toBeUndefined();
			} finally {
				await handle.dispose();
			}
		},
	);

	it("refuses an origin that could never match at boot, naming http.cors.allowedOrigins", async () => {
		await expect(
			bootTemplate({ env: { HTTP_CORS_ALLOWED_ORIGINS: "https://app.example.com/" } }),
		).rejects.toThrow(/http\.cors\.allowedOrigins/);
	});

	it("has boot refuse cors.allowedOrigins, the path it moved from, naming the new path and its variable", async () => {
		await expect(
			bootTemplate({ hocon: 'cors.allowedOrigins = ["https://app.example.com"]\n' }),
		).rejects.toMatchObject({
			details: {
				reason: "config-path-relocated",
				relocated: [
					{
						module: "http",
						from: "cors.allowedOrigins",
						to: "http.cors.allowedOrigins",
						environmentVariable: "HTTP_CORS_ALLOWED_ORIGINS",
					},
				],
			},
		});
	});

	it("has boot refuse CORS_ALLOWED_ORIGINS set alone, naming HTTP_CORS_ALLOWED_ORIGINS", async () => {
		await expect(
			bootTemplate({ env: { CORS_ALLOWED_ORIGINS: "https://app.example.com" } }),
		).rejects.toMatchObject({
			details: {
				reason: "environment-variable-renamed",
				renamed: [
					{
						module: "http",
						from: "CORS_ALLOWED_ORIGINS",
						to: "HTTP_CORS_ALLOWED_ORIGINS",
						path: "http.cors.allowedOrigins",
						state: "unset",
					},
				],
			},
		});
	});
});

/**
 * The template's own files with `hocon` written into its `application.conf`,
 * above the shipped content: a value an operator sets there, above the
 * lines that bind the environment variables.
 */
function withApplicationValues(hocon: string): string[] {
	const { applicationConfPath, envConfPath } = resolveConfigPaths(configDir, "development");
	const dir = mkdtempSync(join(tmpdir(), "own-modules-application-"));
	operatorDirs.push(dir);
	const application = join(dir, "application.conf");
	writeFileSync(application, `${hocon}\n${readFileSync(applicationConfPath, "utf8")}`);
	const development = join(dir, "development.conf");
	writeFileSync(development, readFileSync(envConfPath, "utf8"));
	return [development, application];
}

describe("an environment variable wins over a value the template's application.conf sets", () => {
	it("HTTP_PORT over http.port", async () => {
		const handle = await bootTemplate({
			files: withApplicationValues("http.port = 4000"),
			env: { HTTP_PORT: "8080" },
		});
		try {
			expect(handle.components.httpHostSettings?.port).toBe(8080);
		} finally {
			await handle.dispose();
		}
	});

	it("HTTP_TRUST_PROXY over http.trustProxy", async () => {
		const handle = await bootTemplate({
			files: withApplicationValues("http.trustProxy = 1"),
			env: { HTTP_TRUST_PROXY: "loopback" },
		});
		try {
			expect(handle.components.httpSettings?.trustProxy).toEqual(["loopback"]);
		} finally {
			await handle.dispose();
		}
	});

	it("HTTP_CORS_ALLOWED_ORIGINS over http.cors.allowedOrigins", async () => {
		const handle = await bootTemplate({
			files: withApplicationValues('http.cors.allowedOrigins = ["https://file.example.com"]'),
			env: { HTTP_CORS_ALLOWED_ORIGINS: "https://env.example.com" },
		});
		try {
			expect(handle.components.httpSettings?.cors.allowedOrigins).toEqual([
				"https://env.example.com",
			]);
		} finally {
			await handle.dispose();
		}
	});

	it("REDIS_CLIENTS_URL over redis-clients.url", async () => {
		const redis = await listeningRedis();
		const handle = await bootTemplate({
			redis: true,
			files: withApplicationValues('redis-clients.url = "redis://127.0.0.1:9"'),
			env: {
				REDIS_CLIENTS_URL: `redis://127.0.0.1:${redis.port}`,
				REDIS_CLIENTS_PASSWORD: "url-test-password",
			},
		});
		try {
			await vi.waitFor(() => expect(redis.received()).toContain("url-test-password"), {
				timeout: 10_000,
			});
		} finally {
			await handle.dispose().catch(() => {});
			await redis.close();
		}
	});

	it("REDIS_CLIENTS_PASSWORD over redis-clients.password", async () => {
		const redis = await listeningRedis();
		const handle = await bootTemplate({
			redis: true,
			files: withApplicationValues('redis-clients.password = "from-the-file"'),
			env: {
				REDIS_CLIENTS_URL: `redis://127.0.0.1:${redis.port}`,
				REDIS_CLIENTS_PASSWORD: "from-the-environment",
			},
		});
		try {
			await vi.waitFor(() => expect(redis.received()).toContain("from-the-environment"), {
				timeout: 10_000,
			});
			expect(redis.received()).not.toContain("from-the-file");
		} finally {
			await handle.dispose().catch(() => {});
			await redis.close();
		}
	});
});

/** The marker of the block of variable bindings `application.conf` ships last. */
const BINDINGS_BLOCK = "# The variables that set keys of the template's own modules";

/**
 * The template's own files with its `application.conf` trimmed of the block
 * of variable bindings it ships last, as a deployment's own copy may be.
 */
function withoutApplicationBindings(): string[] {
	const { applicationConfPath, envConfPath } = resolveConfigPaths(configDir, "development");
	const shipped = readFileSync(applicationConfPath, "utf8");
	const at = shipped.indexOf(BINDINGS_BLOCK);
	if (at < 0) throw new Error("application.conf ships no bindings block");
	const dir = mkdtempSync(join(tmpdir(), "own-modules-trimmed-"));
	operatorDirs.push(dir);
	const application = join(dir, "application.conf");
	writeFileSync(application, shipped.slice(0, at));
	const development = join(dir, "development.conf");
	writeFileSync(development, readFileSync(envConfPath, "utf8"));
	return [development, application];
}

describe("a value the template's application.conf sets wins over a variable only its reference.conf binds", () => {
	it("logging.level over LOG_LEVEL", () => {
		const own = readOwnLayers(withApplicationValues('logging.level = "warn"'), {
			env: { ...BASE_ENV, LOG_LEVEL: "debug" },
		});
		expect(readLogging(own)).toEqual({ level: "warn" });
	});

	it("http.readinessTimeoutMs over HTTP_READINESS_TIMEOUT_MS", async () => {
		const handle = await bootTemplate({
			files: withApplicationValues("http.readinessTimeoutMs = 2500"),
			env: { HTTP_READINESS_TIMEOUT_MS: "1500" },
		});
		try {
			expect(handle.components.httpHostSettings?.readinessTimeoutMs).toBe(2500);
		} finally {
			await handle.dispose();
		}
	});

	it("key-store.local.kid over KEY_STORE_LOCAL_KID", async () => {
		const handle = await bootTemplate({
			files: withApplicationValues('key-store.local.kid = "k-file"'),
			env: { KEY_STORE_LOCAL_KID: "k-env" },
		});
		try {
			expect(handle.components.keyStore?.getSigningKidFallback()).toBe("k-file");
		} finally {
			await handle.dispose();
		}
	});
});

describe("an environment variable takes effect though application.conf does not bind it", () => {
	it("HTTP_PORT and HTTP_TRUST_PROXY", async () => {
		const handle = await bootTemplate({
			files: withoutApplicationBindings(),
			env: { HTTP_PORT: "8080", HTTP_TRUST_PROXY: "loopback" },
		});
		try {
			expect(handle.components.httpHostSettings?.port).toBe(8080);
			expect(handle.components.httpSettings?.trustProxy).toEqual(["loopback"]);
		} finally {
			await handle.dispose();
		}
	});

	it("HTTP_CORS_ALLOWED_ORIGINS", async () => {
		const handle = await bootTemplate({
			files: withoutApplicationBindings(),
			env: { HTTP_CORS_ALLOWED_ORIGINS: "https://env.example.com" },
		});
		try {
			expect(handle.components.httpSettings?.cors.allowedOrigins).toEqual([
				"https://env.example.com",
			]);
		} finally {
			await handle.dispose();
		}
	});

	it("REDIS_CLIENTS_URL and REDIS_CLIENTS_PASSWORD", async () => {
		const redis = await listeningRedis();
		const handle = await bootTemplate({
			redis: true,
			files: withoutApplicationBindings(),
			env: {
				REDIS_CLIENTS_URL: `redis://127.0.0.1:${redis.port}`,
				REDIS_CLIENTS_PASSWORD: "trimmed-file-password",
			},
		});
		try {
			await vi.waitFor(() => expect(redis.received()).toContain("trimmed-file-password"), {
				timeout: 10_000,
			});
		} finally {
			await handle.dispose().catch(() => {});
			await redis.close();
		}
	});
});

describe("key-store", () => {
	it("owns key-store, and reads it as its section rather than the configuration", () => {
		expect(keyStoreModule.name).toBe("key-store");
		expect(keyStoreModule.section?.at).toBeUndefined();
		expect(keyStoreModule.section?.reference?.href).toBe(TEMPLATE_REFERENCE.href);
		expect(keyStoreModule.requires ?? []).not.toContain("config");
		expect(keyStoreModule.optional ?? []).not.toContain("config");
	});

	it("builds the shipped EdDSA key store, kid v0, from the key pair the environment supplies", async () => {
		const handle = await bootTemplate();
		try {
			expect(handle.components.keyStore?.algorithm).toBe("EdDSA");
			expect(handle.components.keyStore?.getSigningKidFallback()).toBe("v0");
		} finally {
			await handle.dispose();
		}
	});

	it("builds an HS256 key store under KEY_STORE_LOCAL_ALGORITHM and KEY_STORE_LOCAL_SECRET, with the kid KEY_STORE_LOCAL_KID names", async () => {
		const handle = await bootTemplate({
			env: {
				KEY_STORE_LOCAL_PRIVATE_KEY: undefined,
				KEY_STORE_LOCAL_PUBLIC_KEY: undefined,
				KEY_STORE_LOCAL_ALGORITHM: "HS256",
				KEY_STORE_LOCAL_SECRET: "own-modules-hs256-secret.at-least-32-bytes.ok",
				KEY_STORE_LOCAL_KID: "k-env",
			},
		});
		try {
			expect(handle.components.keyStore?.algorithm).toBe("HS256");
			expect(handle.components.keyStore?.getSigningKidFallback()).toBe("k-env");
		} finally {
			await handle.dispose();
		}
	});

	it("takes a kid an operator writes in HOCON", async () => {
		const handle = await bootTemplate({ hocon: 'key-store.local.kid = "k-hocon"\n' });
		try {
			expect(handle.components.keyStore?.getSigningKidFallback()).toBe("k-hocon");
		} finally {
			await handle.dispose();
		}
	});

	it("ships core's default algorithm, and no key material", () => {
		const shipped = parseFile(fileURLToPath(TEMPLATE_REFERENCE), { env: {} }).toObject() as {
			"key-store": { provider: unknown; local: Record<string, unknown> };
		};
		expect(shipped["key-store"].provider).toBe("local");
		expect(shipped["key-store"].local).toEqual({
			algorithm: DEFAULT_SIGNING_ALGORITHM,
			kid: "v0",
		});
	});

	it("refuses to boot with no key material, naming the variables to set and how to make a key pair", async () => {
		const booting = bootTemplate({
			env: { KEY_STORE_LOCAL_PRIVATE_KEY: undefined, KEY_STORE_LOCAL_PUBLIC_KEY: undefined },
		});
		await expect(booting).rejects.toThrow(/KEY_STORE_LOCAL_PRIVATE_KEY_PATH/);
		await expect(booting).rejects.toThrow(/KEY_STORE_LOCAL_PUBLIC_KEY_PATH/);
		await expect(booting).rejects.toThrow(/key-store\.local\.privateKeyPath/);
		await expect(booting).rejects.toThrow(/openssl genpkey -algorithm ed25519/i);
	});

	it("refuses to boot on KEY_STORE_LOCAL_SECRET alone, saying how to opt into HS256", async () => {
		await expect(
			bootTemplate({
				env: {
					KEY_STORE_LOCAL_PRIVATE_KEY: undefined,
					KEY_STORE_LOCAL_PUBLIC_KEY: undefined,
					KEY_STORE_LOCAL_SECRET: "own-modules-hs256-secret.at-least-32-bytes.ok",
				},
			}),
		).rejects.toThrow(/KEY_STORE_LOCAL_ALGORITHM=HS256/);
	});

	it("refuses to boot on an HS256 secret below 32 bytes, naming the key and its variable", async () => {
		const booting = bootTemplate({
			env: {
				KEY_STORE_LOCAL_PRIVATE_KEY: undefined,
				KEY_STORE_LOCAL_PUBLIC_KEY: undefined,
				KEY_STORE_LOCAL_ALGORITHM: "HS256",
				KEY_STORE_LOCAL_SECRET: "too-short-a-secret",
			},
		});
		await expect(booting).rejects.toThrow(/at least 32 bytes/i);
		await expect(booting).rejects.toThrow(/key-store\.local\.secret/);
		await expect(booting).rejects.toThrow(/KEY_STORE_LOCAL_SECRET/);
	});

	it("refuses a key store section its schema refuses at boot, naming the operator's path", async () => {
		await expect(bootTemplate({ hocon: 'key-store.local.algorithm = "none"\n' })).rejects.toThrow(
			/key-store\.local/,
		);
	});

	it("has boot refuse each key at oauth.jwt.signingKey, the path it moved from, naming its new path and variable", async () => {
		await expect(
			bootTemplate({
				hocon: 'oauth.jwt.signingKey { provider = "local", local.kid = "k-old" }\n',
			}),
		).rejects.toMatchObject({
			details: {
				reason: "config-path-relocated",
				relocated: expect.arrayContaining([
					{
						module: "key-store",
						from: "oauth.jwt.signingKey.provider",
						to: "key-store.provider",
						environmentVariable: "KEY_STORE_PROVIDER",
					},
					{
						module: "key-store",
						from: "oauth.jwt.signingKey.local.kid",
						to: "key-store.local.kid",
						environmentVariable: "KEY_STORE_LOCAL_KID",
					},
				]),
			},
		});
	});

	it.each([
		["OAUTH_JWT_SIGNING_KEY_PROVIDER", "KEY_STORE_PROVIDER", "key-store.provider", "local"],
		["OAUTH_JWT_ALGORITHM", "KEY_STORE_LOCAL_ALGORITHM", "key-store.local.algorithm", "EdDSA"],
		["OAUTH_JWT_KID", "KEY_STORE_LOCAL_KID", "key-store.local.kid", "k-renamed"],
		[
			"OAUTH_JWT_SECRET",
			"KEY_STORE_LOCAL_SECRET",
			"key-store.local.secret",
			"own-modules-hs256-secret.at-least-32-bytes.ok",
		],
		[
			"OAUTH_JWT_PRIVATE_KEY_PATH",
			"KEY_STORE_LOCAL_PRIVATE_KEY_PATH",
			"key-store.local.privateKeyPath",
			"/keys/private.pem",
		],
		[
			"OAUTH_JWT_PUBLIC_KEY_PATH",
			"KEY_STORE_LOCAL_PUBLIC_KEY_PATH",
			"key-store.local.publicKeyPath",
			"/keys/public.pem",
		],
		[
			"OAUTH_JWT_PRIVATE_KEY",
			"KEY_STORE_LOCAL_PRIVATE_KEY",
			"key-store.local.privateKey",
			signingKey.privateKey,
		],
		[
			"OAUTH_JWT_PUBLIC_KEY",
			"KEY_STORE_LOCAL_PUBLIC_KEY",
			"key-store.local.publicKey",
			signingKey.publicKey,
		],
	])("has boot refuse %s set alone, naming %s", async (from, to, path, value) => {
		await expect(bootTemplate({ env: { [from]: value, [to]: undefined } })).rejects.toMatchObject({
			details: {
				reason: "environment-variable-renamed",
				renamed: [{ module: "key-store", from, to, path, state: "unset" }],
			},
		});
	});

	it("boots with each old name beside its new one at the same value", async () => {
		const handle = await bootTemplate({
			env: {
				OAUTH_JWT_PRIVATE_KEY: signingKey.privateKey,
				OAUTH_JWT_PUBLIC_KEY: signingKey.publicKey,
				OAUTH_JWT_KID: "k-both",
				KEY_STORE_LOCAL_KID: "k-both",
			},
		});
		try {
			expect(handle.components.keyStore?.getSigningKidFallback()).toBe("k-both");
		} finally {
			await handle.dispose();
		}
	});
});

/**
 * A TCP server standing in for Redis: it records what each connection sends
 * and answers nothing, so a client dialled at it connects and writes its
 * handshake.
 */
async function listeningRedis(): Promise<{
	readonly port: number;
	readonly received: () => string;
	readonly close: () => Promise<void>;
}> {
	const sockets = new Set<Socket>();
	let received = "";
	const server = createServer((socket) => {
		sockets.add(socket);
		socket.on("close", () => sockets.delete(socket));
		socket.on("data", (chunk) => {
			received += chunk.toString("utf8");
		});
	});
	server.listen(0, "127.0.0.1");
	await once(server, "listening");
	const { port } = server.address() as AddressInfo;
	return {
		port,
		received: () => received,
		close: async () => {
			for (const socket of sockets) socket.destroy();
			await new Promise<void>((resolve) => server.close(() => resolve()));
		},
	};
}

describe("redis-clients", () => {
	it("owns redis-clients, and reads it as its section rather than the configuration", () => {
		expect(standaloneRedisClientsModule.name).toBe("redis-clients");
		expect(standaloneRedisClientsModule.section?.at).toBeUndefined();
		expect(standaloneRedisClientsModule.section?.reference?.href).toBe(TEMPLATE_REFERENCE.href);
		expect(standaloneRedisClientsModule.requires ?? []).not.toContain("config");
		expect(standaloneRedisClientsModule.optional ?? []).not.toContain("config");
	});

	it("is loaded by the shipped composition, whose refresh-token family store is on Redis", () => {
		const own = readOwnLayers(ownFiles(), { env: BASE_ENV });
		const modules = buildModules(readSwitches(own), { environment: "development" });
		expect(named(modules, "redis-clients")).toBe(standaloneRedisClientsModule);
	});

	it("dials the URL REDIS_CLIENTS_URL names, with the password REDIS_CLIENTS_PASSWORD names", async () => {
		const redis = await listeningRedis();
		const password = "own-modules-redis-password";
		const handle = await bootTemplate({
			redis: true,
			env: {
				REDIS_CLIENTS_URL: `redis://127.0.0.1:${redis.port}`,
				REDIS_CLIENTS_PASSWORD: password,
			},
		});
		try {
			await vi.waitFor(() => expect(redis.received()).toContain(password), { timeout: 10_000 });
		} finally {
			await handle.dispose().catch(() => {});
			await redis.close();
		}
	});

	it("dials the URL an operator writes in HOCON", async () => {
		const redis = await listeningRedis();
		const handle = await bootTemplate({
			redis: true,
			hocon: `redis-clients { url = "redis://127.0.0.1:${redis.port}", password = "from-hocon-password" }\n`,
		});
		try {
			await vi.waitFor(() => expect(redis.received()).toContain("from-hocon-password"), {
				timeout: 10_000,
			});
		} finally {
			await handle.dispose().catch(() => {});
			await redis.close();
		}
	});

	it("refuses a null URL at boot, naming the key", async () => {
		await expect(
			bootTemplate({ redis: true, hocon: "redis-clients.url = null\n" }),
		).rejects.toThrow(/redis-clients\.url/);
	});

	it("refuses a configuration without its section at boot, naming the section: its own parse", async () => {
		await expect(
			bootTemplate({
				redis: true,
				adjust: ({ "redis-clients": _dropped, ...rest }) => rest,
			}),
		).rejects.toThrow(/redis-clients/);
	});

	it("refuses an empty URL when a client is built, naming the key and its variable", async () => {
		await expect(bootTemplate({ redis: true, env: { REDIS_CLIENTS_URL: "" } })).rejects.toThrow(
			/redis-clients\.url.*REDIS_CLIENTS_URL/s,
		);
	});

	it("has boot refuse refreshTokenFamilyStore.redis, the path it moved from, naming the new paths and variables", async () => {
		const err = await bootTemplate({
			redis: true,
			hocon: 'refreshTokenFamilyStore.redis { url = "redis://127.0.0.1:9", password = "p" }\n',
		}).then(
			() => undefined,
			(thrown: unknown) => thrown,
		);
		expect(err).toBeInstanceOf(BootError);
		expect((err as BootError).details).toEqual({
			reason: "config-path-relocated",
			relocated: [
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
			],
		});
	});

	it.each([
		["REFRESH_TOKEN_FAMILY_STORE_REDIS_URL", "REDIS_CLIENTS_URL", "redis-clients.url"],
		[
			"REFRESH_TOKEN_FAMILY_STORE_REDIS_PASSWORD",
			"REDIS_CLIENTS_PASSWORD",
			"redis-clients.password",
		],
	])("has boot refuse %s set alone, naming %s", async (from, to, path) => {
		await expect(
			bootTemplate({ redis: true, env: { [from]: "redis://127.0.0.1:9" } }),
		).rejects.toMatchObject({
			details: {
				reason: "environment-variable-renamed",
				renamed: [{ module: "redis-clients", from, to, path, state: "unset" }],
			},
		});
	});
});

/** A YAML file of `text` in a directory removed after the suite. */
function yamlFile(name: string, text: string): string {
	const dir = mkdtempSync(join(tmpdir(), "own-modules-yaml-"));
	operatorDirs.push(dir);
	const file = join(dir, name);
	writeFileSync(file, text);
	return file;
}

/** The value at a dotted path of the configuration boot parsed. */
function parsedAt(handle: AppHandle, path: string): unknown {
	let cursor: unknown = handle.components.config;
	for (const key of path.split(".")) {
		if (typeof cursor !== "object" || cursor === null) return undefined;
		cursor = (cursor as Record<string, unknown>)[key];
	}
	return cursor;
}

/** Each variable the repositories module renamed: old name, new name, path, a value. */
const REPOSITORY_RENAMES = [
	["CLIENT_PATH", "REPOSITORIES_CLIENT_YAML_PATH", "repositories.client.yaml.path", "./x.yaml"],
	["CLIENT_USER_PATH", "REPOSITORIES_USER_YAML_PATH", "repositories.user.yaml.path", "./y.yaml"],
	...(
		[
			["AUTHENTICATE_URL", "authenticateUrl", "https://store.example/authenticate"],
			["AUTHENTICATE_BY_TOKEN_URL", "authenticateByTokenUrl", "https://store.example/by-token"],
			["LINK_FEDERATED_IDENTITY_URL", "linkFederatedIdentityUrl", "https://store.example/link"],
			[
				"FIND_SUBJECT_BY_FEDERATED_IDENTITY_URL",
				"findSubjectByFederatedIdentityUrl",
				"https://store.example/find",
			],
			[
				"BEARER_TOKEN",
				"bearerToken",
				"0328d706529061d93abd6d826e09ef0f0a1e71a12af813b29e5cd2977b7dc63a",
			],
			["TIMEOUT", "timeout", "3000"],
			["MAX_RESPONSE_BYTES", "maxResponseBytes", "2048"],
		] as const
	).map(
		([name, key, value]) =>
			[
				`CLIENT_USER_${name}`,
				`REPOSITORIES_USER_HTTP_${name}`,
				`repositories.user.http.${key}`,
				value,
			] as const,
	),
] as const;

describe("repositories", () => {
	it("owns repositories, and reads it as its section rather than the configuration", async () => {
		const own = readOwnLayers(ownFiles(), { env: BASE_ENV });
		const modules = buildModules(readSwitches(own), { environment: "development" });
		const repositories = named(modules, "repositories");
		expect(repositories.section?.at).toBeUndefined();
		expect(repositories.section?.reference?.href).toBe(TEMPLATE_REFERENCE.href);
		expect(repositories.requires ?? []).not.toContain("config");
		expect(repositories.optional ?? []).not.toContain("config");
	});

	it("reads the client registry and the users from the YAML files REPOSITORIES_*_YAML_PATH name", async () => {
		const clients = yamlFile(
			"clients.yaml",
			"yaml-client:\n  tokenEndpointAuthMethod: none\n  allowedRedirectUris: []\n",
		);
		const users = yamlFile("users.yaml", "");
		const handle = await bootTemplate({
			repositories: true,
			env: { REPOSITORIES_CLIENT_YAML_PATH: clients, REPOSITORIES_USER_YAML_PATH: users },
		});
		try {
			expect(parsedAt(handle, "repositories.client.yaml.path")).toBe(clients);
			expect(await handle.components.clientRepository?.findById("yaml-client")).toBeDefined();
		} finally {
			await handle.dispose();
		}
	});

	it("builds the Store's HTTP user repository under ADAPTERS_USER_REPOSITORY=http, from REPOSITORIES_USER_HTTP_*", async () => {
		const clients = yamlFile("clients.yaml", "");
		const handle = await bootTemplate({
			repositories: true,
			env: {
				ADAPTERS_USER_REPOSITORY: "http",
				REPOSITORIES_CLIENT_YAML_PATH: clients,
				REPOSITORIES_USER_HTTP_AUTHENTICATE_URL: "https://store.example/authenticate",
				REPOSITORIES_USER_HTTP_AUTHENTICATE_BY_TOKEN_URL: "https://store.example/by-token",
				REPOSITORIES_USER_HTTP_LINK_FEDERATED_IDENTITY_URL: "https://store.example/link",
			},
		});
		try {
			const users = handle.components.userRepository;
			expect(users).toBeInstanceOf(HttpUserRepository);
			expect((users as HttpUserRepository).linkFederatedIdentity).toBeDefined();
			expect(parsedAt(handle, "repositories.user.http.timeout")).toBe(5000);
		} finally {
			await handle.dispose();
		}
	});

	/** `repositories` as the template's reference resolves it under `env`, parsed with the module's schema. */
	const referenced = (env: Record<string, string> = {}) =>
		repositoriesSectionSchema.parse(
			(parseFile(fileURLToPath(TEMPLATE_REFERENCE), { env }).toObject() as Record<string, unknown>)
				.repositories,
		).user.http;

	it.each([
		[
			"REPOSITORIES_USER_HTTP_LINK_FEDERATED_IDENTITY_URL",
			"linkFederatedIdentityUrl",
			"https://store.example/link",
		],
		[
			"REPOSITORIES_USER_HTTP_FIND_SUBJECT_BY_FEDERATED_IDENTITY_URL",
			"findSubjectByFederatedIdentityUrl",
			"https://store.example/identity",
		],
		[
			"REPOSITORIES_USER_HTTP_BEARER_TOKEN",
			"bearerToken",
			"0328d706529061d93abd6d826e09ef0f0a1e71a12af813b29e5cd2977b7dc63a",
		],
		[
			"REPOSITORIES_USER_HTTP_MARK_MFA_ENROLLED_URL",
			"markMfaEnrolledUrl",
			"https://store.example/mfa/enrolled",
		],
	])(
		"binds %s at repositories.user.http.%s, and leaves the key absent while it is unset",
		(variable, key, value) => {
			// Absent, not blank: the repository defines the seam a URL enables only
			// when the URL is there, and refuses a blank credential.
			expect(referenced({ [variable]: value })).toHaveProperty(key, value);
			expect(referenced()).not.toHaveProperty(key);
		},
	);

	it("builds a user repository that writes the MFA enrollment witness with REPOSITORIES_USER_HTTP_MARK_MFA_ENROLLED_URL, and one that does not without it", async () => {
		const clients = yamlFile("clients.yaml", "");
		const env = {
			ADAPTERS_USER_REPOSITORY: "http",
			REPOSITORIES_CLIENT_YAML_PATH: clients,
			REPOSITORIES_USER_HTTP_AUTHENTICATE_URL: "https://store.example/authenticate",
			REPOSITORIES_USER_HTTP_AUTHENTICATE_BY_TOKEN_URL: "https://store.example/by-token",
		};
		for (const [url, writes] of [
			["https://store.example/mfa/enrolled", true],
			[undefined, false],
		] as const) {
			const handle = await bootTemplate({
				repositories: true,
				env: { ...env, REPOSITORIES_USER_HTTP_MARK_MFA_ENROLLED_URL: url },
			});
			try {
				const users = handle.components.userRepository;
				expect(users).toBeInstanceOf(HttpUserRepository);
				expect(supportsMfaEnrollmentWitness(users as HttpUserRepository), String(url)).toBe(writes);
			} finally {
				await handle.dispose();
			}
		}
	});

	it("refuses the boot for a witness URL that is not https or loopback http, naming markMfaEnrolledUrl and quoting no value", async () => {
		const clients = yamlFile("clients.yaml", "");
		for (const url of [
			"http://store.internal/mfa/enrolled?key=QUERY-SECRET",
			"https://user:QUERY-SECRET@store.example/mfa/enrolled",
		]) {
			const refused = await bootTemplate({
				repositories: true,
				env: {
					ADAPTERS_USER_REPOSITORY: "http",
					REPOSITORIES_CLIENT_YAML_PATH: clients,
					REPOSITORIES_USER_HTTP_AUTHENTICATE_URL: "https://store.example/authenticate",
					REPOSITORIES_USER_HTTP_AUTHENTICATE_BY_TOKEN_URL: "https://store.example/by-token",
					REPOSITORIES_USER_HTTP_MARK_MFA_ENROLLED_URL: url,
				},
			}).then(
				async (handle) => {
					await handle.dispose();
					return undefined;
				},
				(error: unknown) => error,
			);
			expect(refused, url).toBeInstanceOf(BootError);
			expect((refused as BootError).reason, url).toBe("provides-factory-failed");
			const text = `${(refused as BootError).message} ${String(((refused as BootError).cause as Error | undefined)?.message)}`;
			expect(text, url).toContain('"markMfaEnrolledUrl"');
			expect(text, url).not.toContain("QUERY-SECRET");
		}
	});

	it("ships an empty identity-lookup coverage declaration, which reaches the factory as a list", () => {
		expect(referenced().federatedIdentityLookupCoverage).toEqual([]);
	});

	it("reads the client registry and the users under static, core's alias of yaml, from its own blocks", async () => {
		const clients = yamlFile(
			"clients.yaml",
			"static-client:\n  tokenEndpointAuthMethod: none\n  allowedRedirectUris: []\n",
		);
		const users = yamlFile("users.yaml", "");
		const handle = await bootTemplate({
			repositories: true,
			env: { ADAPTERS_CLIENT_REPOSITORY: "static", ADAPTERS_USER_REPOSITORY: "static" },
			hocon: `repositories.client.static.path = "${clients}"\nrepositories.user.static.path = "${users}"\n`,
		});
		try {
			expect(parsedAt(handle, "repositories.client.static.path")).toBe(clients);
			expect(await handle.components.clientRepository?.findById("static-client")).toBeDefined();
			expect(handle.components.userRepository).toBeDefined();
		} finally {
			await handle.dispose();
		}
	});

	it.each([
		["ADAPTERS_CLIENT_REPOSITORY", "repositories.client.static.path"],
		["ADAPTERS_USER_REPOSITORY", "repositories.user.static.path"],
	])(
		"refuses %s=static without %s at the section's parse, before any repository is built, naming it",
		async (variable, path) => {
			// The client registry's file is absent, as in a fresh copy of the
			// template: the refusal comes before any repository reads a file.
			await expect(
				bootTemplate({
					repositories: true,
					env: { [variable]: "static", REPOSITORIES_CLIENT_YAML_PATH: "/nonexistent/clients.yaml" },
				}),
			).rejects.toMatchObject({
				reason: "config-validation-failed",
				message: expect.stringContaining(path),
			});
		},
	);

	it("refuses a key the section does not declare, naming it", async () => {
		await expect(
			bootTemplate({ repositories: true, hocon: 'repositories.user.ldap.url = "ldap://x"\n' }),
		).rejects.toMatchObject({
			reason: "config-validation-failed",
			message: expect.stringContaining('"ldap"'),
		});
	});

	it.each(REPOSITORY_RENAMES)(
		"has boot refuse %s set alone, naming %s and %s",
		async (from, to, path, value) => {
			await expect(
				bootTemplate({ repositories: true, env: { [from]: value } }),
			).rejects.toMatchObject({
				details: {
					reason: "environment-variable-renamed",
					renamed: [{ module: "repositories", from, to, path, state: "unset" }],
				},
			});
		},
	);
});

describe("standalone-in-memory-code-repository", () => {
	it("reads its own section, which STANDALONE_IN_MEMORY_CODE_REPOSITORY_DEFAULT_EXPIRES_IN sets", async () => {
		const handle = await bootTemplate({
			env: { STANDALONE_IN_MEMORY_CODE_REPOSITORY_DEFAULT_EXPIRES_IN: "900" },
		});
		try {
			expect(parsedAt(handle, "standalone-in-memory-code-repository.defaultExpiresIn")).toBe(900);
		} finally {
			await handle.dispose();
		}
	});

	it("refuses a lifetime that is not positive whole seconds, naming the key", async () => {
		await expect(
			bootTemplate({ env: { STANDALONE_IN_MEMORY_CODE_REPOSITORY_DEFAULT_EXPIRES_IN: "0" } }),
		).rejects.toThrow(/standalone-in-memory-code-repository\.defaultExpiresIn/);
	});

	it("has boot refuse repositories.code.memory, the path it moved from, and repositories.code.redis, removed", async () => {
		await expect(
			bootTemplate({
				hocon:
					'repositories.code { memory.defaultExpiresIn = 900, redis.endpointUri = "redis://x" }\n',
			}),
		).rejects.toMatchObject({
			details: {
				reason: "config-path-relocated",
				relocated: [
					{
						module: "standalone-in-memory-code-repository",
						from: "repositories.code.memory.defaultExpiresIn",
						to: "standalone-in-memory-code-repository.defaultExpiresIn",
						environmentVariable: "STANDALONE_IN_MEMORY_CODE_REPOSITORY_DEFAULT_EXPIRES_IN",
					},
					{
						module: "standalone-in-memory-code-repository",
						from: "repositories.code.redis.endpointUri",
						to: null,
					},
				],
			},
		});
	});

	it.each([
		[
			"CLIENT_CODE_DEFAULT_EXPIRES_IN",
			"900",
			{
				to: "STANDALONE_IN_MEMORY_CODE_REPOSITORY_DEFAULT_EXPIRES_IN",
				path: "standalone-in-memory-code-repository.defaultExpiresIn",
				state: "unset",
			},
		],
		["CLIENT_CODE_ENDPOINT_URI", "redis://x", { to: null, path: null, state: "removed" }],
		["CLIENT_CODE_PASSWORD", "p", { to: null, path: null, state: "removed" }],
	])("has boot refuse %s", async (from, value, expected) => {
		await expect(bootTemplate({ env: { [from]: value } })).rejects.toMatchObject({
			details: {
				reason: "environment-variable-renamed",
				renamed: [{ module: "standalone-in-memory-code-repository", from, ...expected }],
			},
		});
	});
});

describe("audit-sink", () => {
	it("builds the sink ADAPTERS_AUDIT_SINK names, the template's logger by default", async () => {
		const shipped = await bootTemplate();
		const console = await bootTemplate({ env: { ADAPTERS_AUDIT_SINK: "console" } });
		try {
			expect(shipped.components.auditSink?.kind).toBe("logger");
			expect(console.components.auditSink?.kind).toBe("console");
		} finally {
			await shipped.dispose();
			await console.dispose();
		}
	});

	it("reads its own section, audit-sink, and requires no configuration", () => {
		const own = readOwnLayers(ownFiles(), { env: BASE_ENV });
		const sink = named(
			buildModules(readSwitches(own), { environment: "development" }),
			"audit-sink",
		);
		expect(sink.section?.at).toBeUndefined();
		expect(sink.requires ?? []).not.toContain("config");
	});

	it("has boot refuse a sink's options at audit.sink, the path they moved from, naming audit-sink", async () => {
		await expect(
			bootTemplate({ hocon: "audit.sink.console.pretty = true\n" }),
		).rejects.toMatchObject({
			details: {
				reason: "config-path-relocated",
				relocated: [
					{
						module: "audit-sink",
						from: "audit.sink.console.pretty",
						to: "audit-sink.console.pretty",
					},
				],
			},
		});
	});
});
