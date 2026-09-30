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
 * The template's own modules: each owns a section of the configuration, at
 * the path it declares, with its defaults in the template's
 * `config/reference.conf`, and reads it through `deps.section`, never the
 * whole configuration. What each section sets reaches the process, for the
 * shipped configuration and for an operator's environment and HOCON
 * overrides, through the template's real path: `readOwnLayers`, then
 * `resolveForBoot` over every loaded module's reference, then `createApp`.
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
	coreReference,
	createApp,
	DEFAULT_SIGNING_ALGORITHM,
	defineModule,
	InMemoryClientRepository,
	InMemoryUserRepository,
	type Logger,
	type Module,
	memoryRefreshTokenFamilyStoreModule,
	moduleReferences,
} from "@o3co/auth-provider-core";
import { httpSettingsContract, packageReferenceProblems } from "@o3co/auth-provider-core/testing";
import { parseFile } from "@o3co/ts.hocon";
import express from "express";
import request from "supertest";
import { afterAll, describe, expect, it, vi } from "vitest";
import { buildModules } from "../buildModules.mjs";
import {
	expectedSessionRequirements,
	readLogging,
	readOwnLayers,
	readSwitches,
	resolveConfigPaths,
	resolveForBoot,
	resolveLayers,
	SWITCHES,
} from "../configPath.mjs";
import { createAppLogger } from "../logger.mjs";
import {
	corsModule,
	httpModule,
	keyStoreModule,
	loggingModule,
	standaloneRedisClientsModule,
} from "../modules.mjs";

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
	OAUTH_JWT_PRIVATE_KEY: signingKey.privateKey,
	OAUTH_JWT_PUBLIC_KEY: signingKey.publicKey,
	SESSION_SECRET: "own-modules-session-secret.at-least-32-bytes.ok",
	SESSION_SECURE: "false",
	SESSION_NAME: "auth.session",
	SESSION_STORAGE_TYPE: "memory",
	CLIENT_USER_TYPE: "yaml",
	DEPLOYMENT_MODE: "single",
	OAUTH_CODE_ADAPTER: "memory",
	ACCESS_TOKEN_DENYLIST_ADAPTER: "memory",
	REPLAY_SEEN_SET_ADAPTER: "memory",
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
		repositoriesModule: testRepositoriesModule,
		...(options.redis ? {} : { refreshTokenFamilyModules: [memoryRefreshTokenFamilyStoreModule] }),
	});
	const resolved = resolveForBoot(own, modules, expectedSessionRequirements(switches));
	return createApp({
		modules,
		bootstrapComponents: {
			config: (options.adjust
				? options.adjust({ ...(resolved as unknown as Record<string, unknown>) })
				: resolved) as typeof resolved,
			pathResolver: (s: string) => s,
			logger: silentLogger(),
		},
	});
}

/** The module in `modules` named `name`. */
const named = (modules: readonly Module[], name: string): Module => {
	const found = modules.find((module) => module.name === name);
	if (found === undefined) throw new Error(`no module named ${name}`);
	return found;
};

describe("the template's config/reference.conf", () => {
	it("holds only its own modules' sections, each of which parses its part without losing a path", () => {
		expect(
			packageReferenceProblems({
				reference: TEMPLATE_REFERENCE,
				modules: [
					loggingModule,
					httpModule,
					corsModule,
					keyStoreModule,
					standaloneRedisClientsModule,
				],
				read: (path) => parseFile(path, { env: {} }).toObject(),
			}),
		).toEqual([]);
	});

	it("is layered beneath the template's own files whenever one of its modules is loaded", () => {
		const own = readOwnLayers(ownFiles(), { env: BASE_ENV });
		const modules = buildModules(readSwitches(own), { environment: "development" });
		expect(moduleReferences(modules).map((url) => url.href)).toContain(TEMPLATE_REFERENCE.href);
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

	it("is loaded by the shipped composition, so boot parses its section", () => {
		const own = readOwnLayers(ownFiles(), { env: BASE_ENV });
		const modules = buildModules(readSwitches(own), { environment: "development" });
		expect(named(modules, "logging")).toBe(loggingModule);
	});

	it("is not among SWITCHES", () => {
		expect(SWITCHES).not.toContain("logging");
	});

	it.each([
		["the shipped default", {}, undefined, "info"],
		["LOG_LEVEL", { LOG_LEVEL: "debug" }, undefined, "debug"],
		["HOCON an operator writes", {}, 'logging.level = "warn"\n', "warn"],
		["HOCON over LOG_LEVEL", { LOG_LEVEL: "debug" }, 'logging.level = "error"\n', "error"],
	])("gives the logger the level %s sets", (_name, env, hocon, level) => {
		const own = readOwnLayers(ownFiles(hocon), { env: { ...BASE_ENV, ...env } });
		expect(readLogging(own)).toEqual({ level });
		const logger = createAppLogger(readLogging(own)) as unknown as { readonly level: string };
		expect(logger.level).toBe(level);
	});

	it("refuses a level it does not know before boot, naming logging.level", () => {
		const own = readOwnLayers(ownFiles(), { env: { ...BASE_ENV, LOG_LEVEL: "verbose" } });
		expect(() => readLogging(own)).toThrow(/logging\.level/);
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
	it("owns http, reads the CORS list through the cors module's slot, and requires no configuration", () => {
		expect(httpModule.name).toBe("http");
		expect(httpModule.section?.at).toBeUndefined();
		expect(httpModule.section?.reference?.href).toBe(TEMPLATE_REFERENCE.href);
		expect(httpModule.requires ?? []).toEqual(["corsAllowedOrigins"]);
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

	it("is loaded by the shipped composition, with the cors module", () => {
		const own = readOwnLayers(ownFiles(), { env: BASE_ENV });
		const modules = buildModules(readSwitches(own), { environment: "development" });
		expect(named(modules, "http")).toBe(httpModule);
		expect(named(modules, "cors")).toBe(corsModule);
	});

	describe("the httpSettings it provides keeps the slot's contract", () => {
		for (const [name, env] of [
			["for the shipped configuration", {}],
			[
				"for an operator's overrides",
				{
					HTTP_TRUST_PROXY: "10.0.0.0/8,loopback",
					CORS_ALLOWED_ORIGINS: "https://app.example.com,http://localhost:5173",
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

	it("refuses a trust proxy entry that is not an address, a range or a named range at boot, naming http.trustProxy", async () => {
		await expect(bootTemplate({ env: { HTTP_TRUST_PROXY: "proxy.internal" } })).rejects.toThrow(
			/http\.trustProxy/,
		);
	});
});

describe("cors", () => {
	it.each([
		["with CORS_ALLOWED_ORIGINS unset", {}],
		[
			"with a list in CORS_ALLOWED_ORIGINS",
			{ CORS_ALLOWED_ORIGINS: "https://a.example,https://b.example" },
		],
		["with CORS_ALLOWED_ORIGINS empty", { CORS_ALLOWED_ORIGINS: "" }],
	])(
		"resolves its application.conf over its reference as core's reference resolves alone, which core reads without httpSettings, %s",
		(_name, env) => {
			const { applicationConfPath } = resolveConfigPaths(configDir, "development");
			const template = resolveLayers(readOwnLayers([applicationConfPath], { env }), [
				TEMPLATE_REFERENCE,
			]).cors;
			const core = (
				parseFile(fileURLToPath(coreReference()), { env }).toObject() as { cors?: unknown }
			).cors;
			expect(template).toEqual(core);
			expect(template).toBeDefined();
		},
	);

	it("owns cors, and requires nothing", () => {
		expect(corsModule.name).toBe("cors");
		expect(corsModule.section?.at).toBeUndefined();
		expect(corsModule.section?.reference?.href).toBe(TEMPLATE_REFERENCE.href);
		expect(corsModule.requires ?? []).toEqual([]);
		expect(corsModule.optional ?? []).toEqual([]);
		expect(Object.keys(corsModule.provides ?? {})).toEqual(["corsAllowedOrigins"]);
	});

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
		["CORS_ALLOWED_ORIGINS", { CORS_ALLOWED_ORIGINS: "https://app.example.com" }, undefined],
		["HOCON an operator writes", {}, 'cors.allowedOrigins = ["https://app.example.com"]\n'],
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

	it("refuses an origin that could never match at boot, naming cors.allowedOrigins", async () => {
		await expect(
			bootTemplate({ env: { CORS_ALLOWED_ORIGINS: "https://app.example.com/" } }),
		).rejects.toThrow(/cors\.allowedOrigins/);
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

	it("CORS_ALLOWED_ORIGINS over cors.allowedOrigins", async () => {
		const handle = await bootTemplate({
			files: withApplicationValues('cors.allowedOrigins = ["https://file.example.com"]'),
			env: { CORS_ALLOWED_ORIGINS: "https://env.example.com" },
		});
		try {
			expect(handle.components.httpSettings?.cors.allowedOrigins).toEqual([
				"https://env.example.com",
			]);
		} finally {
			await handle.dispose();
		}
	});

	it("REFRESH_TOKEN_FAMILY_STORE_REDIS_URL over refreshTokenFamilyStore.redis.url", async () => {
		const redis = await listeningRedis();
		const handle = await bootTemplate({
			redis: true,
			files: withApplicationValues('refreshTokenFamilyStore.redis.url = "redis://127.0.0.1:9"'),
			env: {
				REFRESH_TOKEN_FAMILY_STORE_REDIS_URL: `redis://127.0.0.1:${redis.port}`,
				REFRESH_TOKEN_FAMILY_STORE_REDIS_PASSWORD: "url-test-password",
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

	it("REFRESH_TOKEN_FAMILY_STORE_REDIS_PASSWORD over refreshTokenFamilyStore.redis.password", async () => {
		const redis = await listeningRedis();
		const handle = await bootTemplate({
			redis: true,
			files: withApplicationValues('refreshTokenFamilyStore.redis.password = "from-the-file"'),
			env: {
				REFRESH_TOKEN_FAMILY_STORE_REDIS_URL: `redis://127.0.0.1:${redis.port}`,
				REFRESH_TOKEN_FAMILY_STORE_REDIS_PASSWORD: "from-the-environment",
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

describe("key-store", () => {
	it("owns oauth.jwt.signingKey, and reads it as its section rather than the configuration", () => {
		expect(keyStoreModule.section?.at).toBe("oauth.jwt.signingKey");
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

	it("builds an HS256 key store under OAUTH_JWT_ALGORITHM and OAUTH_JWT_SECRET, with the kid OAUTH_JWT_KID names", async () => {
		const handle = await bootTemplate({
			env: {
				OAUTH_JWT_PRIVATE_KEY: undefined,
				OAUTH_JWT_PUBLIC_KEY: undefined,
				OAUTH_JWT_ALGORITHM: "HS256",
				OAUTH_JWT_SECRET: "own-modules-hs256-secret.at-least-32-bytes.ok",
				OAUTH_JWT_KID: "k-env",
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
		const handle = await bootTemplate({ hocon: 'oauth.jwt.signingKey.local.kid = "k-hocon"\n' });
		try {
			expect(handle.components.keyStore?.getSigningKidFallback()).toBe("k-hocon");
		} finally {
			await handle.dispose();
		}
	});

	it("ships core's default algorithm, and no key material", () => {
		const shipped = parseFile(fileURLToPath(TEMPLATE_REFERENCE), { env: {} }).toObject() as {
			oauth: { jwt: { signingKey: { provider: unknown; local: Record<string, unknown> } } };
		};
		expect(shipped.oauth.jwt.signingKey.provider).toBe("local");
		expect(shipped.oauth.jwt.signingKey.local).toEqual({
			algorithm: DEFAULT_SIGNING_ALGORITHM,
			kid: "v0",
		});
	});

	it("refuses to boot with no key material, naming the variables to set and how to make a key pair", async () => {
		const booting = bootTemplate({
			env: { OAUTH_JWT_PRIVATE_KEY: undefined, OAUTH_JWT_PUBLIC_KEY: undefined },
		});
		await expect(booting).rejects.toThrow(/OAUTH_JWT_PRIVATE_KEY_PATH/);
		await expect(booting).rejects.toThrow(/openssl genpkey -algorithm ed25519/i);
	});

	it("refuses to boot on OAUTH_JWT_SECRET alone, saying how to opt into HS256", async () => {
		await expect(
			bootTemplate({
				env: {
					OAUTH_JWT_PRIVATE_KEY: undefined,
					OAUTH_JWT_PUBLIC_KEY: undefined,
					OAUTH_JWT_SECRET: "own-modules-hs256-secret.at-least-32-bytes.ok",
				},
			}),
		).rejects.toThrow(/OAUTH_JWT_ALGORITHM=HS256/);
	});

	it("refuses to boot on an HS256 secret below 32 bytes", async () => {
		await expect(
			bootTemplate({
				env: {
					OAUTH_JWT_PRIVATE_KEY: undefined,
					OAUTH_JWT_PUBLIC_KEY: undefined,
					OAUTH_JWT_ALGORITHM: "HS256",
					OAUTH_JWT_SECRET: "too-short-a-secret",
				},
			}),
		).rejects.toThrow(/at least 32 bytes/i);
	});

	it("refuses a key store section its schema refuses at boot, naming the operator's path", async () => {
		await expect(
			bootTemplate({ hocon: 'oauth.jwt.signingKey.local.algorithm = "none"\n' }),
		).rejects.toThrow(/oauth\.jwt\.signingKey\.local/);
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
	it("owns refreshTokenFamilyStore.redis, and reads it as its section rather than the configuration", () => {
		expect(standaloneRedisClientsModule.section?.at).toBe("refreshTokenFamilyStore.redis");
		expect(standaloneRedisClientsModule.section?.reference?.href).toBe(TEMPLATE_REFERENCE.href);
		expect(standaloneRedisClientsModule.requires ?? []).not.toContain("config");
		expect(standaloneRedisClientsModule.optional ?? []).not.toContain("config");
	});

	it("is loaded by the shipped composition, whose refresh-token family store is on Redis", () => {
		const own = readOwnLayers(ownFiles(), { env: BASE_ENV });
		const modules = buildModules(readSwitches(own), { environment: "development" });
		expect(named(modules, "redis-clients")).toBe(standaloneRedisClientsModule);
	});

	it("dials the URL REFRESH_TOKEN_FAMILY_STORE_REDIS_URL names, with the password REFRESH_TOKEN_FAMILY_STORE_REDIS_PASSWORD names", async () => {
		const redis = await listeningRedis();
		const password = "own-modules-redis-password";
		const handle = await bootTemplate({
			redis: true,
			env: {
				REFRESH_TOKEN_FAMILY_STORE_REDIS_URL: `redis://127.0.0.1:${redis.port}`,
				REFRESH_TOKEN_FAMILY_STORE_REDIS_PASSWORD: password,
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
			hocon: `refreshTokenFamilyStore.redis { url = "redis://127.0.0.1:${redis.port}", password = "from-hocon-password" }\n`,
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
			bootTemplate({ redis: true, hocon: "refreshTokenFamilyStore.redis.url = null\n" }),
		).rejects.toThrow(/refreshTokenFamilyStore\.redis\.url/);
	});

	it("refuses a configuration without its section at boot, naming the section: its own parse", async () => {
		await expect(
			bootTemplate({
				redis: true,
				adjust: ({ refreshTokenFamilyStore: _dropped, ...rest }) => rest,
			}),
		).rejects.toThrow(/refreshTokenFamilyStore\.redis/);
	});

	it("refuses an empty URL when a client is built, naming the key and its variable", async () => {
		await expect(
			bootTemplate({ redis: true, env: { REFRESH_TOKEN_FAMILY_STORE_REDIS_URL: "" } }),
		).rejects.toThrow(/refreshTokenFamilyStore\.redis\.url.*REFRESH_TOKEN_FAMILY_STORE_REDIS_URL/s);
	});
});
