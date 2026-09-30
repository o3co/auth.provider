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
 * the path it is read at today, with its defaults in the template's
 * `config/reference.conf`, and reads it through `deps.section`, never the
 * whole configuration. What each section sets reaches the process as it did,
 * for the shipped configuration and for an operator's environment and HOCON
 * overrides, through the template's real path: `readOwnLayers`, then
 * `resolveForBoot` over every loaded module's reference, then `createApp`.
 */

import { generateKeyPairSync } from "node:crypto";
import { once } from "node:events";
import { mkdtempSync, writeFileSync } from "node:fs";
import { type AddressInfo, createServer, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
	type AppHandle,
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
import { packageReferenceProblems } from "@o3co/auth-provider-core/testing";
import { parseFile } from "@o3co/ts.hocon";
import { describe, expect, it, vi } from "vitest";
import { buildModules } from "../buildModules.mjs";
import {
	expectedSessionRequirements,
	readOwnLayers,
	readSwitches,
	resolveConfigPaths,
	resolveForBoot,
} from "../configPath.mjs";
import { keyStoreModule, standaloneRedisClientsModule } from "../modules.mjs";

const configDir = fileURLToPath(new URL("../../config", import.meta.url));
/** The template's own defaults: what its modules declare as their sections' reference. */
const TEMPLATE_REFERENCE = new URL("../../config/reference.conf", import.meta.url);

const signingKey = generateKeyPairSync("ed25519", {
	publicKeyEncoding: { type: "spki", format: "pem" },
	privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

/**
 * What the shipped configuration needs set to boot, every store in memory
 * but where a test asks for Redis: the issuer, the shipped EdDSA key pair
 * inline, and the session secret.
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

/** A logger that writes nothing and remembers what it was handed. */
const recordingLogger = (): Logger & { readonly lines: unknown[][] } => {
	const lines: unknown[][] = [];
	const record = (...args: unknown[]) => {
		lines.push(args);
	};
	const logger = {
		lines,
		trace: record,
		debug: record,
		info: record,
		warn: record,
		error: record,
		fatal: record,
		child: () => logger,
	};
	return logger as unknown as Logger & { readonly lines: unknown[][] };
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
	/** Keep the shipped Redis refresh-token family store, and with it the shared Redis clients. */
	readonly redis?: boolean;
	readonly logger?: Logger;
}

/** The template's own files for the development environment, under an operator's layer when given. */
function ownFiles(hocon?: string): string[] {
	const { applicationConfPath, envConfPath } = resolveConfigPaths(configDir, "development");
	if (hocon === undefined) return [envConfPath, applicationConfPath];
	const file = join(mkdtempSync(join(tmpdir(), "own-modules-")), "operator.conf");
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
	const own = readOwnLayers(ownFiles(options.hocon), { env });
	const switches = readSwitches(own);
	const modules = buildModules(switches, {
		environment: "development",
		repositoriesModule: testRepositoriesModule,
		...(options.redis ? {} : { refreshTokenFamilyModules: [memoryRefreshTokenFamilyStoreModule] }),
	});
	return createApp({
		modules,
		bootstrapComponents: {
			config: resolveForBoot(own, modules, expectedSessionRequirements(switches)),
			pathResolver: (s: string) => s,
			logger: options.logger ?? recordingLogger(),
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
				modules: [keyStoreModule, standaloneRedisClientsModule],
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

	it("refuses a section with no URL at boot, naming the key", async () => {
		await expect(
			bootTemplate({ redis: true, hocon: "refreshTokenFamilyStore.redis.url = null\n" }),
		).rejects.toThrow(/refreshTokenFamilyStore\.redis\.url/);
	});

	it("refuses an empty URL when a client is built, naming the key and its variable", async () => {
		await expect(
			bootTemplate({ redis: true, env: { REFRESH_TOKEN_FAMILY_STORE_REDIS_URL: "" } }),
		).rejects.toThrow(/refreshTokenFamilyStore\.redis\.url.*REFRESH_TOKEN_FAMILY_STORE_REDIS_URL/s);
	});
});
