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
 * The development compose run, `docker-compose.yml`, with MFA on as the
 * template ships it, and the Mailpit overlay, `docker-compose.mailpit.yml`: a
 * development run whose mail goes through the SMTP sender to Mailpit. It is an
 * overlay on `docker-compose.yml`, so a plain `docker compose up` starts no
 * Mailpit, and the production file names none. The compose files are read as
 * the fixed-shape files they are, and the process each run describes is booted
 * from the shipped files, as `app.mts` boots them, under the environment the
 * run sets: `.env.example`'s lines, then each compose file's `environment`, the
 * overlay's last. Redis is a stand-in: nothing here issues a command.
 */

import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
	createApp,
	type MailSender,
	memoryRefreshTokenFamilyStoreModule,
} from "@o3co/auth-provider-core";
import {
	standardDevelopmentMailSenderModule,
	standardSmtpMailSenderModule,
} from "@o3co/auth-provider-standard";
import { afterEach, describe, expect, it, vi } from "vitest";
import { buildModules } from "#/buildModules.mjs";
import { readOwnLayers, readSwitches, resolveConfigPaths, resolveForBoot } from "#/configPath.mjs";
import { createRecordingLogger } from "./all-modules-composition.fixture.mjs";

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

const standaloneDir = fileURLToPath(new URL("../..", import.meta.url));
const configDir = fileURLToPath(new URL("../../config", import.meta.url));
const read = (rel: string): string => readFileSync(join(standaloneDir, rel), "utf8");

const OVERLAY = "docker-compose.mailpit.yml";

/** The lines of a service's block in a compose file, comments and blank lines left out. */
function serviceBlock(rel: string, name: string): string[] {
	const lines = read(rel).split("\n");
	const services = lines.findIndex((line) => /^services:\s*$/.test(line));
	const start = lines.findIndex(
		(line, at) => at > services && new RegExp(`^ {2}${name}:\\s*$`).test(line),
	);
	if (services === -1 || start === -1) return [];
	const block: string[] = [];
	for (const line of lines.slice(start + 1)) {
		if (line.trim() === "" || /^\s*#/.test(line)) continue;
		if (!/^ {4}/.test(line)) break;
		block.push(line);
	}
	return block;
}

const unquote = (text: string): string => text.trim().replace(/^["']|["']$/g, "");

/** A scalar key of a service's block. */
function scalar(block: readonly string[], key: string): string | undefined {
	for (const line of block) {
		const match = new RegExp(`^ {4}${key}:\\s*(\\S.*)$`).exec(line);
		if (match) return unquote(match[1] as string);
	}
	return undefined;
}

/** The entries under a key of a service's block, each trimmed. */
function entries(block: readonly string[], key: string): string[] {
	const at = block.findIndex((line) => new RegExp(`^ {4}${key}:\\s*$`).test(line));
	if (at === -1) return [];
	const found: string[] = [];
	for (const line of block.slice(at + 1)) {
		if (!/^ {6}/.test(line)) break;
		found.push(line.trim());
	}
	return found;
}

/** The `- "…"` entries of a list, unquoted. */
const listOf = (lines: readonly string[]): string[] =>
	lines.map((line) => unquote(line.replace(/^-\s*/, "")));

/** `.env.example`'s uncommented lines: what a `.env` copied from it sets. */
function dotenvExample(): Record<string, string> {
	const env: Record<string, string> = {};
	for (const line of read(".env.example").split("\n")) {
		const match = /^([A-Z][A-Z0-9_]*)=(.*)$/.exec(line);
		if (match) env[match[1] as string] = match[2] as string;
	}
	return env;
}

/**
 * A service's `environment`, interpolated as compose does from the project's
 * `.env`: `${VAR:-default}` is the variable when it is set and not empty, the
 * default otherwise.
 */
function environmentOf(
	rel: string,
	service: string,
	dotenv: Readonly<Record<string, string>>,
): Record<string, string> {
	const env: Record<string, string> = {};
	for (const line of entries(serviceBlock(rel, service), "environment")) {
		const match = /^([A-Z][A-Z0-9_]*):\s*(.*)$/.exec(line);
		if (!match) continue;
		env[match[1] as string] = unquote(match[2] as string).replace(
			/\$\{([A-Z][A-Z0-9_]*):-([^}]*)\}/g,
			(_, name: string, fallback: string) => (dotenv[name] ? dotenv[name] : fallback),
		);
	}
	return env;
}

describe("Mailpit runs only in the overlay", () => {
	it("is not a service of the development or the production compose file", () => {
		expect(serviceBlock("docker-compose.yml", "mailpit")).toEqual([]);
		expect(serviceBlock("docker-compose.production.yml", "mailpit")).toEqual([]);
		expect(read("docker-compose.production.yml")).not.toMatch(/mailpit/i);
	});

	it("runs a pinned Mailpit image in the app's network namespace", () => {
		const mailpit = serviceBlock(OVERLAY, "mailpit");
		expect(scalar(mailpit, "image")).toMatch(/^axllent\/mailpit:v\d+\.\d+\.\d+$/);
		expect(scalar(mailpit, "network_mode")).toBe("service:app");
	});

	it("publishes Mailpit's web UI on loopback, from the app service that owns the namespace", () => {
		expect(listOf(entries(serviceBlock(OVERLAY, "app"), "ports"))).toContain("127.0.0.1:8025:8025");
	});

	it("points the SMTP sender at Mailpit over the app's loopback, in plaintext", () => {
		expect(environmentOf(OVERLAY, "app", {})).toMatchObject({
			STANDARD_SMTP_MAIL_SENDER_HOST: "localhost",
			STANDARD_SMTP_MAIL_SENDER_PORT: "1025",
			STANDARD_SMTP_MAIL_SENDER_SECURE: "none",
		});
	});
});

describe("the process each development run describes", () => {
	const handles: { dispose(): Promise<void> }[] = [];
	afterEach(async () => {
		for (const handle of handles.splice(0)) await handle.dispose();
	});

	const signingKey = generateKeyPairSync("ed25519", {
		publicKeyEncoding: { type: "spki", format: "pem" },
		privateKeyEncoding: { type: "pkcs8", format: "pem" },
	});
	const clientsFile = (() => {
		const file = join(mkdtempSync(join(tmpdir(), "mailpit-compose-")), "clients.yaml");
		writeFileSync(file, "");
		return file;
	})();

	/** What the operator writes into `.env` beside `.env.example`'s lines: its required blanks. */
	const OPERATOR: Readonly<Record<string, string>> = {
		OAUTH_JWT_ISSUER: "http://localhost:3000",
		KEY_STORE_LOCAL_PRIVATE_KEY: signingKey.privateKey,
		KEY_STORE_LOCAL_PUBLIC_KEY: signingKey.publicKey,
		SESSION_STORE_SECRET: "mailpit-compose-session-secret.at-least-32-bytes.ok",
		REPOSITORIES_USER_HTTP_AUTHENTICATE_URL: "https://users.test/authenticate",
		REPOSITORIES_USER_HTTP_AUTHENTICATE_BY_TOKEN_URL: "https://users.test/by-token",
		REPOSITORIES_CLIENT_YAML_PATH: clientsFile,
	};

	/**
	 * The container's environment: `.env`, then each compose file's
	 * `environment`, the overlay's last unless `overlay` is false.
	 */
	function containerEnv(overlay = true): Record<string, string> {
		const dotenv: Record<string, string> = { ...dotenvExample(), ...OPERATOR };
		// The pem pair is given inline here; the paths name files this test has not written.
		delete dotenv.KEY_STORE_LOCAL_PRIVATE_KEY_PATH;
		delete dotenv.KEY_STORE_LOCAL_PUBLIC_KEY_PATH;
		return {
			...Object.fromEntries(Object.entries(dotenv).filter(([, value]) => value !== "")),
			...environmentOf("docker-compose.yml", "app", dotenv),
			...(overlay ? environmentOf(OVERLAY, "app", dotenv) : {}),
		};
	}

	it("boots docker-compose.yml's run with MFA required: development, the development mail sender, the MFA stores on its Redis", async () => {
		const env = containerEnv(false);
		// `app.mts`: CONFIG_ENV, then NODE_ENV, then development; the run sets neither.
		expect(env.CONFIG_ENV ?? env.NODE_ENV).toBeUndefined();
		const { applicationConfPath, envConfPath } = resolveConfigPaths(configDir, "development");
		const own = readOwnLayers([envConfPath, applicationConfPath], { env });
		const switches = readSwitches(own);
		expect(switches.mfaMode).toBe("required");
		// A hot reload restarts the process on every save, and Redis keeps the
		// factors, and the sessions beside them, across it.
		expect(switches.adapters).toMatchObject({
			mfaFactorStore: "redis",
			mfaTransactionStore: "redis",
		});

		const modules = buildModules(switches, {
			environment: "development",
			refreshTokenFamilyModules: [memoryRefreshTokenFamilyStoreModule],
		});
		const handle = await createApp({
			modules,
			bootstrapComponents: {
				config: resolveForBoot(own, modules, switches),
				pathResolver: (s: string) => s,
				logger: createRecordingLogger(),
			},
		});
		handles.push(handle);
		expect((handle.components.mailSender as MailSender | undefined)?.kind).toBe(
			"standard-development",
		);
		expect((handle.components.config as { mfa?: { mode?: unknown } } | undefined)?.mfa?.mode).toBe(
			"required",
		);
	});

	it("selects a configuration that is not development, so the SMTP sender is installed", () => {
		const configEnv = containerEnv().CONFIG_ENV;
		expect(configEnv).toBeDefined();
		expect(configEnv).not.toBe("development");
		// A missing `{ENV}.conf` is fatal at boot.
		expect(existsSync(resolveConfigPaths(configDir, configEnv as string).envConfPath)).toBe(true);
	});

	it("boots with MFA on and the SMTP sender in the mailSender slot, relaying to Mailpit", async () => {
		const env = containerEnv();
		const configEnv = env.CONFIG_ENV as string;
		const { applicationConfPath, envConfPath } = resolveConfigPaths(configDir, configEnv);
		const own = readOwnLayers([envConfPath, applicationConfPath], { env });
		const switches = readSwitches(own);
		expect(switches.mfaMode).toBe("required");

		const modules = buildModules(switches, {
			environment: configEnv,
			refreshTokenFamilyModules: [memoryRefreshTokenFamilyStoreModule],
		});
		const names = modules.map((module) => module.name);
		expect(names).toContain(standardSmtpMailSenderModule.name);
		expect(names).not.toContain(
			standardDevelopmentMailSenderModule({ environment: "development" }).name,
		);

		const handle = await createApp({
			modules,
			bootstrapComponents: {
				config: resolveForBoot(own, modules, switches),
				pathResolver: (s: string) => s,
				logger: createRecordingLogger(),
			},
		});
		handles.push(handle);
		expect((handle.components.mailSender as MailSender | undefined)?.kind).toBe("standard-smtp");
		expect(
			(handle.components.config as Record<string, unknown> | undefined)?.[
				"standard-smtp-mail-sender"
			],
		).toMatchObject({ host: "localhost", port: 1025, secure: "none" });
	});
});
