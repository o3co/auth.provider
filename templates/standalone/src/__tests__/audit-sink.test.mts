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
 * The scaffold wires an audit sink. `emitAuditEvent` is a no-op when the slot
 * is empty, so without one every security-relevant event the routes emit
 * (`token.issued.failure`, `authorize.rejected`, `rate_limit.unavailable`, …)
 * is dropped, and nothing fails or warns.
 *
 * Pinned from three sides: the sink implementation, the module that resolves
 * it from config, and the manifest, which must contain exactly one provider
 * for the slot.
 */

import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import {
	type AuditEvent,
	type AuditSink,
	createApp,
	createKeyStoreFactory,
	defineModule,
	InMemoryClientRepository,
	InMemoryUserRepository,
	type Logger,
	memoryRefreshTokenFamilyStoreModule,
	registerBuiltinKeyStores,
} from "@o3co/auth-provider-core";
import { coreConfigForTests } from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";
import { buildModules } from "../buildModules.mjs";
import type { Switches } from "../configPath.mjs";
import { createAppLogger, createAuditLogger, createLoggerAuditSink } from "../logger.mjs";
import { auditSinkModuleFor } from "../modules.mjs";
import { capturedRenames, shippedAdapters } from "./library-references.fixture.mjs";

const keyPair = generateKeyPairSync("ed25519", {
	publicKeyEncoding: { type: "spki", format: "pem" },
	privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

/** The template modules' sections sit beside core's, so the configuration is wider than `AppConfig`. */
const baseConfig: Switches & Record<string, unknown> = {
	// The shipped selections, every store in this process.
	adapters: {
		...shippedAdapters(),
		accessTokenDenylist: "memory",
		replaySeenSet: "memory",
		codeRepository: "memory",
		userRepository: "yaml",
	},
	mfaMode: "off",
	storeTransport: undefined,
	// What a resolution under an environment that sets none captures of
	// core's renamed variables.
	...{
		"renamed-variables": capturedRenames({}),
	},
	http: { port: 0, trustProxy: false, readinessTimeoutMs: 1000, cors: { allowedOrigins: [] } },
	logging: { level: "silent" },
	"key-store": {
		provider: "local",
		local: {
			algorithm: "EdDSA",
			kid: "v0",
			privateKey: keyPair.privateKey,
			publicKey: keyPair.publicKey,
			previousKeys: [],
		},
	},
	// The shipped `application.conf` expects no session requirement (ADR
	// 2026-09-28-session-admission).
	...coreConfigForTests({ federations: { google: { enabled: false, type: "google" } } }),
	oauth: {
		jwt: {
			issuer: "https://auth.test",
		},
		accessToken: { expiresIn: 3600 },
		refreshToken: {
			expiresIn: 86400,
			unknownFamilyPolicy: "reject" as const,
			legacyRtPolicy: "reject" as const,
		},
		grants: {},
		oidcMode: "oidc-required",
	},
	"session-store": {
		secret: "test-session-secret.at-least-32-bytes.ok",
		name: "auth.sid",
		maxAge: 3600000,
		secure: false,
		sameSite: "lax",
		domain: null,
		storage: { type: "memory", redis: { url: "redis://localhost:6379" } },
	},
	session: {
		loginPage: { url: "/login" },
		rateLimit: { login: { windowMs: 60000, limit: 10 } },
	},
	rateLimit: { failMode: "open" },
	"standalone-in-memory-code-repository": { defaultExpiresIn: 600 },
};

const CLIENT_ID = "audit-client";
const CLIENT_SECRET = "audit-secret";
const BASIC_AUTH = `Basic ${Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64")}`;

const testRepositoriesModule = defineModule({
	name: "test:repositories",
	provides: {
		clientRepository: () =>
			new InMemoryClientRepository(
				new Map([
					[
						CLIENT_ID,
						{
							tokenEndpointAuthMethod: "client_secret_basic",
							clientSecret: CLIENT_SECRET,
							allowedRedirectUris: [],
							allowedScopes: [],
							allowedAudiences: [],
							backchannelLogoutSessionRequired: true,
							frontchannelLogoutSessionRequired: true,
							allowedAzpForFederationToken: false,
						},
					],
				]),
			),
		userRepository: () => new InMemoryUserRepository(new Map()),
	},
});

const testKeyStoreModule = defineModule({
	name: "test:key-store",
	requires: ["config"] as const,
	provides: {
		keyStore: async ({ config: c }) => {
			const factory = createKeyStoreFactory();
			registerBuiltinKeyStores(factory);
			return factory.create({
				type: "local",
				...((c as { "key-store"?: { local?: object } })["key-store"]?.local ?? {}),
			});
		},
	},
});

/** Minimal `Logger` double — the interface is pino's, so only what we assert on. */
function fakeLogger(): Logger & { info: ReturnType<typeof vi.fn> } {
	const self = {
		trace: vi.fn(),
		debug: vi.fn(),
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		fatal: vi.fn(),
		child: () => self,
	};
	return self as unknown as Logger & { info: ReturnType<typeof vi.fn> };
}

/** Resolve `auditSink` the way the boot planner does: call the module's provider with its section. */
async function resolveSink(sink: string, section?: Record<string, unknown>): Promise<AuditSink> {
	const provider = auditSinkModuleFor(sink).provides?.auditSink;
	if (!provider) throw new Error("the audit-sink module must provide the auditSink slot");
	return (await provider({ section } as never)) as AuditSink;
}

describe("the template's audit sink", () => {
	describe("createLoggerAuditSink — one event, one line, through the app's own JSON stream", () => {
		it("records the event through the injected logger", async () => {
			const logger = fakeLogger();
			const sink = createLoggerAuditSink(logger);
			const event: AuditEvent = {
				timestamp: new Date("2026-08-27T00:00:00Z"),
				type: "authorize.rejected",
				clientId: "c1",
				subject: "u1",
				details: { reason: "client_not_first_party" },
			};

			await sink.record(event);

			expect(logger.info).toHaveBeenCalledTimes(1);
			const [payload, message] = logger.info.mock.calls[0] as [Record<string, unknown>, string];
			// The event type doubles as the message so an operator can alert on
			// the name without a JSON path, matching how this template's other
			// structured events are named.
			expect(message).toBe("authorize.rejected");
			expect(payload.audit).toMatchObject({
				type: "authorize.rejected",
				clientId: "c1",
				subject: "u1",
			});
		});

		it("nests the event under `audit` so it cannot collide with pino's own keys", async () => {
			// `level`, `time`, `name` and `msg` belong to the log envelope. An
			// event spread at the top level would let a future audit field
			// overwrite one of them and corrupt the line for every consumer.
			const logger = fakeLogger();
			await createLoggerAuditSink(logger).record({
				timestamp: new Date("2026-08-27T00:00:00Z"),
				type: "rate_limit.unavailable",
			});
			const [payload] = logger.info.mock.calls[0] as [Record<string, unknown>];
			expect(Object.keys(payload)).toEqual(["audit"]);
		});

		it("reports the sink kind it was registered under", () => {
			expect(createLoggerAuditSink(fakeLogger()).kind).toBe("logger");
		});
	});

	describe("the audit trail is not gated by logging.level", () => {
		it("keeps the audit logger at info while the app logger is silenced", () => {
			// An audit trail is evidence, not diagnostics. `LOGGING_LEVEL=warn` is an
			// ordinary production setting and `silent` is a legitimate one;
			// neither may silently drop audit events.
			const appLogger = createAppLogger({ level: "silent" });
			const auditLogger = createAuditLogger();
			expect((appLogger as unknown as { level: string }).level).toBe("silent");
			expect((auditLogger as unknown as { level: string }).level).toBe("info");
		});

		it("names the audit stream so it is separable from application logs", () => {
			const bindings = (
				createAuditLogger() as unknown as { bindings(): Record<string, unknown> }
			).bindings();
			expect(bindings.name).toBe("audit");
		});
	});

	describe("the audit-sink module — builds the sink adapters.auditSink selects", () => {
		it("builds the logger sink for the shipped selection", async () => {
			expect((await resolveSink(baseConfig.adapters.auditSink)).kind).toBe("logger");
		});

		it("builds core's built-in console sink when selected", async () => {
			expect((await resolveSink("console")).kind).toBe("console");
		});

		it("builds a sink with no audit-sink section at all", async () => {
			expect((await resolveSink("logger", undefined)).kind).toBe("logger");
		});

		it("refuses a sink no builder is registered under, naming it", async () => {
			// There is no "none" sink. An operator who selects one gets a boot
			// failure naming the sinks that exist, not a silent deployment with
			// no audit trail.
			await expect(resolveSink("none")).rejects.toThrow(/none/);
		});
	});

	describe("buildModules — the slot is filled in the manifest operators deploy", () => {
		it("wires exactly one auditSink provider", () => {
			const modules = buildModules(baseConfig, {
				keyStoreModule: testKeyStoreModule,
				repositoriesModule: testRepositoriesModule,
				refreshTokenFamilyModules: [memoryRefreshTokenFamilyStoreModule],
			});
			const providers = modules.filter((m) => Object.keys(m.provides ?? {}).includes("auditSink"));
			expect(providers).toHaveLength(1);
			expect(providers[0]?.name).toBe("audit-sink");
		});

		it("the shipped reference.conf selects a sink, and never 'none'", () => {
			const conf = readFileSync(new URL("../../config/reference.conf", import.meta.url), "utf8");
			expect(conf).toMatch(/adapters\s*\{[\s\S]*?auditSink\s*=\s*"logger"/);
			expect(conf).not.toMatch(/auditSink\s*=\s*"none"/);
		});
	});

	describe("end to end: an OAuth failure reaches the sink", () => {
		let handleRef: { dispose(): Promise<void> } | undefined;

		afterEach(async () => {
			await handleRef?.dispose();
			handleRef = undefined;
		});

		it("records token.issued.failure for an unsupported grant_type", async () => {
			// `emitAuditEvent` records nothing when the slot is empty.
			const logger = fakeLogger();
			const spyAuditModule = defineModule({
				name: "audit-sink",
				provides: { auditSink: () => createLoggerAuditSink(logger) },
			});
			const handle = await createApp({
				modules: buildModules(baseConfig, {
					keyStoreModule: testKeyStoreModule,
					repositoriesModule: testRepositoriesModule,
					refreshTokenFamilyModules: [memoryRefreshTokenFamilyStoreModule],
					auditSinkModule: spyAuditModule,
				}),
				bootstrapComponents: { config: baseConfig, pathResolver: (s) => s },
			});
			handleRef = handle;

			const app = express();
			app.use(handle.router);
			const res = await request(app)
				.post("/oauth/token")
				.set("Authorization", BASIC_AUTH)
				.type("form")
				.send({ grant_type: "definitely-not-a-grant" });

			expect(res.status).toBe(400);
			// `emitAuditEvent` is fire-and-forget; let the detached promise settle.
			await new Promise((r) => setImmediate(r));
			const types = logger.info.mock.calls.map(
				(call) => (call[0] as { audit: AuditEvent }).audit.type,
			);
			expect(types).toContain("token.issued.failure");
		});

		it("boots the shipped manifest with its own audit sink wired", async () => {
			const handle = await createApp({
				modules: buildModules(baseConfig, {
					keyStoreModule: testKeyStoreModule,
					repositoriesModule: testRepositoriesModule,
					refreshTokenFamilyModules: [memoryRefreshTokenFamilyStoreModule],
				}),
				bootstrapComponents: { config: baseConfig, pathResolver: (s) => s },
			});
			handleRef = handle;
			expect(handle).toBeDefined();
		});
	});
});
