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
 * #287 — the audit-event pipeline existed and the scaffold wired no sink, so
 * every security-relevant event the routes emit (`token.issued.failure`,
 * `authorize.rejected`, `rate_limit.unavailable`, …) was dropped by the
 * artifact operators actually deploy. `emitAuditEvent` is a no-op when the
 * slot is empty, so nothing failed and nothing warned: the deployment simply
 * had no audit trail.
 *
 * These tests pin the closure from three sides — the sink implementation, the
 * module that resolves it from config, and the manifest that must contain
 * exactly one provider for the slot.
 */

import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import {
	type AppConfig,
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
import express from "express";
import request from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";
import { buildModules } from "../buildModules.mjs";
import { createAppLogger, createAuditLogger, createLoggerAuditSink } from "../logger.mjs";
import { auditSinkModule } from "../modules.mjs";

const keyPair = generateKeyPairSync("ed25519", {
	publicKeyEncoding: { type: "spki", format: "pem" },
	privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

const baseConfig: AppConfig = {
	http: { port: 0, trustProxy: false, readinessTimeoutMs: 1000 },
	logging: { level: "silent" },
	oauth: {
		jwt: {
			issuer: "https://auth.test",
			signingKey: {
				provider: "local",
				local: {
					algorithm: "EdDSA",
					kid: "v0",
					privateKey: keyPair.privateKey,
					publicKey: keyPair.publicKey,
					previousKeys: [],
				},
			},
		},
		accessToken: { expiresIn: 3600 },
		refreshToken: {
			expiresIn: 86400,
			unknownFamilyPolicy: "reject" as const,
			legacyRtPolicy: "reject" as const,
		},
		grants: {},
		oidcMode: "oidc-required",
		code: { adapter: "memory" as const },
	},
	session: {
		secret: "test-session-secret.at-least-32-bytes.ok",
		name: "auth.sid",
		maxAge: 3600000,
		secure: false,
		sameSite: "lax",
		domain: null,
		storage: { type: "memory", redis: { url: "redis://localhost:6379" } },
	},
	rateLimit: {
		login: { windowMs: 60000, limit: 10 },
		failMode: "open",
	},
	federations: { google: { enabled: false } },
	repositories: {
		client: { type: "yaml", path: "./config/clients.yaml" },
		user: { type: "yaml", path: "./config/users.yaml", timeout: 5000 },
		code: { type: "memory", defaultExpiresIn: 600 },
	},
	endpoints: { login: { url: "/login" } },
	cors: { allowedOrigins: [] },
	audit: { sink: { type: "logger" } },
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
				...((c as AppConfig).oauth.jwt.signingKey.local ?? {}),
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

/** Resolve `auditSink` the way the boot planner does: call the module's provider. */
async function resolveSink(config: AppConfig): Promise<AuditSink> {
	const provider = auditSinkModule.provides?.auditSink;
	if (!provider) throw new Error("auditSinkModule must provide the auditSink slot");
	return (await provider({ config } as never)) as AuditSink;
}

describe("#287: the template's audit sink", () => {
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
			// An audit trail is evidence, not diagnostics. `LOG_LEVEL=warn` is an
			// ordinary production setting and `silent` is a legitimate one; if
			// either silenced audit events, #287 would be back — the same silent
			// drop, reached from the operator's side instead of the scaffold's.
			const appLogger = createAppLogger({ ...baseConfig, logging: { level: "silent" } });
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

	describe("auditSinkModule — resolves the sink from config", () => {
		it("resolves the logger sink for the shipped default", async () => {
			expect((await resolveSink(baseConfig)).kind).toBe("logger");
		});

		it("resolves core's built-in console sink when selected", async () => {
			const sink = await resolveSink({ ...baseConfig, audit: { sink: { type: "console" } } });
			expect(sink.kind).toBe("console");
		});

		it("still produces a sink when the audit section is absent entirely", async () => {
			// The failure #287 describes is silent absence. A config that says
			// nothing about auditing must land on a sink, not on `undefined`.
			const { audit: _audit, ...withoutAudit } = baseConfig;
			const sink = await resolveSink(withoutAudit as AppConfig);
			expect(sink.kind).toBe("logger");
		});

		it("refuses an unknown sink type at boot, naming what is registered", async () => {
			// There is no "none" — #304's sink policy. An operator who writes one
			// gets a boot failure naming the sinks that exist, not a silent
			// deployment with no audit trail.
			await expect(
				resolveSink({ ...baseConfig, audit: { sink: { type: "none" } } }),
			).rejects.toThrow(/none/);
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
			expect(providers[0]?.name).toBe("standalone:audit-sink");
		});

		it("the shipped application.conf selects a sink, and never 'none'", () => {
			const conf = readFileSync(new URL("../../config/application.conf", import.meta.url), "utf8");
			expect(conf).toMatch(/audit\s*\{[\s\S]*?sink\s*\{[\s\S]*?type\s*=\s*"logger"/);
			expect(conf).not.toMatch(/type\s*=\s*"none"/);
		});
	});

	describe("end to end: an OAuth failure reaches the sink", () => {
		let handleRef: { dispose(): Promise<void> } | undefined;

		afterEach(async () => {
			await handleRef?.dispose();
			handleRef = undefined;
		});

		it("records token.issued.failure for an unsupported grant_type", async () => {
			// Before #287 this assertion could not fail: nothing filled the slot,
			// so `emitAuditEvent` returned without recording anything.
			const logger = fakeLogger();
			const spyAuditModule = defineModule({
				name: "standalone:audit-sink",
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
