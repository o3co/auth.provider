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
 * Issue #281 — `POST /oauth/webauthn/authentication/options` is guarded by a
 * real rate limiter.
 *
 * Before this, the route carried comments claiming rate limiting was "composed
 * externally at module-wiring time" and nothing composed it: the endpoint was
 * unauthenticated, unthrottled, and drove a challenge-store write per request.
 *
 * These tests exercise the guard through the boot planner (`createApp` →
 * `handle.router`) rather than by calling the route factory directly, because
 * the defect was in the WIRING: a handler-level test passes whether or not the
 * module mounts anything in front of it.
 */

import {
	type AuditEvent,
	type AuditSink,
	createApp,
	createMemoryRateLimiter,
	createSymmetricKeyStore,
	defaultChallengeCeremonyModule,
	defineModule,
	type GrantPolicyHook,
	type Logger,
	type Module,
	memoryChallengeStoreModule,
	memoryReplaySeenSetModule,
	memoryWebAuthnCredentialStoreModule,
	type RateLimiter,
} from "@o3co/auth-provider-core";
import { makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import express from "express";
import supertest from "supertest";
import { describe, expect, it, vi } from "vitest";
import type { WebAuthnConfig } from "../config.mjs";
import { webauthnModule } from "../module.mjs";
import { WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_TAG } from "../routes/authenticationOptions.mjs";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const OPTIONS_PATH = "/oauth/webauthn/authentication/options";

const makeCoreConfig = (failMode: "open" | "closed" = "open") => {
	const base = makeValidAppConfig();
	return {
		...base,
		oauth: { ...base.oauth, jwt: { ...base.oauth.jwt, issuer: "https://test.example" } },
		rateLimit: { ...base.rateLimit, failMode },
	};
};

const makeWebAuthnConfig = (limit: number): WebAuthnConfig => ({
	rpId: "example.com",
	rpName: "Example App",
	origin: ["https://example.com"],
	challengeTtlMs: 120_000,
	attestationPreference: "none",
	userVerification: "preferred",
	allowCredentialsForKnownUser: false,
	rateLimit: { authenticationOptions: { limit, windowSeconds: 60 } },
});

const keyStoreModule = defineModule({
	name: "test:webauthn-rl-key-store",
	provides: { keyStore: () => createSymmetricKeyStore("test-secret-at-least-32-chars!!") },
});

const noopGrantPolicyModule = defineModule({
	name: "test:webauthn-rl-grant-policy",
	provides: {
		grantPolicy: (): GrantPolicyHook => ({
			kind: "test-noop",
			evaluate: async () => ({ outcome: "allow" }) as const,
		}),
	},
});

const spyLogger = (): Logger & { warn: ReturnType<typeof vi.fn> } => {
	const logger = {
		trace: vi.fn(),
		debug: vi.fn(),
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		fatal: vi.fn(),
		child: () => logger,
	};
	return logger as unknown as Logger & { warn: ReturnType<typeof vi.fn> };
};

const spyAuditSink = (): { sink: AuditSink; events: AuditEvent[] } => {
	const events: AuditEvent[] = [];
	return {
		sink: {
			kind: "spy",
			async record(event) {
				events.push(event);
			},
		},
		events,
	};
};

/** Yield microtasks so the guard's fire-and-forget audit emit settles. */
const settleAudit = () => new Promise((r) => setImmediate(r));

async function bootApp(
	webauthnConfig: WebAuthnConfig,
	extraModules: readonly Module[],
	failMode?: "open" | "closed",
) {
	const config = makeCoreConfig(failMode);
	const handle = await createApp({
		modules: [
			webauthnModule,
			defineModule({
				name: "test:webauthn-rl-config",
				provides: { webauthnConfig: () => webauthnConfig },
			}),
			keyStoreModule,
			memoryChallengeStoreModule,
			memoryReplaySeenSetModule,
			defaultChallengeCeremonyModule,
			memoryWebAuthnCredentialStoreModule,
			noopGrantPolicyModule,
			...extraModules,
		],
		bootstrapComponents: { config, pathResolver: (p: string) => p } as never,
	});
	const app = express();
	app.use(handle.router);
	return { handle, app };
}

const hit = (app: express.Express) =>
	supertest(app).post(OPTIONS_PATH).set("Content-Type", "application/json").send("{}");

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("webauthn authentication/options rate limit (#281) — shared limiter", () => {
	it("runs on the wired `rateLimiter` component and 429s past the limit", async () => {
		const limiter = createMemoryRateLimiter({
			limits: { [WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_TAG]: { limit: 2, windowSeconds: 60 } },
			defaultLimit: { limit: 2, windowSeconds: 60 },
		});
		const limiterModule = defineModule({
			name: "test:webauthn-rl-limiter",
			provides: { rateLimiter: () => limiter },
		});
		const { handle, app } = await bootApp(makeWebAuthnConfig(999), [limiterModule]);

		expect((await hit(app)).status).toBe(200);
		expect((await hit(app)).status).toBe(200);
		const denied = await hit(app);
		expect(denied.status).toBe(429);
		expect(denied.body).toMatchObject({ error: "rate_limited" });

		await handle.dispose();
	});

	it("keys by the documented tag so an operator can declare `limits.<tag>`", async () => {
		const keys: string[] = [];
		const limiter: RateLimiter = {
			kind: "spy",
			async check(key) {
				keys.push(key);
				return { allowed: true };
			},
		};
		const limiterModule = defineModule({
			name: "test:webauthn-rl-spy-limiter",
			provides: { rateLimiter: () => limiter },
		});
		const { handle, app } = await bootApp(makeWebAuthnConfig(999), [limiterModule]);

		await hit(app);

		expect(WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_TAG).toBe("webauthn-authentication-options");
		expect(keys).toHaveLength(1);
		expect(keys[0]).toMatch(/^webauthn-authentication-options:ip:.+/);

		await handle.dispose();
	});

	it("emits RFC RateLimit-* headers", async () => {
		const limiter = createMemoryRateLimiter({
			limits: { [WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_TAG]: { limit: 5, windowSeconds: 60 } },
			defaultLimit: { limit: 5, windowSeconds: 60 },
		});
		const limiterModule = defineModule({
			name: "test:webauthn-rl-header-limiter",
			provides: { rateLimiter: () => limiter },
		});
		const { handle, app } = await bootApp(makeWebAuthnConfig(999), [limiterModule]);

		const res = await hit(app);

		expect(res.headers["ratelimit-limit"]).toBe("5");
		expect(res.headers["ratelimit-remaining"]).toBe("4");

		await handle.dispose();
	});
});

describe("webauthn authentication/options rate limit (#281) — mandatory fallback", () => {
	it("still throttles when no `rateLimiter` component is wired", async () => {
		const { handle, app } = await bootApp(makeWebAuthnConfig(2), []);

		expect((await hit(app)).status).toBe(200);
		expect((await hit(app)).status).toBe(200);
		const denied = await hit(app);
		expect(denied.status).toBe(429);
		expect(denied.body).toMatchObject({ error: "rate_limited" });

		await handle.dispose();
	});

	it("warns that the per-process fallback is in force, naming the spec", async () => {
		const logger = spyLogger();
		const loggerModule = defineModule({
			name: "test:webauthn-rl-logger",
			provides: { logger: () => logger },
		});
		const { handle } = await bootApp(makeWebAuthnConfig(7), [loggerModule]);

		expect(logger.warn).toHaveBeenCalledWith(
			expect.objectContaining({ limit: 7, windowSeconds: 60 }),
			"webauthn_authentication_options_rate_limiter_not_shared",
		);

		await handle.dispose();
	});

	it("does not warn when the shared limiter is wired", async () => {
		const logger = spyLogger();
		const limiter = createMemoryRateLimiter({
			limits: {},
			defaultLimit: { limit: 100, windowSeconds: 60 },
		});
		const { handle } = await bootApp(makeWebAuthnConfig(7), [
			defineModule({ name: "test:webauthn-rl-logger-2", provides: { logger: () => logger } }),
			defineModule({
				name: "test:webauthn-rl-limiter-2",
				provides: { rateLimiter: () => limiter },
			}),
		]);

		expect(logger.warn).not.toHaveBeenCalledWith(
			expect.anything(),
			"webauthn_authentication_options_rate_limiter_not_shared",
		);

		await handle.dispose();
	});
});

describe("webauthn authentication/options rate limit (#281) — limiter outage", () => {
	it("forwards the auditSink so an outage emits rate_limit.unavailable, and applies failMode", async () => {
		const { sink, events } = spyAuditSink();
		const brokenLimiter: RateLimiter = {
			kind: "broken",
			async check() {
				throw new Error("redis down");
			},
		};
		const { handle, app } = await bootApp(
			makeWebAuthnConfig(999),
			[
				defineModule({
					name: "test:webauthn-rl-broken-limiter",
					provides: { rateLimiter: () => brokenLimiter },
				}),
				defineModule({ name: "test:webauthn-rl-audit", provides: { auditSink: () => sink } }),
			],
			"closed",
		);

		const res = await hit(app);
		await settleAudit();

		expect(res.status).toBe(503);
		expect(res.body).toMatchObject({ error: "service_unavailable" });
		const ev = events.find((e) => e.type === "rate_limit.unavailable");
		expect(ev).toBeDefined();
		expect(ev?.details).toMatchObject({
			tag: WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_TAG,
			error: "redis down",
		});

		await handle.dispose();
	});

	it("honours failMode='open' from the same config key the other throttles read", async () => {
		const brokenLimiter: RateLimiter = {
			kind: "broken",
			async check() {
				throw new Error("redis down");
			},
		};
		const { handle, app } = await bootApp(
			makeWebAuthnConfig(999),
			[
				defineModule({
					name: "test:webauthn-rl-broken-limiter-open",
					provides: { rateLimiter: () => brokenLimiter },
				}),
			],
			"open",
		);

		expect((await hit(app)).status).toBe(200);

		await handle.dispose();
	});
});
