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
 * `POST /oauth/webauthn/authentication/options` is unauthenticated and drives a
 * challenge-store write per request. It is guarded by the deployment's
 * `rateLimiter` when one is wired, under the route's tag and on the limits
 * that limiter applies; with none, nothing in the module throttles it.
 *
 * The guard is exercised through the boot planner (`createApp` →
 * `handle.router`), not the route factory: what is under test is the WIRING,
 * and a handler-level test passes whether or not the module mounts anything in
 * front of the handler.
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
import express from "express";
import supertest from "supertest";
import { describe, expect, it, vi } from "vitest";
import type { WebAuthnConfig } from "../config.mjs";
import { webauthnModule } from "../module.mjs";
import { WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_TAG } from "../routes/authenticationOptions.mjs";
import { makeAppConfig, testTokenSettings } from "./appConfig.fixture.mjs";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const OPTIONS_PATH = "/oauth/webauthn/authentication/options";

const makeCoreConfig = (failMode: "open" | "closed" = "open") => {
	const base = makeAppConfig();
	return {
		...base,
		oauth: { ...base.oauth, jwt: { ...base.oauth.jwt, issuer: "https://test.example" } },
		rateLimit: { failMode },
	};
};

const makeWebAuthnConfig = (): WebAuthnConfig => ({
	rpId: "example.com",
	rpName: "Example App",
	origin: ["https://example.com"],
	challengeTtlMs: 120_000,
	attestationPreference: "none",
	userVerification: "preferred",
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

/**
 * The same providers under a test name with no `replicaSafety`, so the
 * replica-safety guard has nothing to refuse and the test reaches the route
 * factory under `core.deployment.mode = "multi"`.
 */
const asSharedStub = (m: Module): Module => {
	const { replicaSafety: _declared, ...manifest } = m;
	return { ...manifest, name: `test:shared:${m.name}` } as Module;
};

/**
 * Boots the module over `section`, its `webauthn` section; a `webauthn` in
 * `extraConfig` is laid over the section's top-level keys.
 */
async function bootApp(
	section: WebAuthnConfig,
	extraModules: readonly Module[],
	failMode?: "open" | "closed",
	deploymentMode?: "single" | "multi",
	extraConfig: Record<string, unknown> = {},
) {
	const { webauthn: sectionOverrides, ...rest } = extraConfig as { webauthn?: object };
	const config = {
		...makeCoreConfig(failMode),
		...(deploymentMode === undefined
			? {}
			: { core: { ...makeCoreConfig().core, deployment: { mode: deploymentMode } } }),
		...rest,
		webauthn: { ...section, ...sectionOverrides },
	};
	// With a deployment mode declared, the memory stores this fixture wires
	// stand in for shared ones: the case under test is the route's own
	// fallback, not the stores the replica-safety guard already refuses by
	// manifest. The stubs keep the providers and drop the declaration
	// — and the core name the guard would still recognise.
	const storeModules: readonly Module[] = [
		memoryChallengeStoreModule,
		memoryReplaySeenSetModule,
		memoryWebAuthnCredentialStoreModule,
	].map((m) => (deploymentMode === undefined ? m : asSharedStub(m)));
	const handle = await createApp({
		modules: [
			webauthnModule,
			keyStoreModule,
			...storeModules,
			defaultChallengeCeremonyModule,
			noopGrantPolicyModule,
			...extraModules,
		],
		bootstrapComponents: {
			config,
			pathResolver: (p: string) => p,
			oauthTokenSettings: testTokenSettings({ issuer: "https://test.example" }),
		} as never,
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

describe("webauthn authentication/options rate limit — shared limiter", () => {
	it("runs on the wired `rateLimiter` component and 429s past the limit", async () => {
		const limiter = createMemoryRateLimiter({
			limits: { [WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_TAG]: { limit: 2, windowSeconds: 60 } },
			defaultLimit: { limit: 2, windowSeconds: 60 },
		});
		const limiterModule = defineModule({
			name: "test:webauthn-rl-limiter",
			provides: { rateLimiter: () => limiter },
		});
		const { handle, app } = await bootApp(makeWebAuthnConfig(), [limiterModule]);

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
		const { handle, app } = await bootApp(makeWebAuthnConfig(), [limiterModule]);

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
		const { handle, app } = await bootApp(makeWebAuthnConfig(), [limiterModule]);

		const res = await hit(app);

		expect(res.headers["ratelimit-limit"]).toBe("5");
		expect(res.headers["ratelimit-remaining"]).toBe("4");

		await handle.dispose();
	});
});

describe("webauthn authentication/options rate limit — the limiter's own limits", () => {
	it("applies the wired limiter's default when its limits are silent about the route", async () => {
		const limiter = createMemoryRateLimiter({
			limits: {},
			defaultLimit: { limit: 3, windowSeconds: 60 },
		});
		const { handle, app } = await bootApp(makeWebAuthnConfig(), [
			defineModule({ name: "test:webauthn-rl-default", provides: { rateLimiter: () => limiter } }),
		]);

		for (let i = 0; i < 3; i += 1) expect((await hit(app)).status).toBe(200);
		expect((await hit(app)).status).toBe(429);

		await handle.dispose();
	});

	it("claims the route's tag and contributes no budget for it", async () => {
		const claim = webauthnModule.contributes?.rateLimitBudgets?.[
			WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_TAG
		] as ((deps: unknown) => unknown) | undefined;
		expect(claim).toBeTypeOf("function");
		expect(await claim?.({ section: makeWebAuthnConfig() })).toBeNull();
	});
});

describe("webauthn authentication/options rate limit — no limiter wired", () => {
	it("lets every request through: the module keeps no limiter of its own", async () => {
		const { handle, app } = await bootApp(makeWebAuthnConfig(), []);

		for (let i = 0; i < 40; i += 1) expect((await hit(app)).status).toBe(200);
		const res = await hit(app);
		expect(res.headers).not.toHaveProperty("ratelimit-limit");

		await handle.dispose();
	});

	it('boots under "multi", with no per-process limiter to warn about', async () => {
		const logger = spyLogger();
		const { handle, app } = await bootApp(
			makeWebAuthnConfig(),
			[defineModule({ name: "test:webauthn-rl-logger", provides: { logger: () => logger } })],
			"open",
			"multi",
		);

		expect((await hit(app)).status).toBe(200);
		expect(logger.warn).not.toHaveBeenCalledWith(
			expect.anything(),
			"webauthn_authentication_options_rate_limiter_not_shared",
		);

		await handle.dispose();
	});

	it("reads neither the deploymentMode slot nor the contributed budgets", () => {
		expect(webauthnModule.requires).not.toContain("deploymentMode");
		expect(webauthnModule.requires).not.toContain("rateLimitBudgetResolver");
	});
});

describe("webauthn authentication/options rate limit — limiter outage", () => {
	it("forwards the auditSink so an outage emits rate_limit.unavailable, and applies the limiter's failMode", async () => {
		const { sink, events } = spyAuditSink();
		const brokenLimiter: RateLimiter = {
			kind: "broken",
			failMode: "closed",
			async check() {
				throw new Error("redis down");
			},
		};
		const { handle, app } = await bootApp(
			makeWebAuthnConfig(),
			[
				defineModule({
					name: "test:webauthn-rl-broken-limiter",
					provides: { rateLimiter: () => brokenLimiter },
				}),
				defineModule({ name: "test:webauthn-rl-audit", provides: { auditSink: () => sink } }),
			],
			// The limiter's policy, not the configuration's `rateLimit.failMode`.
			"open",
		);

		const res = await hit(app);
		await settleAudit();

		expect(res.status).toBe(503);
		expect(res.body).toMatchObject({ error: "service_unavailable" });
		const ev = events.find((e) => e.type === "rate_limit.unavailable");
		expect(ev).toBeDefined();
		expect(ev?.details).toMatchObject({
			tag: WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_TAG,
			cause: { name: "Error" },
		});

		await handle.dispose();
	});

	it("honours the limiter's failMode='open', the policy every other throttle reads", async () => {
		const brokenLimiter: RateLimiter = {
			kind: "broken",
			failMode: "open",
			async check() {
				throw new Error("redis down");
			},
		};
		const { handle, app } = await bootApp(
			makeWebAuthnConfig(),
			[
				defineModule({
					name: "test:webauthn-rl-broken-limiter-open",
					provides: { rateLimiter: () => brokenLimiter },
				}),
			],
			"closed",
		);

		expect((await hit(app)).status).toBe(200);

		await handle.dispose();
	});
});
