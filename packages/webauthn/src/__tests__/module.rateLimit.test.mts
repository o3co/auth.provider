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
 * challenge-store write per request, so it is guarded by a real rate limiter.
 *
 * The guard is exercised through the boot planner (`createApp` →
 * `handle.router`), not the route factory: what is under test is the WIRING,
 * and a handler-level test passes whether or not the module mounts anything in
 * front of the handler.
 */

import {
	type AuditEvent,
	type AuditSink,
	type BootError,
	createApp,
	createMemoryRateLimiter,
	createSymmetricKeyStore,
	type DeploymentMode,
	defaultChallengeCeremonyModule,
	defineModule,
	type GrantPolicyHook,
	type Logger,
	type Module,
	memoryChallengeStoreModule,
	memoryRateLimiterModule,
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

/**
 * The same providers under a test name with no `replicaSafety`, so the
 * replica-safety guard has nothing to refuse and the test reaches the route
 * factory under `deployment.mode = "multi"`.
 */
const asSharedStub = (m: Module): Module => {
	const { replicaSafety: _declared, ...manifest } = m;
	return { ...manifest, name: `test:shared:${m.name}` } as Module;
};

async function bootApp(
	webauthnConfig: WebAuthnConfig,
	extraModules: readonly Module[],
	failMode?: "open" | "closed",
	deploymentMode?: "single" | "multi",
	extraConfig: Record<string, unknown> = {},
) {
	const config = {
		...makeCoreConfig(failMode),
		...(deploymentMode === undefined ? {} : { deployment: { mode: deploymentMode } }),
		...extraConfig,
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
			defineModule({
				name: "test:webauthn-rl-config",
				provides: { webauthnConfig: () => webauthnConfig },
			}),
			keyStoreModule,
			...storeModules,
			defaultChallengeCeremonyModule,
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

describe("webauthn authentication/options rate limit — the configured budget on a bundled shared limiter", () => {
	/**
	 * The composition a scaled deployment has: the bundled limiter module in
	 * the `rateLimiter` slot, its own `limits` silent about this route, and the
	 * route's budget where the package documents it,
	 * `webauthn.rateLimit.authenticationOptions`. The shared limiter must apply
	 * that budget, not its `defaultLimit` (60 per 60 s).
	 */
	const composed = (explicit: Record<string, unknown> = {}) => ({
		webauthn: { rateLimit: { authenticationOptions: { limit: 2, windowSeconds: 60 } } },
		memoryRateLimiter: {
			limits: explicit,
			defaultLimit: { limit: 60, windowSeconds: 60 },
			maxBuckets: 10_000,
		},
	});

	it("applies webauthn.rateLimit.authenticationOptions, not the limiter's default", async () => {
		const { handle, app } = await bootApp(
			makeWebAuthnConfig(2),
			[memoryRateLimiterModule],
			undefined,
			undefined,
			composed(),
		);

		const first = await hit(app);
		expect(first.status).toBe(200);
		expect(first.headers["ratelimit-limit"]).toBe("2");
		expect((await hit(app)).status).toBe(200);
		const denied = await hit(app);
		expect(denied.status).toBe(429);
		expect(denied.body).toMatchObject({ error: "rate_limited" });

		await handle.dispose();
	});

	it("leaves an operator's explicit limits entry for the route in force over the budget the module contributes", async () => {
		// An explicit `limits.webauthn-authentication-options` is a statement
		// about this limiter; the contributed budget must not discard it.
		const { handle, app } = await bootApp(
			makeWebAuthnConfig(2),
			[memoryRateLimiterModule],
			undefined,
			undefined,
			composed({
				[WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_TAG]: { limit: 3, windowSeconds: 60 },
			}),
		);

		const first = await hit(app);
		expect(first.headers["ratelimit-limit"]).toBe("3");
		expect((await hit(app)).status).toBe(200);
		expect((await hit(app)).status).toBe(200);
		expect((await hit(app)).status).toBe(429);

		await handle.dispose();
	});

	it("applies the budget given as the strings HOCON substitutes", async () => {
		const { handle, app } = await bootApp(
			makeWebAuthnConfig(2),
			[memoryRateLimiterModule],
			undefined,
			undefined,
			{
				...composed(),
				webauthn: { rateLimit: { authenticationOptions: { limit: "2", windowSeconds: "60" } } },
			},
		);

		expect((await hit(app)).headers["ratelimit-limit"]).toBe("2");
		await handle.dispose();
	});

	it("refuses to boot on a budget no limiter can apply: core's composed schema refuses it first, by the key's path", async () => {
		for (const authenticationOptions of [
			{ limit: 30, windowSeconds: 0 },
			{ limit: 1.5, windowSeconds: 60 },
			{ limit: "thirty", windowSeconds: 60 },
			{ limit: "", windowSeconds: 60 },
			{ limit: 30, windowSeconds: 1e13 },
		]) {
			const err = await bootApp(
				makeWebAuthnConfig(2),
				[memoryRateLimiterModule],
				undefined,
				undefined,
				{ ...composed(), webauthn: { rateLimit: { authenticationOptions } } },
			).then(
				() => undefined,
				(caught: unknown) => caught as BootError,
			);
			expect(err?.reason, JSON.stringify(authenticationOptions)).toBe("config-validation-failed");
			expect(err?.message, JSON.stringify(authenticationOptions)).toContain(
				"webauthn.rateLimit.authenticationOptions",
			);
		}
	});
});

describe("webauthn authentication/options rate limit — the slot and the contributed budget", () => {
	/**
	 * A shared limiter applies the budget the module contributes from the app
	 * config's `webauthn.rateLimit.authenticationOptions`; the route's
	 * per-process fallback and its headers read the `webauthnConfig` slot. A
	 * composition that hard-codes the slot (`webauthnConfigSchema.parse({…})`)
	 * without the config key runs the route on the limiter's default, and one
	 * whose key differs from the slot has the limiter apply the key. Boot warns
	 * once, naming both values and the key to set.
	 */
	const EVENT = "webauthn_authentication_options_budget_mismatch";
	const sharedLimiter = () =>
		defineModule({
			name: "test:webauthn-rl-shared",
			provides: {
				rateLimiter: () =>
					createMemoryRateLimiter({ limits: {}, defaultLimit: { limit: 60, windowSeconds: 60 } }),
			},
		});
	const withLogger = (logger: Logger) =>
		defineModule({ name: "test:webauthn-rl-mismatch-logger", provides: { logger: () => logger } });
	const mismatchCalls = (logger: ReturnType<typeof spyLogger>) =>
		logger.warn.mock.calls.filter((call) => call[1] === EVENT);

	it("warns when a shared limiter is wired and the config does not give the key", async () => {
		const logger = spyLogger();
		const { handle } = await bootApp(makeWebAuthnConfig(2), [withLogger(logger), sharedLimiter()]);

		expect(mismatchCalls(logger)).toEqual([
			[
				{
					key: "webauthn.rateLimit.authenticationOptions",
					contributed: null,
					webauthnConfig: { limit: 2, windowSeconds: 60 },
				},
				EVENT,
			],
		]);
		await handle.dispose();
	});

	it("warns when the config's key differs from the slot, naming both", async () => {
		const logger = spyLogger();
		const { handle } = await bootApp(
			makeWebAuthnConfig(2),
			[withLogger(logger), sharedLimiter()],
			undefined,
			undefined,
			{ webauthn: { rateLimit: { authenticationOptions: { limit: 5, windowSeconds: 60 } } } },
		);

		expect(mismatchCalls(logger)).toEqual([
			[
				{
					key: "webauthn.rateLimit.authenticationOptions",
					contributed: { limit: 5, windowSeconds: 60 },
					webauthnConfig: { limit: 2, windowSeconds: 60 },
				},
				EVENT,
			],
		]);
		await handle.dispose();
	});

	it("is silent when the key and the slot agree, the key as the strings HOCON substitutes included", async () => {
		for (const authenticationOptions of [
			{ limit: 2, windowSeconds: 60 },
			{ limit: "2", windowSeconds: "60" },
		]) {
			const logger = spyLogger();
			const { handle } = await bootApp(
				makeWebAuthnConfig(2),
				[withLogger(logger), sharedLimiter()],
				undefined,
				undefined,
				{ webauthn: { rateLimit: { authenticationOptions } } },
			);
			expect(mismatchCalls(logger), JSON.stringify(authenticationOptions)).toEqual([]);
			await handle.dispose();
		}
	});

	it("warns when a module has overridden the contributed budget away from the key and the slot, naming it", async () => {
		const logger = spyLogger();
		const tightener = defineModule({
			name: "test:webauthn-rl-tightener",
			overrides: {
				rateLimitBudgets: {
					[WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_TAG]: () => ({ limit: 1, windowSeconds: 60 }),
				},
			},
		});
		const { handle } = await bootApp(
			makeWebAuthnConfig(2),
			[withLogger(logger), sharedLimiter(), tightener],
			undefined,
			undefined,
			{ webauthn: { rateLimit: { authenticationOptions: { limit: 2, windowSeconds: 60 } } } },
		);

		expect(mismatchCalls(logger)).toEqual([
			[
				{
					key: "webauthn.rateLimit.authenticationOptions",
					contributed: { limit: 1, windowSeconds: 60 },
					webauthnConfig: { limit: 2, windowSeconds: 60 },
				},
				EVENT,
			],
		]);
		await handle.dispose();
	});

	it("is silent when no shared limiter is wired: the fallback is built from the slot", async () => {
		const logger = spyLogger();
		const { handle } = await bootApp(makeWebAuthnConfig(2), [withLogger(logger)]);
		expect(mismatchCalls(logger)).toEqual([]);
		await handle.dispose();
	});
});

describe("webauthn authentication/options rate limit — mandatory fallback", () => {
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
			makeWebAuthnConfig(999),
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
			makeWebAuthnConfig(999),
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

// ---------------------------------------------------------------------------
// The per-process fallback keeps its buckets per replica, which multiplies this
// route's flood and enumeration budget by the replica count. With no shared
// `rateLimiter`: `"multi"` refuses to boot, `"single"` is silent, unset warns.
// ---------------------------------------------------------------------------

describe("webauthn authentication/options rate limit — fallback under deployment.mode", () => {
	it('refuses to boot under "multi" with no shared limiter, naming the route as replica-unsafe', async () => {
		// The route factory throws; the planner wraps a factory throw as
		// `contribute-factory-failed` and carries the module's own BootError as
		// `cause`, which is where the reason and the route name live.
		await expect(bootApp(makeWebAuthnConfig(7), [], "open", "multi")).rejects.toMatchObject({
			name: "BootError",
			reason: "contribute-factory-failed",
			cause: {
				name: "BootError",
				reason: "replica-unsafe-adapter",
				message: expect.stringContaining(OPTIONS_PATH),
				details: { reason: "replica-unsafe-adapter", modules: ["webauthn"] },
			},
		});
	});

	it('boots under "multi" when a shared limiter is wired, without warning', async () => {
		const logger = spyLogger();
		const limiter = createMemoryRateLimiter({
			limits: {},
			defaultLimit: { limit: 100, windowSeconds: 60 },
		});
		const { handle } = await bootApp(
			makeWebAuthnConfig(7),
			[
				defineModule({ name: "test:webauthn-rl-logger-3", provides: { logger: () => logger } }),
				defineModule({
					name: "test:webauthn-rl-limiter-3",
					provides: { rateLimiter: () => limiter },
				}),
			],
			"open",
			"multi",
		);
		expect(logger.warn).not.toHaveBeenCalledWith(
			expect.anything(),
			"webauthn_authentication_options_rate_limiter_not_shared",
		);
		await handle.dispose();
	});

	it('is silent under "single": the operator has declared one replica', async () => {
		const logger = spyLogger();
		const { handle, app } = await bootApp(
			makeWebAuthnConfig(7),
			[defineModule({ name: "test:webauthn-rl-logger-4", provides: { logger: () => logger } })],
			"open",
			"single",
		);
		expect(logger.warn).not.toHaveBeenCalledWith(
			expect.anything(),
			"webauthn_authentication_options_rate_limiter_not_shared",
		);
		// Still guarded: the fallback limiter is in force, it is just not news.
		expect((await hit(app)).status).toBe(200);
		await handle.dispose();
	});

	it("keeps the warning when the mode is unset", async () => {
		const logger = spyLogger();
		const { handle } = await bootApp(makeWebAuthnConfig(7), [
			defineModule({ name: "test:webauthn-rl-logger-5", provides: { logger: () => logger } }),
		]);
		expect(logger.warn).toHaveBeenCalledWith(
			expect.objectContaining({ limit: 7, windowSeconds: 60 }),
			"webauthn_authentication_options_rate_limiter_not_shared",
		);
		await handle.dispose();
	});
});

// ---------------------------------------------------------------------------
// The mode comes from core's `deploymentMode` slot, which core fills from the
// configuration's `deployment.mode`: the module reads nothing of `deployment`
// itself.
// ---------------------------------------------------------------------------

describe("webauthn authentication/options rate limit — the deploymentMode slot", () => {
	/** The authentication/options route's factory, run by hand with the slot as given. */
	const buildOptionsRoute = (
		deploymentMode: DeploymentMode,
		deployment: Record<string, unknown>,
		logger: Logger,
		rateLimiter?: RateLimiter,
	) => {
		const deps = {
			...(rateLimiter === undefined ? {} : { rateLimiter }),
			webauthnConfig: makeWebAuthnConfig(7),
			webauthnCredentialStore: {},
			challengeStore: {},
			challengeCeremony: {},
			keyStore: {},
			config: { ...makeCoreConfig(), deployment },
			deploymentMode,
			logger,
		};
		const routes = (webauthnModule.contributes?.routes ?? []) as unknown as ((deps: unknown) => {
			id: string;
		})[];
		return routes
			.map((factory) => factory(deps))
			.find((route) => route.id === "webauthn-authentication-options");
	};

	it("requires the slot", () => {
		expect(webauthnModule.requires).toContain("deploymentMode");
	});

	it("refuses a slot it cannot read, absent included, as a TypeError naming it — a shared limiter wired or not", () => {
		const shared = createMemoryRateLimiter({
			limits: {},
			defaultLimit: { limit: 100, windowSeconds: 60 },
		});
		for (const rateLimiter of [undefined, shared]) {
			for (const deploymentMode of [undefined, "MULTI", null]) {
				expect(
					() => buildOptionsRoute(deploymentMode as never, {}, spyLogger(), rateLimiter),
					String(deploymentMode),
				).toThrow(new TypeError('webauthn: deploymentMode must be "single", "multi" or "unset"'));
			}
		}
	});

	it('refuses the per-process fallback when the slot says "multi", whatever the configuration\'s deployment says', () => {
		expect(() => buildOptionsRoute("multi", { mode: "single" }, spyLogger())).toThrow(
			expect.objectContaining({
				name: "BootError",
				reason: "replica-unsafe-adapter",
				details: { reason: "replica-unsafe-adapter", modules: ["webauthn"] },
			}),
		);
	});

	it('is silent when the slot says "single" and warns when it says "unset", whatever the configuration\'s deployment says', () => {
		const single = spyLogger();
		expect(buildOptionsRoute("single", { mode: "multi" }, single)?.id).toBe(
			"webauthn-authentication-options",
		);
		expect(single.warn).not.toHaveBeenCalledWith(
			expect.anything(),
			"webauthn_authentication_options_rate_limiter_not_shared",
		);
		const unset = spyLogger();
		buildOptionsRoute("unset", { mode: "multi" }, unset);
		expect(unset.warn).toHaveBeenCalledWith(
			expect.objectContaining({ limit: 7, windowSeconds: 60 }),
			"webauthn_authentication_options_rate_limiter_not_shared",
		);
	});

	it("keeps the warning, through createApp, for an empty deployment section", async () => {
		const logger = spyLogger();
		const { handle } = await bootApp(
			makeWebAuthnConfig(7),
			[defineModule({ name: "test:webauthn-rl-logger-6", provides: { logger: () => logger } })],
			"open",
			undefined,
			{ deployment: {} },
		);
		expect(logger.warn).toHaveBeenCalledWith(
			expect.objectContaining({ limit: 7, windowSeconds: 60 }),
			"webauthn_authentication_options_rate_limiter_not_shared",
		);
		await handle.dispose();
	});
});
