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
 * Issue #270 — `/session/login`'s brute-force limiter was express-rate-limit's
 * per-process MemoryStore. Behind a load balancer every replica kept its own
 * buckets, so the configured 20 / 15 min became 20 × replicas and reset on
 * every deploy; the OAuth endpoints had a shared Redis-backed limiter and this
 * one had no adapter at all.
 *
 * These tests pin the route onto the shared `RateLimiter` component, and pin
 * the fallback that keeps a deployment wiring no limiter from silently losing
 * brute-force protection altogether.
 */

import type {
	AppConfig,
	RateLimitDecision,
	RateLimiter,
	UserRepository,
} from "@o3co/auth-provider-core";
import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createRouter } from "../Session.mjs";

const stubConfig = {
	cors: { allowedOrigins: [] },
	session: { domain: null, maxAge: 86400_000 },
	rateLimit: { login: { windowMs: 900_000, limit: 20 }, failMode: "closed" },
} as unknown as AppConfig;

const userRepository = {
	authenticate: vi.fn().mockResolvedValue({ id: "u-1", username: "alice" }),
	authenticateByToken: vi.fn(),
} as unknown as UserRepository;

/** A limiter that records every key it is asked about and answers to script. */
const scriptedLimiter = (
	answer: (key: string, callIndex: number) => RateLimitDecision | Error,
): RateLimiter & { keys: string[] } => {
	const keys: string[] = [];
	return {
		kind: "scripted",
		keys,
		async check(key) {
			const result = answer(key, keys.length);
			keys.push(key);
			if (result instanceof Error) throw result;
			return result;
		},
	};
};

const makeApp = (opts: { rateLimiter?: RateLimiter; config?: AppConfig } = {}) => {
	const app = express();
	app.use((req, _res, next) => {
		(req as unknown as { session: Record<string, unknown> }).session = {
			regenerate(cb: (e: null) => void) {
				cb(null);
			},
			save(cb: (e: null) => void) {
				cb(null);
			},
			destroy(cb: (e: null) => void) {
				cb(null);
			},
		};
		next();
	});
	app.use(
		"/session",
		createRouter(express, {
			userRepository,
			config: opts.config ?? stubConfig,
			...(opts.rateLimiter ? { rateLimiter: opts.rateLimiter } : {}),
		}),
	);
	return app;
};

const login = (app: express.Express) =>
	request(app).post("/session/login").type("json").send({ username: "alice", password: "pw" });

describe("/session/login rate limiting — shared limiter (#270)", () => {
	it("consults the injected RateLimiter rather than a per-process store", async () => {
		const limiter = scriptedLimiter(() => ({ allowed: true, remaining: 19 }));
		await login(makeApp({ rateLimiter: limiter }));
		expect(limiter.keys).toHaveLength(1);
	});

	it("keys by the login prefix and the client IP", async () => {
		// The prefix is what lets an operator give login its own spec, and it is
		// the example key in RateLimiter.check's own contract.
		const limiter = scriptedLimiter(() => ({ allowed: true }));
		await login(makeApp({ rateLimiter: limiter }));
		expect(limiter.keys[0]).toMatch(/^login:ip:/);
	});

	it("returns 429 when the limiter denies", async () => {
		const limiter = scriptedLimiter(() => ({ allowed: false, reason: "limit:login" }));
		const res = await login(makeApp({ rateLimiter: limiter }));
		expect(res.status).toBe(429);
		expect(res.body.error).toBe("rate_limited");
	});

	it("still emits RateLimit-* headers, as the previous limiter did", async () => {
		const resetAt = new Date(Date.now() + 60_000);
		const limiter = scriptedLimiter(() => ({ allowed: true, remaining: 7, resetAt }));
		const res = await login(makeApp({ rateLimiter: limiter }));
		expect(res.headers["ratelimit-limit"]).toBe("20");
		expect(res.headers["ratelimit-remaining"]).toBe("7");
		expect(res.headers["ratelimit-reset"]).toBeDefined();
	});

	it("advertises the limit the adapter enforced, not the one configured here", async () => {
		// An operator who declares `limits.login` on the adapter overrides the
		// value seeded from `rateLimit.login`. A header advertising a limit no
		// request is measured against is worse than no header at all.
		const limiter = scriptedLimiter(() => ({ allowed: true, remaining: 4, limit: 5 }));
		const res = await login(makeApp({ rateLimiter: limiter }));
		expect(res.headers["ratelimit-limit"]).toBe("5");
	});

	it("falls back to the configured limit when the adapter reports none", async () => {
		// `RateLimitDecision.limit` is optional so pre-existing custom adapters
		// keep compiling.
		const limiter = scriptedLimiter(() => ({ allowed: true, remaining: 4 }));
		const res = await login(makeApp({ rateLimiter: limiter }));
		expect(res.headers["ratelimit-limit"]).toBe("20");
	});

	it("sets Retry-After on a denial that carries a reset time", async () => {
		const resetAt = new Date(Date.now() + 30_000);
		const limiter = scriptedLimiter(() => ({ allowed: false, resetAt }));
		const res = await login(makeApp({ rateLimiter: limiter }));
		expect(res.status).toBe(429);
		expect(Number(res.headers["retry-after"])).toBeGreaterThan(0);
	});
});

describe("/session/login rate limiting — limiter failure (#270)", () => {
	it("fails closed with 503 when the limiter throws and failMode is closed", async () => {
		// Parity with the OAuth endpoints: one failMode policy for the product,
		// not one per router.
		const limiter = scriptedLimiter(() => new Error("redis down"));
		const res = await login(makeApp({ rateLimiter: limiter }));
		expect(res.status).toBe(503);
	});

	it("fails open when failMode is open", async () => {
		const limiter = scriptedLimiter(() => new Error("redis down"));
		const config = {
			...stubConfig,
			rateLimit: { login: { windowMs: 900_000, limit: 20 }, failMode: "open" },
		} as unknown as AppConfig;
		const res = await login(makeApp({ rateLimiter: limiter, config }));
		expect(res.status).not.toBe(503);
	});
});

describe("/session/login rate limiting — fallback (#270)", () => {
	it("still limits when no RateLimiter is wired", async () => {
		// Losing the limiter entirely would turn a weak protection into none on
		// the one endpoint that exists to resist password guessing.
		const config = {
			...stubConfig,
			rateLimit: { login: { windowMs: 900_000, limit: 2 }, failMode: "closed" },
		} as unknown as AppConfig;
		const app = makeApp({ config });
		expect((await login(app)).status).not.toBe(429);
		expect((await login(app)).status).not.toBe(429);
		expect((await login(app)).status).toBe(429);
	});

	it("warns that the fallback limiter is per-process", async () => {
		const warn = vi.fn();
		const app = express();
		app.use("/session", (req, _res, next) => {
			(req as unknown as { session: Record<string, unknown> }).session = {};
			next();
		});
		createRouter(express, {
			userRepository,
			config: stubConfig,
			logger: { warn, info: vi.fn(), error: vi.fn(), debug: vi.fn() } as never,
		});
		expect(warn).toHaveBeenCalled();
		const [, message] = warn.mock.calls[0] as [unknown, string];
		expect(message).toBe("login_rate_limiter_not_shared");
		void app;
	});
});
