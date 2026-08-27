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
 * Issue #325 — `createRateLimitGuard` is the single implementation of the
 * rate-limit outage policy that used to live as two hand-synchronized copies
 * (`checkRateLimit` in oauth routes, `loginRateLimit` in session routes).
 *
 * These tests pin the contract both consumers rely on: the key shape, the
 * check context, the 429 envelope, the `failMode` outage policy with its
 * paired `logger.error` + `rate_limit.unavailable` audit emission, and the
 * RFC RateLimit-* / Retry-After header emission with its
 * decision-over-configuration precedence.
 */

import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import type { AuditEvent, AuditSink } from "#/audit/types.mjs";
import type { Logger } from "#/logging/Logger.mjs";
import { createRateLimitGuard } from "#/ratelimit/guard.mjs";
import type { RateLimitDecision, RateLimiter } from "#/ratelimit/types.mjs";

/** A limiter that records every key/ctx it is asked about and answers to script. */
const scriptedLimiter = (
	answer: (key: string, callIndex: number) => RateLimitDecision | Error,
): RateLimiter & { keys: string[]; contexts: unknown[] } => {
	const keys: string[] = [];
	const contexts: unknown[] = [];
	return {
		kind: "scripted",
		keys,
		contexts,
		async check(key, ctx) {
			const result = answer(key, keys.length);
			keys.push(key);
			contexts.push(ctx);
			if (result instanceof Error) throw result;
			return result;
		},
	};
};

const makeLogger = (): Logger & { error: ReturnType<typeof vi.fn> } => ({
	debug: vi.fn(),
	info: vi.fn(),
	warn: vi.fn(),
	error: vi.fn(),
});

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

const makeApp = (guard: express.RequestHandler) => {
	const app = express();
	app.get("/guarded", guard, (_req, res) => {
		res.status(200).json({ ok: true });
	});
	return app;
};

const hit = (app: express.Express) =>
	request(app).get("/guarded").set("User-Agent", "guard-test/1.0");

/** Yield microtasks so the fire-and-forget audit emit settles. */
const settleAudit = () => new Promise((r) => setImmediate(r));

describe("createRateLimitGuard — allow path", () => {
	it("calls through to the route when the limiter allows", async () => {
		const limiter = scriptedLimiter(() => ({ allowed: true }));
		const res = await hit(
			makeApp(createRateLimitGuard({ limiter, tag: "token", failMode: "open" })),
		);
		expect(res.status).toBe(200);
		expect(res.body).toEqual({ ok: true });
	});

	it("keys by the tag prefix and the client IP", async () => {
		const limiter = scriptedLimiter(() => ({ allowed: true }));
		await hit(makeApp(createRateLimitGuard({ limiter, tag: "token", failMode: "open" })));
		expect(limiter.keys).toHaveLength(1);
		expect(limiter.keys[0]).toMatch(/^token:ip:.+/);
	});

	it("passes the same normalized ip into the check context as the key uses (CP-10)", async () => {
		const limiter = scriptedLimiter(() => ({ allowed: true }));
		await hit(makeApp(createRateLimitGuard({ limiter, tag: "login", failMode: "open" })));
		const ctx = limiter.contexts[0] as { ip?: string; userAgent?: string };
		expect(limiter.keys[0]).toBe(`login:ip:${ctx.ip}`);
		expect(ctx.userAgent).toBe("guard-test/1.0");
	});

	it("does not log an error or emit audit on the success path", async () => {
		const logger = makeLogger();
		const { sink, events } = spyAuditSink();
		const limiter = scriptedLimiter(() => ({ allowed: true }));
		await hit(
			makeApp(
				createRateLimitGuard({
					limiter,
					tag: "token",
					failMode: "closed",
					logger,
					auditSink: sink,
				}),
			),
		);
		await settleAudit();
		expect(logger.error).not.toHaveBeenCalled();
		expect(events).toHaveLength(0);
	});
});

describe("createRateLimitGuard — deny path", () => {
	it("returns 429 with the RFC 6749 §5.2 envelope carrying decision.reason", async () => {
		const limiter = scriptedLimiter(() => ({ allowed: false, reason: "limit:token" }));
		const res = await hit(
			makeApp(createRateLimitGuard({ limiter, tag: "token", failMode: "open" })),
		);
		expect(res.status).toBe(429);
		expect(res.body).toEqual({ error: "rate_limited", error_description: "limit:token" });
	});

	it("falls back to the stock description when reason is empty (AS-2 `||`, not `??`)", async () => {
		const limiter = scriptedLimiter(() => ({ allowed: false, reason: "" }));
		const res = await hit(
			makeApp(createRateLimitGuard({ limiter, tag: "token", failMode: "open" })),
		);
		expect(res.status).toBe(429);
		expect(res.body.error_description).toBe("Rate limit exceeded");
	});

	it("sets Retry-After from decision.resetAt on a denial", async () => {
		const resetAt = new Date(Date.now() + 30_000);
		const limiter = scriptedLimiter(() => ({ allowed: false, resetAt }));
		const res = await hit(
			makeApp(createRateLimitGuard({ limiter, tag: "token", failMode: "open" })),
		);
		expect(res.status).toBe(429);
		expect(Number(res.headers["retry-after"])).toBeGreaterThan(0);
	});

	it("omits Retry-After when the decision carries no reset time", async () => {
		const limiter = scriptedLimiter(() => ({ allowed: false }));
		const res = await hit(
			makeApp(createRateLimitGuard({ limiter, tag: "token", failMode: "open" })),
		);
		expect(res.status).toBe(429);
		expect(res.headers["retry-after"]).toBeUndefined();
	});
});

describe("createRateLimitGuard — RateLimit-* headers", () => {
	it("emits RateLimit-* from the decision on the allow path", async () => {
		const resetAt = new Date(Date.now() + 60_000);
		const limiter = scriptedLimiter(() => ({ allowed: true, remaining: 7, limit: 20, resetAt }));
		const res = await hit(
			makeApp(createRateLimitGuard({ limiter, tag: "token", failMode: "open" })),
		);
		expect(res.headers["ratelimit-limit"]).toBe("20");
		expect(res.headers["ratelimit-remaining"]).toBe("7");
		expect(Number(res.headers["ratelimit-reset"])).toBeGreaterThan(0);
	});

	it("emits RateLimit-* on the deny path too", async () => {
		const resetAt = new Date(Date.now() + 60_000);
		const limiter = scriptedLimiter(() => ({ allowed: false, remaining: 0, limit: 20, resetAt }));
		const res = await hit(
			makeApp(createRateLimitGuard({ limiter, tag: "token", failMode: "open" })),
		);
		expect(res.status).toBe(429);
		expect(res.headers["ratelimit-limit"]).toBe("20");
		expect(res.headers["ratelimit-remaining"]).toBe("0");
	});

	it("advertises the limit the adapter enforced over the configured fallback", async () => {
		// An operator who declares a per-adapter limit overrides the value the
		// caller configured. A header advertising a limit no request is measured
		// against is worse than no header at all.
		const limiter = scriptedLimiter(() => ({ allowed: true, remaining: 4, limit: 5 }));
		const res = await hit(
			makeApp(
				createRateLimitGuard({
					limiter,
					tag: "login",
					failMode: "open",
					headerFallback: { limit: 20, windowSeconds: 900 },
				}),
			),
		);
		expect(res.headers["ratelimit-limit"]).toBe("5");
	});

	it("falls back to headerFallback when the adapter reports no limit / reset", async () => {
		const limiter = scriptedLimiter(() => ({ allowed: true, remaining: 4 }));
		const res = await hit(
			makeApp(
				createRateLimitGuard({
					limiter,
					tag: "login",
					failMode: "open",
					headerFallback: { limit: 20, windowSeconds: 900 },
				}),
			),
		);
		expect(res.headers["ratelimit-limit"]).toBe("20");
		expect(res.headers["ratelimit-reset"]).toBe("900");
	});

	it("omits RateLimit-Limit / RateLimit-Reset when neither decision nor fallback provides them", async () => {
		// A guard with no configured spec (the oauth endpoints) only advertises
		// what the adapter actually reported.
		const limiter = scriptedLimiter(() => ({ allowed: true }));
		const res = await hit(
			makeApp(createRateLimitGuard({ limiter, tag: "token", failMode: "open" })),
		);
		expect(res.headers["ratelimit-limit"]).toBeUndefined();
		expect(res.headers["ratelimit-reset"]).toBeUndefined();
		expect(res.headers["ratelimit-remaining"]).toBeUndefined();
	});

	it("clamps a negative remaining to 0", async () => {
		const limiter = scriptedLimiter(() => ({ allowed: false, remaining: -3 }));
		const res = await hit(
			makeApp(createRateLimitGuard({ limiter, tag: "token", failMode: "open" })),
		);
		expect(res.headers["ratelimit-remaining"]).toBe("0");
	});
});

describe("createRateLimitGuard — limiter outage (OR-5 failMode policy)", () => {
	it("failMode='open': lets the request through and logs rate_limiter_failed_open", async () => {
		const logger = makeLogger();
		const limiter = scriptedLimiter(() => new Error("redis down"));
		const res = await hit(
			makeApp(createRateLimitGuard({ limiter, tag: "token", failMode: "open", logger })),
		);
		expect(res.status).toBe(200);
		expect(logger.error).toHaveBeenCalledWith(
			expect.objectContaining({
				error: expect.stringContaining("redis down"),
				mode: "open",
				tag: "token",
			}),
			"rate_limiter_failed_open",
		);
	});

	it("failMode='closed': returns 503 service_unavailable and logs rate_limiter_failed_closed", async () => {
		const logger = makeLogger();
		const limiter = scriptedLimiter(() => new Error("redis down"));
		const res = await hit(
			makeApp(createRateLimitGuard({ limiter, tag: "login", failMode: "closed", logger })),
		);
		expect(res.status).toBe(503);
		expect(res.body).toEqual({
			error: "service_unavailable",
			error_description: "Rate limiter temporarily unavailable",
		});
		expect(logger.error).toHaveBeenCalledWith(
			expect.objectContaining({
				error: expect.stringContaining("redis down"),
				mode: "closed",
				tag: "login",
			}),
			"rate_limiter_failed_closed",
		);
	});

	it("emits the rate_limit.unavailable audit event under failMode='open'", async () => {
		const { sink, events } = spyAuditSink();
		const limiter = scriptedLimiter(() => new Error("redis down"));
		await hit(
			makeApp(createRateLimitGuard({ limiter, tag: "token", failMode: "open", auditSink: sink })),
		);
		await settleAudit();
		const ev = events.find((e) => e.type === "rate_limit.unavailable");
		expect(ev).toBeDefined();
		expect(ev?.details).toEqual({ tag: "token", error: "redis down" });
		expect(ev?.userAgent).toBe("guard-test/1.0");
	});

	it("emits the rate_limit.unavailable audit event under failMode='closed'", async () => {
		const { sink, events } = spyAuditSink();
		const limiter = scriptedLimiter(() => new Error("redis down"));
		await hit(
			makeApp(createRateLimitGuard({ limiter, tag: "login", failMode: "closed", auditSink: sink })),
		);
		await settleAudit();
		expect(events.map((e) => e.type)).toContain("rate_limit.unavailable");
	});

	it("stringifies a non-Error throw into the log and audit payloads", async () => {
		const logger = makeLogger();
		const { sink, events } = spyAuditSink();
		const limiter: RateLimiter = {
			kind: "broken",
			async check() {
				throw "socket hangup";
			},
		};
		await hit(
			makeApp(
				createRateLimitGuard({ limiter, tag: "token", failMode: "open", logger, auditSink: sink }),
			),
		);
		await settleAudit();
		expect(logger.error).toHaveBeenCalledWith(
			expect.objectContaining({ error: "socket hangup" }),
			"rate_limiter_failed_open",
		);
		expect(events[0]?.details).toEqual({ tag: "token", error: "socket hangup" });
	});

	it("survives an outage with no audit sink wired", async () => {
		const limiter = scriptedLimiter(() => new Error("redis down"));
		const res = await hit(
			makeApp(createRateLimitGuard({ limiter, tag: "token", failMode: "open" })),
		);
		expect(res.status).toBe(200);
	});
});
