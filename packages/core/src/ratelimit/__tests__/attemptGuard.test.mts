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
 * `createAttemptGuard`: the per-process fallback each deployment mode allows,
 * failing closed whenever the counter has no usable answer (a throw, a
 * timeout, a malformed answer), whatever the counter declares, and the
 * `RateLimit-*` / `Retry-After` headers, from the owner's spec.
 */

import express from "express";
import request from "supertest";
import { describe, expect, it, type Mock, vi } from "vitest";
import type { AuditEvent, AuditSink } from "#/audit/types.mjs";
import type { Logger } from "#/logging/Logger.mjs";
import {
	type AttemptGuard,
	type AttemptGuardOptions,
	type AttemptVerdict,
	attemptCounterUnavailableEnvelope,
	createAttemptGuard,
} from "#/ratelimit/attemptGuard.mjs";
import type { AttemptCount, AttemptCounter, AttemptSpec } from "#/ratelimit/attempts.mjs";

const SPEC: AttemptSpec = { limit: 2, windowSeconds: 60 };
const NOW = Date.parse("2026-10-03T00:00:00.000Z");

const makeLogger = (): Logger & {
	warn: Mock<(...args: unknown[]) => void>;
	error: Mock<(...args: unknown[]) => void>;
} => ({
	trace: vi.fn(),
	debug: vi.fn(),
	info: vi.fn(),
	warn: vi.fn<(...args: unknown[]) => void>(),
	error: vi.fn<(...args: unknown[]) => void>(),
	fatal: vi.fn(),
	child: vi.fn((): Logger => {
		throw new Error("attemptGuard.test: logger.child is not expected");
	}),
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

/** A counter answering `answer` to every consume, recording each key and spec. */
const scripted = (
	answer: (key: string, spec: AttemptSpec) => unknown,
): AttemptCounter & { calls: Array<{ key: string; spec: AttemptSpec }> } => {
	const calls: Array<{ key: string; spec: AttemptSpec }> = [];
	return {
		calls,
		consume: async (key, spec) => {
			calls.push({ key, spec });
			return answer(key, spec) as AttemptCount;
		},
	};
};

const count = (allowed: boolean, remaining: number, resetInMs = 30_000): AttemptCount => ({
	allowed,
	remaining,
	resetAt: new Date(NOW + resetInMs),
});

const guardOf = (options: Partial<AttemptGuardOptions> = {}): AttemptGuard =>
	createAttemptGuard({
		counter: scripted(() => count(true, 1)),
		deploymentMode: "single",
		tag: "login",
		spec: SPEC,
		logger: makeLogger(),
		now: () => NOW,
		...options,
	});

const appOf = (guard: AttemptGuard) => {
	const app = express();
	app.post("/per-ip", guard.perIp, (_req, res) => {
		res.status(200).json({ ok: true });
	});
	app.post("/subject/:sub", async (req, res) => {
		const verdict: AttemptVerdict = await guard.attempt(req, res, `user:${req.params.sub}`);
		if (verdict.verdict !== "allowed") return;
		res.status(200).json({ ok: true, remaining: verdict.count.remaining });
	});
	return app;
};

const settleAudit = () => new Promise((r) => setImmediate(r));

describe("createAttemptGuard: the per-process fallback, by deployment mode", () => {
	it('refuses to build under "multi" with no shared counter, naming the route\'s tag and the mode', () => {
		expect(() => guardOf({ counter: undefined, deploymentMode: "multi" })).toThrow(
			/core\.deployment\.mode is "multi".*login/s,
		);
	});

	it("warns once when the mode is unset, and counts per process against the owner's spec", async () => {
		const logger = makeLogger();
		const guard = guardOf({ counter: undefined, deploymentMode: "unset", logger });
		expect(logger.warn).toHaveBeenCalledTimes(1);
		expect(logger.warn).toHaveBeenCalledWith(
			{ tag: "login", limit: 2, windowSeconds: 60 },
			"attempt_counter_not_shared",
		);
		const app = appOf(guard);
		expect((await request(app).post("/per-ip")).status).toBe(200);
		expect((await request(app).post("/per-ip")).status).toBe(200);
		expect((await request(app).post("/per-ip")).status).toBe(429);
	});

	it('is silent under "single", and counts per process', async () => {
		const logger = makeLogger();
		const guard = guardOf({ counter: undefined, deploymentMode: "single", logger });
		expect(logger.warn).not.toHaveBeenCalled();
		const app = appOf(guard);
		await request(app).post("/per-ip");
		await request(app).post("/per-ip");
		expect((await request(app).post("/per-ip")).status).toBe(429);
	});

	it.each(["single", "multi", "unset"] as const)(
		"builds silently over a shared counter under %s",
		(deploymentMode) => {
			const logger = makeLogger();
			guardOf({ deploymentMode, logger });
			expect(logger.warn).not.toHaveBeenCalled();
		},
	);

	it("refuses a deployment mode it cannot read, rather than reading it as unset", () => {
		expect(() =>
			guardOf({ counter: undefined, deploymentMode: undefined as unknown as "single" }),
		).toThrow(TypeError);
		expect(() => guardOf({ deploymentMode: "replicated" as unknown as "single" })).toThrow(
			TypeError,
		);
	});
});

describe("createAttemptGuard: what it is built from", () => {
	it.each([
		["a zero limit", { limit: 0, windowSeconds: 60 }],
		["a fractional window", { limit: 2, windowSeconds: 1.5 }],
		["no spec", undefined],
	])("refuses %s", (_label, spec) => {
		expect(() => guardOf({ spec: spec as AttemptSpec })).toThrow(RangeError);
	});

	it.each([
		["empty", ""],
		["carrying a colon", "login:ip"],
		["not a string", 7],
	])("refuses a tag %s", (_label, tag) => {
		expect(() => guardOf({ tag: tag as string })).toThrow(RangeError);
	});

	it("refuses a counter without consume, such as a rate limiter", () => {
		const limiter = { kind: "memory", check: async () => ({ allowed: true }) };
		expect(() => guardOf({ counter: limiter as unknown as AttemptCounter })).toThrow(TypeError);
	});

	it.each([
		["zero", 0],
		["a fraction", 1.5],
		["NaN", Number.NaN],
		["past what a timer keeps", 2 ** 31],
	])("refuses a timeoutMs of %s", (_label, timeoutMs) => {
		expect(() => guardOf({ timeoutMs })).toThrow(RangeError);
	});

	it("counts against the spec as it was when built: a later change to the caller's object loosens nothing", async () => {
		const counter = scripted(() => count(true, 1));
		const spec = { limit: 2, windowSeconds: 60 };
		const app = appOf(guardOf({ counter, spec }));
		spec.limit = 1_000;
		await request(app).post("/per-ip");
		expect(counter.calls[0]?.spec).toEqual({ limit: 2, windowSeconds: 60 });
	});
});

describe("createAttemptGuard: keys and the spec handed to the counter", () => {
	it("keys the middleware per IP, and attempt() under the caller's id, both under the tag", async () => {
		const counter = scripted(() => count(true, 1));
		const app = appOf(guardOf({ counter }));
		await request(app).post("/per-ip");
		await request(app).post("/subject/alice");
		expect(counter.calls.map((c) => c.key)).toEqual([
			expect.stringMatching(/^login:ip:.+/),
			"login:user:alice",
		]);
		for (const call of counter.calls) expect(call.spec).toEqual(SPEC);
	});
});

describe("createAttemptGuard: answers and headers", () => {
	it("lets an allowed attempt through with the owner's limit and the count's remaining and reset", async () => {
		const app = appOf(guardOf({ counter: scripted(() => count(true, 1, 30_500)) }));
		const res = await request(app).post("/per-ip");
		expect(res.status).toBe(200);
		expect(res.headers["ratelimit-limit"]).toBe("2");
		expect(res.headers["ratelimit-remaining"]).toBe("1");
		expect(res.headers["ratelimit-reset"]).toBe("31");
		expect(res.headers["retry-after"]).toBeUndefined();
	});

	it("answers a refusal 429 rate_limited with Retry-After, and the handler does not run", async () => {
		const app = appOf(guardOf({ counter: scripted(() => count(false, 0, 12_000)) }));
		const res = await request(app).post("/subject/alice");
		expect(res.status).toBe(429);
		expect(res.body).toEqual({ error: "rate_limited", error_description: "Rate limit exceeded" });
		expect(res.headers["ratelimit-limit"]).toBe("2");
		expect(res.headers["ratelimit-remaining"]).toBe("0");
		expect(res.headers["ratelimit-reset"]).toBe("12");
		expect(res.headers["retry-after"]).toBe("12");
	});

	it("answers a refusal with the route's own error when it names one", async () => {
		const app = appOf(
			guardOf({
				counter: scripted(() => count(false, 0)),
				refused: { error: "slow_down", description: "too many device code attempts" },
			}),
		);
		const res = await request(app).post("/subject/alice");
		expect(res.status).toBe(429);
		expect(res.body).toEqual({
			error: "slow_down",
			error_description: "too many device code attempts",
		});
	});

	it("reports a reset already past as 0", async () => {
		const app = appOf(guardOf({ counter: scripted(() => count(false, 0, -5_000)) }));
		const res = await request(app).post("/per-ip");
		expect(res.headers["ratelimit-reset"]).toBe("0");
		expect(res.headers["retry-after"]).toBe("0");
	});

	it("returns the verdict it answered with", async () => {
		const verdicts: AttemptVerdict[] = [];
		let next = count(true, 1);
		const guard = guardOf({ counter: scripted(() => next) });
		const app = express();
		app.post("/v", async (req, res) => {
			const verdict = await guard.attempt(req, res, "user:alice");
			verdicts.push(verdict);
			if (verdict.verdict === "allowed") res.status(204).end();
		});
		await request(app).post("/v");
		next = count(false, 0);
		await request(app).post("/v");
		next = { allowed: true } as AttemptCount;
		await request(app).post("/v");
		expect(verdicts).toEqual([
			{ verdict: "allowed", count: count(true, 1) },
			{ verdict: "refused", count: count(false, 0) },
			{ verdict: "unavailable" },
		]);
	});
});

describe("createAttemptGuard: fails closed", () => {
	const unavailable = async (
		counter: AttemptCounter,
		failure: string,
		extra: Partial<AttemptGuardOptions> = {},
	) => {
		const logger = makeLogger();
		const { sink, events } = spyAuditSink();
		const handler = vi.fn();
		const guard = guardOf({ counter, logger, auditSink: sink, ...extra });
		const app = express();
		app.post("/per-ip", guard.perIp, (_req, res) => {
			handler();
			res.status(200).end();
		});
		const res = await request(app).post("/per-ip").set("User-Agent", "attempt-test/1.0");
		await settleAudit();
		expect(res.status).toBe(503);
		expect(res.body).toEqual(attemptCounterUnavailableEnvelope());
		expect(res.body).toEqual({
			error: "service_unavailable",
			error_description: "Attempt counter temporarily unavailable",
		});
		expect(res.headers["ratelimit-limit"]).toBeUndefined();
		expect(res.headers["retry-after"]).toBeUndefined();
		expect(handler).not.toHaveBeenCalled();
		expect(logger.error).toHaveBeenCalledTimes(1);
		expect(logger.error).toHaveBeenCalledWith(
			expect.objectContaining({ tag: "login", failure }),
			"attempt_counter_unavailable",
		);
		expect(events).toHaveLength(1);
		expect(events[0]).toMatchObject({
			type: "rate_limit.unavailable",
			userAgent: "attempt-test/1.0",
			details: { tag: "login", failure },
		});
		return { logger, events };
	};

	it("when consume rejects, logging the error's projection and auditing its name", async () => {
		const { logger, events } = await unavailable(
			scripted(() => {
				throw Object.assign(new Error("ECONNREFUSED 10.0.0.1:6379 secret"), {
					code: "ECONNREFUSED",
				});
			}),
			"threw",
		);
		expect(events[0]?.details?.cause).toEqual({ name: "Error", code: "ECONNREFUSED" });
		expect(JSON.stringify(events[0])).not.toContain("secret");
		expect(logger.error.mock.calls[0]?.[0]).toHaveProperty("error");
	});

	it("when consume throws before it returns a promise", async () => {
		const counter: AttemptCounter = {
			consume: () => {
				throw new Error("sync");
			},
		};
		await unavailable(counter, "threw");
	});

	it("when consume does not settle within timeoutMs", async () => {
		const counter: AttemptCounter = { consume: () => new Promise<AttemptCount>(() => {}) };
		await unavailable(counter, "timed_out", { timeoutMs: 20 });
	});

	it.each([
		["null", null],
		["no remaining", { allowed: true, resetAt: new Date(NOW) }],
		["allowed as a string", { allowed: "true", remaining: 1, resetAt: new Date(NOW) }],
		["an Invalid Date", { allowed: true, remaining: 1, resetAt: new Date(Number.NaN) }],
		[
			"more remaining than the owner's limit leaves",
			{ allowed: true, remaining: 5, resetAt: new Date(NOW) },
		],
	])("when consume answers %s", async (_label, answer) => {
		await unavailable(
			scripted(() => answer),
			"malformed",
		);
	});

	it("whatever outage policy the counter declares", async () => {
		const counter = Object.assign(
			scripted(() => {
				throw new Error("down");
			}),
			{ failMode: "open" },
		);
		await unavailable(counter, "threw");
	});
});
