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
 * `/session/login`'s attempt limit: one attempt counted per request, under
 * `login:ip:<ip>`, against `session.rateLimit.login` on the `attemptCounter`
 * slot's counter, through core's attempt guard. No rate limiter's budgets,
 * failMode or outage loosen it: a counter that cannot answer is a `503`.
 * Without a counter, the guard counts per process where the deployment mode
 * allows it.
 */

import type {
	AppConfig,
	AttemptCount,
	AttemptCounter,
	AttemptSpec,
	AuditEvent,
	AuditSink,
	DeploymentMode,
	UserRepository,
} from "@o3co/auth-provider-core";
import { createTestCsrfTokenSigner, resolverForTests } from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createCsrfProtection } from "../../csrf.mjs";
import { createRouter } from "../Session.mjs";

/** The session module's section, as the router receives it: the login's limit. */
const stubConfig = {
	session: { rateLimit: { login: { windowMs: 900_000, limit: 20 } } },
} as unknown as AppConfig;

/** The session cookie, as the `sessionCookiePolicy` slot carries it. */
const COOKIE = { name: "auth.session", secure: false, sameSite: "lax", domain: undefined } as const;

/** The session module's section of a configuration. */
const sectionOf = (config: AppConfig) =>
	(config as unknown as { session: Record<string, unknown> }).session;

/** The CSRF guard runs ahead of the attempt guard, so every request here clears it. */
const SIGNER = createTestCsrfTokenSigner();
const csrf = createCsrfProtection({ signer: SIGNER, cookieName: "auth.session.csrf" });
const csrfToken = csrf.mint();

const userRepository = {
	authenticate: vi.fn().mockResolvedValue({ id: "u-1", username: "alice" }),
	authenticateByToken: vi.fn(),
} as unknown as UserRepository;

/** A user directory whose `authenticate` is a spy. */
const credentialsSpy = () => ({
	authenticate: vi.fn().mockResolvedValue({ id: "u-1", username: "alice" }),
	authenticateByToken: vi.fn(),
});

/** A counter that records every consume and answers to script. */
const scriptedCounter = (
	answer: (key: string, spec: AttemptSpec) => AttemptCount | Error,
): AttemptCounter & { calls: { key: string; spec: AttemptSpec }[] } => {
	const calls: { key: string; spec: AttemptSpec }[] = [];
	return {
		calls,
		async consume(key, spec) {
			calls.push({ key, spec });
			const result = answer(key, spec);
			if (result instanceof Error) throw result;
			return result;
		},
	};
};

const allowed = (): AttemptCount => ({
	allowed: true,
	remaining: 19,
	resetAt: new Date(Date.now() + 900_000),
});

const spyLogger = () => ({
	trace: vi.fn(),
	debug: vi.fn(),
	info: vi.fn(),
	warn: vi.fn(),
	error: vi.fn(),
	fatal: vi.fn(),
	child: vi.fn(),
});

const routerFor = (
	opts: {
		attemptCounter?: AttemptCounter;
		auditSink?: AuditSink;
		config?: AppConfig;
		deploymentMode?: DeploymentMode;
		logger?: ReturnType<typeof spyLogger>;
		userRepository?: UserRepository;
	} = {},
) =>
	createRouter(express, {
		csrfTokenSigner: SIGNER,
		userRepository: opts.userRepository ?? userRepository,
		requirements: resolverForTests([]),
		section: sectionOf(opts.config ?? stubConfig),
		sessionCookie: COOKIE,
		deploymentMode: "deploymentMode" in opts ? (opts.deploymentMode as DeploymentMode) : "unset",
		...(opts.attemptCounter ? { attemptCounter: opts.attemptCounter } : {}),
		...(opts.auditSink ? { auditSink: opts.auditSink } : {}),
		logger: (opts.logger ?? spyLogger()) as never,
	});

const makeApp = (opts: Parameters<typeof routerFor>[0] = {}) => {
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
	app.use("/session", routerFor(opts));
	return app;
};

const login = (app: express.Express) =>
	request(app)
		.post("/session/login")
		.set("Cookie", `${csrf.cookieName}=${csrfToken}`)
		.set(csrf.headerName, csrfToken)
		.type("json")
		.send({ username: "alice", password: "pw" });

describe("/session/login attempts — the shared counter", () => {
	it("counts one attempt per request under login:ip:<ip>, against session.rateLimit.login in whole seconds", async () => {
		const counter = scriptedCounter(allowed);
		const res = await login(makeApp({ attemptCounter: counter }));
		expect(res.status).toBe(200);
		expect(counter.calls).toHaveLength(1);
		expect(counter.calls[0]?.key).toMatch(/^login:ip:/);
		expect(counter.calls[0]?.spec).toEqual({ limit: 20, windowSeconds: 900 });
	});

	it("answers a refused attempt 429 rate_limited with Retry-After alone, never RateLimit-*", async () => {
		const counter = scriptedCounter(() => ({
			allowed: false,
			remaining: 0,
			resetAt: new Date(Date.now() + 30_000),
		}));
		const res = await login(makeApp({ attemptCounter: counter }));
		expect(res.status).toBe(429);
		expect(res.body.error).toBe("rate_limited");
		expect(Number(res.headers["retry-after"])).toBeGreaterThan(0);
		expect(res.headers["cache-control"]).toBe("no-store");
		expect(Object.keys(res.headers).filter((h) => h.startsWith("ratelimit-"))).toEqual([]);
	});

	it("sends no RateLimit-* headers on an allowed attempt", async () => {
		const res = await login(makeApp({ attemptCounter: scriptedCounter(allowed) }));
		expect(res.status).toBe(200);
		expect(Object.keys(res.headers).filter((h) => h.startsWith("ratelimit-"))).toEqual([]);
	});

	it("checks no credentials once an attempt is refused", async () => {
		const repo = credentialsSpy();
		const counter = scriptedCounter(() => ({
			allowed: false,
			remaining: 0,
			resetAt: new Date(Date.now() + 30_000),
		}));
		expect(
			(
				await login(
					makeApp({ attemptCounter: counter, userRepository: repo as unknown as UserRepository }),
				)
			).status,
		).toBe(429);
		expect(repo.authenticate).not.toHaveBeenCalled();
	});
});

describe("/session/login attempts — a counter that cannot answer", () => {
	it("fails closed with 503, checking no credentials", async () => {
		const repo = credentialsSpy();
		const counter = scriptedCounter(() => new Error("redis down"));
		const res = await login(
			makeApp({ attemptCounter: counter, userRepository: repo as unknown as UserRepository }),
		);
		expect(res.status).toBe(503);
		expect(res.body.error).toBe("service_unavailable");
		expect(repo.authenticate).not.toHaveBeenCalled();
	});

	it("audits the outage as rate_limit.unavailable, tagged login", async () => {
		const events: AuditEvent[] = [];
		const sink: AuditSink = {
			kind: "spy",
			async record(event) {
				events.push(event);
			},
		};
		await login(
			makeApp({
				attemptCounter: scriptedCounter(() => new Error("redis down")),
				auditSink: sink,
			}),
		);
		await new Promise((r) => setImmediate(r));
		const event = events.find((e) => e.type === "rate_limit.unavailable");
		expect(event?.details).toMatchObject({ tag: "login", failure: "threw" });
	});
});

describe("/session/login attempts — session.rateLimit.login", () => {
	it("refuses to build the router over a section with no rateLimit.login, naming it", () => {
		const config = { session: {} } as unknown as AppConfig;
		expect(() => routerFor({ config })).toThrow(/session\.rateLimit\.login/);
	});

	it.each([
		[1_500, 2],
		[500, 1],
		[60_000, 60],
	])("reads windowMs %d as %d whole seconds, rounded up", async (windowMs, windowSeconds) => {
		const counter = scriptedCounter(allowed);
		const config = {
			session: { rateLimit: { login: { windowMs, limit: 3 } } },
		} as unknown as AppConfig;
		await login(makeApp({ attemptCounter: counter, config }));
		expect(counter.calls[0]?.spec).toEqual({ limit: 3, windowSeconds });
	});
});

describe("/session/login attempts — no counter wired", () => {
	it("still limits, per process", async () => {
		const config = {
			session: { rateLimit: { login: { windowMs: 900_000, limit: 2 } } },
		} as unknown as AppConfig;
		const app = makeApp({ config });
		expect((await login(app)).status).toBe(200);
		expect((await login(app)).status).toBe(200);
		expect((await login(app)).status).toBe(429);
	});

	it('refuses to mount under "multi", naming the login and the slot', () => {
		expect(() => routerFor({ deploymentMode: "multi" })).toThrow(
			/core\.deployment\.mode is "multi" but no shared attemptCounter is wired for "login"/,
		);
	});

	it('mounts under "multi" when a counter is wired, without warning', () => {
		const logger = spyLogger();
		expect(() =>
			routerFor({ deploymentMode: "multi", attemptCounter: scriptedCounter(allowed), logger }),
		).not.toThrow();
		expect(logger.warn).not.toHaveBeenCalled();
	});

	it('is silent under "single", and warns attempt_counter_not_shared when the mode is "unset"', () => {
		const single = spyLogger();
		routerFor({ deploymentMode: "single", logger: single });
		expect(single.warn).not.toHaveBeenCalled();
		const unset = spyLogger();
		routerFor({ deploymentMode: "unset", logger: unset });
		expect(unset.warn).toHaveBeenCalledWith(
			{ tag: "login", limit: 20, windowSeconds: 900 },
			"attempt_counter_not_shared",
		);
	});

	it("refuses a mode it cannot read, absent included, as a TypeError naming the routes — a counter wired or not", () => {
		for (const attemptCounter of [undefined, scriptedCounter(allowed)]) {
			for (const deploymentMode of [undefined, "MULTI", null]) {
				expect(
					() =>
						routerFor({
							deploymentMode: deploymentMode as never,
							...(attemptCounter ? { attemptCounter } : {}),
						}),
					String(deploymentMode),
				).toThrow(
					new TypeError('session routes: deploymentMode must be "single", "multi" or "unset"'),
				);
			}
		}
	});
});
