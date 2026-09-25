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
 * The cookie session's store failing, through the real stack.
 *
 * `sessionStoreModule` mounts express-session over connect-redis. When that
 * store could not load a request's session, express-session handed the error
 * to `next(err)` and the request ended in the terminal handler as an
 * unlogged-as-outage `500`; when it could not save the session (or refresh its
 * expiry) after the route answered, the error reached Express's final handler,
 * which printed its stack and dropped the connection. A store that cannot
 * answer is the server's outage: `503 temporarily_unavailable` before the
 * route runs, one error line either way.
 *
 * A route that meets the same store failing answers its own `503` and logs
 * its own line; express-session must not then write the session again when
 * the response ends — after a failed regeneration it would save the fresh,
 * empty session, and after a failed transaction write refresh the expiry of
 * one it never changed, each time waiting on the same store and reporting
 * the same outage a second time. (A failed `req.session.save` needs no such
 * care: express-session counts a session as saved once a save was asked.)
 *
 * Booted through `createApp`: the real module, the real express-session and
 * the real connect-redis, over a node-redis client faked in memory (the one
 * seam), whose commands can be made to fail.
 */

import {
	createApp,
	defineModule,
	type Logger,
	type UserRepository,
} from "@o3co/auth-provider-core";
import { makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import express, { type Request, type Response } from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/** The fake node-redis client: an in-memory map whose commands can be made to fail. */
const fake = vi.hoisted(() => {
	const data = new Map<string, string>();
	const failing = new Set<string>();
	const calls: Record<string, number> = { get: 0, set: 0, expire: 0, del: 0 };
	/** What node-redis rejects a refused command with: the command's arguments ride on it. */
	const replyError = (command: string, args: unknown[]): Error =>
		Object.assign(new Error("LOADING Redis is loading the dataset in memory"), {
			name: "ReplyError",
			command: { name: command, args },
		});
	const run = <T,>(command: string, args: unknown[], answer: () => T): Promise<T> => {
		calls[command] = (calls[command] ?? 0) + 1;
		return failing.has(command)
			? Promise.reject(replyError(command, args))
			: Promise.resolve(answer());
	};
	const client = {
		on: () => client,
		connect: async () => undefined,
		quit: async () => undefined,
		ping: async () => "PONG",
		get: (key: string) => run("get", [key], () => data.get(key) ?? null),
		set: (key: string, value: string) =>
			run("set", [key, value], () => {
				data.set(key, value);
				return "OK";
			}),
		expire: (key: string) => run("expire", [key], () => (data.has(key) ? 1 : 0)),
		del: (keys: string[]) =>
			run("del", keys, () => {
				for (const key of keys) data.delete(key);
				return keys.length;
			}),
	};
	return { data, failing, calls, client };
});

vi.mock("redis", () => ({ createClient: () => fake.client }));

import { sessionStoreModuleFor } from "#/modules/sessionStoreModule.mjs";
import {
	makeFederationTokenStore,
	makePermissivePolicy,
	makeSessionFederationIndex,
	makeUserRepository,
	makeUserSessionStore,
} from "#/routes/__tests__/federation-harness.mjs";
import { createRouter as createFederationRouter } from "#/routes/Federation.mjs";
import { createRouter as createSessionRouter } from "#/routes/Session.mjs";

/** A logger whose every level is a spy; `child` answers the same logger. */
function spyLogger() {
	const logger = {
		trace: vi.fn(),
		debug: vi.fn(),
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		fatal: vi.fn(),
		child: vi.fn(),
	};
	logger.child.mockReturnValue(logger);
	return logger;
}

type SpyLogger = ReturnType<typeof spyLogger>;

const clear = (logger: SpyLogger): void => {
	for (const level of Object.values(logger)) level.mockClear();
	logger.child.mockReturnValue(logger);
};

/**
 * Exactly one line at error level, object-first, named `event`, carrying
 * `fields` and the store error's projection — a plain object, never the
 * `Error`, and nothing of the command's arguments — and nothing at any other
 * level.
 */
function expectOneOutageLine(
	logger: SpyLogger,
	event: string,
	fields: Record<string, unknown>,
): void {
	expect(logger.error).toHaveBeenCalledTimes(1);
	const [context, name] = logger.error.mock.calls[0] as [Record<string, unknown>, string];
	expect(name).toBe(event);
	expect(context).toMatchObject(fields);
	expect(context.err).not.toBeInstanceOf(Error);
	expect(context.err).toMatchObject({ name: "ReplyError" });
	expect(JSON.stringify(context.err)).not.toContain("sess:");
	for (const level of ["trace", "debug", "info", "warn", "fatal"] as const) {
		expect(logger[level]).not.toHaveBeenCalled();
	}
}

const SESSION_STORE_UNAVAILABLE = {
	error: "temporarily_unavailable",
	error_description: "Session store unavailable",
};

let dispose: (() => Promise<void>) | undefined;
afterEach(async () => {
	await dispose?.();
	dispose = undefined;
});

beforeEach(() => {
	fake.data.clear();
	fake.failing.clear();
	for (const command of Object.keys(fake.calls)) fake.calls[command] = 0;
});

const alice = { id: "user-1", username: "alice" };

/**
 * `sessionStoreModuleFor` over the fake Redis, then a module of routes that
 * read and write `req.session` — two probes, and the session package's own
 * login and federation routers.
 */
async function boot(logger: SpyLogger): Promise<express.Express> {
	const base = makeValidAppConfig();
	const config = {
		...base,
		session: {
			...base.session,
			name: "test.sid",
			secure: false,
			storage: { type: "redis", redis: { url: "redis://fake:6379" } },
		},
		deployment: { mode: "single" },
	};
	const routes = defineModule({
		name: "test:cookie-session-routes",
		contributes: {
			routes: [
				() => {
					const router = express.Router();
					router.get("/write", (req: Request, res: Response) => {
						(req.session as unknown as Record<string, unknown>).value = "written";
						res.json({ ok: true });
					});
					router.get("/read", (req: Request, res: Response) => {
						res.json({ value: (req.session as unknown as Record<string, unknown>).value ?? null });
					});
					return { id: "test-probe", mountPath: "/probe", handler: router };
				},
				() => ({
					id: "test-session",
					mountPath: "/session",
					handler: createSessionRouter(express, {
						userRepository: {
							authenticate: vi.fn(async () => alice),
							authenticateByToken: vi.fn(async () => alice),
						} as unknown as UserRepository,
						config: config as never,
						logger: logger as unknown as Logger,
					}),
				}),
				() => ({
					id: "test-federation",
					mountPath: "/session",
					handler: createFederationRouter(express, {
						config: config as never,
						federationProviders: new Map([
							[
								"test",
								{
									name: "test",
									scope: ["openid"],
									buildAuthorizationUrl: () => new URL("https://idp.example.com/authorize"),
									exchangeCode: vi.fn(),
								},
							],
							[
								"apple",
								{
									name: "apple",
									scope: ["email"],
									responseMode: "form_post",
									buildAuthorizationUrl: () => new URL("https://appleid.apple.com/auth/authorize"),
									exchangeCode: vi.fn(),
								},
							],
						]),
						federationRedirectPolicyResolver: new Map([
							["test", makePermissivePolicy()],
							["apple", makePermissivePolicy()],
						]),
						providerCallbackUrls: new Map([
							["test", "https://app.example.com/session/oauth/federation/test/callback"],
							["apple", "https://app.example.com/session/oauth/federation/apple/callback"],
						]),
						userRepository: makeUserRepository(),
						userSessionStore: makeUserSessionStore(),
						sessionFederationIndex: makeSessionFederationIndex(),
						federationTokenStore: makeFederationTokenStore(),
						logger: logger as unknown as Logger,
					}),
				}),
			],
		},
	});
	const handle = await createApp({
		modules: [sessionStoreModuleFor(config), routes],
		bootstrapComponents: {
			config,
			pathResolver: (p: string) => p,
			logger: logger as unknown as Logger,
		} as never,
	});
	dispose = () => handle.dispose();
	const app = express();
	app.use(handle.router);
	clear(logger);
	return app;
}

describe("the cookie session's store, as express-session reaches it", () => {
	it("cannot load a session: 503 before the route runs, one error line", async () => {
		const logger = spyLogger();
		const agent = request.agent(await boot(logger));
		expect((await agent.get("/probe/write")).status).toBe(200);
		clear(logger);

		fake.failing.add("get");
		const res = await agent.get("/probe/read");

		expect(res.status).toBe(503);
		expect(res.body).toEqual(SESSION_STORE_UNAVAILABLE);
		expectOneOutageLine(logger, "session_middleware_store_unavailable", {
			store: "cookie_session",
			step: "load",
		});
	});

	it("cannot save the session after the route answered: the answer stands, one error line", async () => {
		const logger = spyLogger();
		const agent = request.agent(await boot(logger));

		fake.failing.add("set");
		const res = await agent.get("/probe/write");

		expect(res.status).toBe(200);
		expectOneOutageLine(logger, "session_middleware_store_unavailable", {
			store: "cookie_session",
			step: "save",
		});
	});

	it("cannot refresh an unchanged session's expiry after the route answered: one error line", async () => {
		const logger = spyLogger();
		const agent = request.agent(await boot(logger));
		expect((await agent.get("/probe/write")).status).toBe(200);
		clear(logger);

		fake.failing.add("expire");
		const res = await agent.get("/probe/read");

		expect(res.status).toBe(200);
		expect(res.body).toEqual({ value: "written" });
		expectOneOutageLine(logger, "session_middleware_store_unavailable", {
			store: "cookie_session",
			step: "save",
		});
	});

	it("logs nothing when the store answers", async () => {
		const logger = spyLogger();
		const agent = request.agent(await boot(logger));
		expect((await agent.get("/probe/write")).status).toBe(200);
		expect((await agent.get("/probe/read")).body).toEqual({ value: "written" });
		for (const level of ["trace", "debug", "info", "warn", "error", "fatal"] as const) {
			expect(logger[level]).not.toHaveBeenCalled();
		}
	});
});

describe("a route that meets the cookie store failing answers once, and the session is not written again", () => {
	/** A CSRF pair for the agent, from the router's own issuing route. */
	const csrfFor = async (agent: ReturnType<typeof request.agent>) => {
		const csrf = await agent.get("/session/csrf");
		expect(csrf.status).toBe(200);
		return {
			header: csrf.body.header_name as string,
			token: csrf.body.csrf_token as string,
		};
	};

	it("POST /session/login whose session cannot be regenerated: 503, one error line, and no session written", async () => {
		const logger = spyLogger();
		const agent = request.agent(await boot(logger));
		// A browser that already holds a session: regeneration destroys it first.
		expect((await agent.get("/probe/write")).status).toBe(200);
		const csrf = await csrfFor(agent);
		clear(logger);
		fake.calls.set = 0;

		fake.failing.add("del");
		fake.failing.add("set");
		fake.failing.add("expire");
		const res = await agent
			.post("/session/login")
			.set(csrf.header, csrf.token)
			.type("form")
			.send({ username: "alice", password: "correct-horse-battery-staple" });

		expect(res.status).toBe(503);
		expectOneOutageLine(logger, "login_store_unavailable", {
			store: "cookie_session",
			step: "regenerate",
		});
		expect(fake.calls.set).toBe(0);
		expect(fake.calls.expire).toBe(0);
	});

	it("GET /session/oauth/federation/:name whose form_post transaction cannot be written: 503, one error line, the session left alone", async () => {
		const logger = spyLogger();
		const agent = request.agent(await boot(logger));
		expect((await agent.get("/probe/write")).status).toBe(200);
		clear(logger);
		fake.calls.set = 0;

		fake.failing.add("set");
		fake.failing.add("expire");
		const res = await agent.get("/session/oauth/federation/apple");

		expect(res.status).toBe(503);
		expect(res.body).toEqual(SESSION_STORE_UNAVAILABLE);
		expectOneOutageLine(logger, "federation_start_store_unavailable", {
			store: "federation_transaction",
			step: "set",
		});
		expect(fake.calls.set).toBe(1);
		expect(fake.calls.expire).toBe(0);
	});

	it("POST /session/login whose session cannot be saved: 503, one error line, one write attempted", async () => {
		const logger = spyLogger();
		const agent = request.agent(await boot(logger));
		const csrf = await csrfFor(agent);

		fake.failing.add("set");
		const res = await agent
			.post("/session/login")
			.set(csrf.header, csrf.token)
			.type("form")
			.send({ username: "alice", password: "correct-horse-battery-staple" });

		expect(res.status).toBe(503);
		expect(res.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "Session store temporarily unavailable",
		});
		expectOneOutageLine(logger, "login_store_unavailable", {
			store: "cookie_session",
			step: "save",
		});
		expect(fake.calls.set).toBe(1);
	});

	it("GET /session/oauth/federation/:name whose envelope cannot be saved: 503, one error line, one write attempted", async () => {
		const logger = spyLogger();
		const agent = request.agent(await boot(logger));

		fake.failing.add("set");
		const res = await agent.get("/session/oauth/federation/test");

		expect(res.status).toBe(503);
		expect(res.body).toEqual(SESSION_STORE_UNAVAILABLE);
		expectOneOutageLine(logger, "federation_start_store_unavailable", {
			store: "cookie_session",
			step: "save",
		});
		expect(fake.calls.set).toBe(1);
	});
});
