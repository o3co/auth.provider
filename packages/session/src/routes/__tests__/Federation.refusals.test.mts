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
 * Refusals of a request's shape, and the line a refused callback's failed
 * discard writes:
 * - the start refuses a `redirect_to` that is not one string, before any
 *   policy or store is reached;
 * - a callback's parameters are read from an object only; anything else is
 *   no parameters, so a `form_post` callback whose body is not a form is a
 *   missing `state` and leaves its transaction in place;
 * - a refused `form_post` callback whose transaction cannot be deleted is one
 *   `federation_cleanup_failed` warn with `store`, `step` and the error's
 *   projection.
 */

import type { FederationProvider, Logger } from "@o3co/auth-provider-core";
import { resolverForTests } from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { SESSION_ADMISSION_ACTIONS } from "#/admissionActions.mjs";
import {
	deriveFederationTransactionCookieName,
	FEDERATION_TRANSACTION_KEY_PREFIX,
} from "#/federations/transaction.mjs";
import { createRouter } from "#/routes/Federation.mjs";
import { readCallbackParams } from "#/routes/FederationCallbackRequest.mjs";
import {
	makeFederationTokenStore,
	makePermissivePolicy,
	makeRecordStore,
	makeSessionFederationIndex,
	makeUserRepository,
	makeUserSessionStore,
} from "./federation-harness.mjs";

const COOKIE_NAME = deriveFederationTransactionCookieName("harness.session");

function makeFormPostProvider(
	exchangeCode: FederationProvider["exchangeCode"],
): FederationProvider {
	return {
		name: "apple",
		scope: ["email"],
		responseMode: "form_post",
		buildAuthorizationUrl: ({ state }) => {
			const url = new URL("https://appleid.apple.com/auth/authorize");
			url.searchParams.set("state", state);
			return url;
		},
		exchangeCode,
	};
}

function makeQueryProvider(): FederationProvider {
	return {
		name: "query-idp",
		scope: ["openid"],
		buildAuthorizationUrl: ({ state }) => {
			const url = new URL("https://idp.example.com/authorize");
			url.searchParams.set("state", state);
			return url;
		},
		exchangeCode: async () => ({ issuer: "https://idp.example.com", sub: "s", expiresAt: null }),
	};
}

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

/**
 * The router over a per-request session and an express-session store backed
 * by `records`, whose `destroy` fails when `failDestroy` is set. `trail`
 * receives `"session_dropped"` when a route drops the request's session.
 */
function buildApp({
	failDestroy = false,
	logger,
	trail,
	dropThrows = false,
	withoutPolicies = false,
}: {
	failDestroy?: boolean;
	logger?: ReturnType<typeof spyLogger>;
	trail?: string[];
	/** Make dropping the request's session throw. */
	dropThrows?: boolean;
	/** Register no redirect policy for any provider. */
	withoutPolicies?: boolean;
} = {}) {
	const records = new Map<string, unknown>();
	const backing = makeRecordStore(records);
	const sessionStore = {
		get: backing.get,
		set: backing.set,
		destroy(sid: string, cb?: (err?: unknown) => void) {
			if (failDestroy) return cb?.(new Error("store down"));
			backing.destroy(sid, cb);
		},
	};
	const exchangeCode = vi.fn<FederationProvider["exchangeCode"]>(async () => ({
		issuer: "https://appleid.apple.com",
		sub: "apple-sub",
		expiresAt: null,
	}));

	const app = express();
	app.use((req, _res, next) => {
		let session: Record<string, unknown> | undefined = {
			cookie: { sameSite: "lax", secure: false, httpOnly: true },
			save(cb?: (err: unknown) => void) {
				cb?.(null);
			},
			regenerate(cb?: (err: unknown) => void) {
				cb?.(null);
			},
			destroy(cb?: (err: unknown) => void) {
				cb?.(null);
			},
		};
		Object.defineProperty(req, "session", {
			configurable: true,
			get: () => session,
			set: (value: Record<string, unknown> | undefined) => {
				if (value === undefined) {
					if (dropThrows) throw new Error("drop failed");
					trail?.push("session_dropped");
				}
				session = value;
			},
		});
		(req as unknown as { sessionStore: unknown }).sessionStore = sessionStore;
		next();
	});
	app.use(
		createRouter(express, {
			requirements: resolverForTests([], { actions: SESSION_ADMISSION_ACTIONS }),
			config: { "session-store": { name: "harness.session" } } as never,
			federationProviders: new Map<string, FederationProvider>([
				["apple", makeFormPostProvider(exchangeCode)],
				["query-idp", makeQueryProvider()],
			]),
			federationRedirectPolicyResolver: new Map(
				withoutPolicies
					? []
					: [
							["apple", makePermissivePolicy()],
							["query-idp", makePermissivePolicy()],
						],
			) as never,
			providerCallbackUrls: new Map([
				["apple", "https://app.example.com/oauth/federation/apple/callback"],
				["query-idp", "https://app.example.com/oauth/federation/query-idp/callback"],
			]),
			userRepository: makeUserRepository(),
			userSessionStore: makeUserSessionStore(),
			sessionFederationIndex: makeSessionFederationIndex(),
			federationTokenStore: makeFederationTokenStore(),
			...(logger === undefined ? {} : { logger: logger as unknown as Logger }),
		}),
	);
	app.use(
		(err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
			res.status(500).json({ unhandled: err instanceof Error ? err.message : String(err) });
		},
	);
	return { app, records, exchangeCode };
}

/** Start a `form_post` flow on `app` and return the transaction cookie to replay. */
async function startFormPost(app: express.Express) {
	const res = await request(app).get("/oauth/federation/apple");
	const header = ((res.headers["set-cookie"] as unknown as string[]) ?? []).find((c) =>
		c.startsWith(`${COOKIE_NAME}=`),
	);
	if (!header) throw new Error("start leg issued no transaction cookie");
	const id = decodeURIComponent(header.split(";")[0]?.slice(COOKIE_NAME.length + 1) ?? "");
	return { id, cookie: `${COOKIE_NAME}=${encodeURIComponent(id)}` };
}

describe("the start refuses a redirect_to it has no policy to judge", () => {
	it("answers exactly 500 internal_error and logs one federation_misconfigured line naming the provider", async () => {
		const logger = spyLogger();
		const { app, records } = buildApp({ withoutPolicies: true, logger });

		const res = await request(app).get("/oauth/federation/query-idp?redirect_to=%2Fdashboard");

		expect(res.status).toBe(500);
		expect(res.headers["content-type"]).toBe("application/json; charset=utf-8");
		expect(res.text).toBe(
			'{"error":"internal_error","error_description":"redirect policy not registered for provider"}',
		);
		expect(res.headers.location).toBeUndefined();
		expect(records.size).toBe(0);
		expect(logger.error).toHaveBeenCalledTimes(1);
		expect(logger.error.mock.calls[0]).toEqual([
			{ provider: "query-idp", reason: "no_redirect_policy" },
			"federation_misconfigured",
		]);
		expect(Object.keys(logger.error.mock.calls[0]?.[0] as object)).toEqual(["provider", "reason"]);
		for (const level of ["trace", "debug", "info", "warn", "fatal"] as const) {
			expect(logger[level]).not.toHaveBeenCalled();
		}
	});
});

describe("the start refuses a redirect_to that is not one string", () => {
	it("answers 400 invalid_redirect for a repeated redirect_to, and starts nothing", async () => {
		const { app, records } = buildApp();

		const res = await request(app).get("/oauth/federation/apple?redirect_to=%2Fa&redirect_to=%2Fb");

		expect(res.status).toBe(400);
		expect(res.body).toEqual({
			error: "invalid_redirect",
			error_description: "redirect_to must be a string",
		});
		expect(res.headers.location).toBeUndefined();
		expect(records.size).toBe(0);
	});
});

describe("a callback's parameters are read from an object only", () => {
	it.each([
		["undefined", undefined],
		["null", null],
		["a string", "state=s&code=c"],
		["a number", 42],
		["a boolean", true],
	])("reads %s as no parameters", (_label, source) => {
		expect(readCallbackParams(source)).toEqual({});
	});

	it("keeps only an object's string entries", () => {
		expect(readCallbackParams({ state: "s", code: ["a", "b"], user: { name: "x" } })).toEqual({
			state: "s",
		});
	});

	it("answers a form_post callback whose body is not a form as a missing state, keeping its transaction", async () => {
		const { app, records, exchangeCode } = buildApp();
		const flow = await startFormPost(app);

		const res = await request(app)
			.post("/oauth/federation/apple/callback")
			.set("Cookie", flow.cookie)
			.set("Content-Type", "text/plain")
			.send("state=s&code=c");

		expect(res.status).toBe(400);
		expect(res.body).toEqual({
			error: "invalid_request",
			error_description: "Missing state parameter",
		});
		expect(records.has(`${FEDERATION_TRANSACTION_KEY_PREFIX}${flow.id}`)).toBe(true);
		expect(exchangeCode).not.toHaveBeenCalled();
	});
});

describe("a refused form_post callback whose transaction cannot be discarded", () => {
	it("writes one federation_cleanup_failed warn with the store, the step and the error's projection, then drops the session", async () => {
		const { app, records } = buildApp();
		const flow = await startFormPost(app);
		const logger = spyLogger();
		const trail: string[] = [];
		logger.warn.mockImplementation((_context: unknown, name: string) => {
			trail.push(name);
		});
		const { app: broken, records: brokenRecords } = buildApp({
			failDestroy: true,
			logger,
			trail,
		});
		for (const [key, value] of records) brokenRecords.set(key, value);

		const res = await request(broken)
			.post("/oauth/federation/apple/callback")
			.set("Cookie", flow.cookie)
			.type("form")
			.send({ state: "not-the-state", code: "c" });

		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_state");
		expect(logger.warn).toHaveBeenCalledTimes(1);
		const [context, name] = logger.warn.mock.calls[0] as [Record<string, unknown>, string];
		expect(name).toBe("federation_cleanup_failed");
		expect(context).toEqual({
			store: "federation_transaction",
			step: "delete",
			err: expect.objectContaining({ name: "Error", detail: "store down" }),
		});
		expect(context.err).not.toBeInstanceOf(Error);
		for (const level of ["trace", "debug", "info", "error", "fatal"] as const) {
			expect(logger[level]).not.toHaveBeenCalled();
		}
		// The cookie session is dropped, after its cause is logged, so
		// express-session does not write to the failing store again.
		expect(trail).toEqual(["federation_cleanup_failed", "session_dropped"]);
	});

	it("keeps the session when the discard succeeds", async () => {
		const trail: string[] = [];
		const { app, records } = buildApp({ trail });
		const flow = await startFormPost(app);
		expect(records.has(`${FEDERATION_TRANSACTION_KEY_PREFIX}${flow.id}`)).toBe(true);

		const res = await request(app)
			.post("/oauth/federation/apple/callback")
			.set("Cookie", flow.cookie)
			.type("form")
			.send({ state: "not-the-state", code: "c" });

		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_state");
		expect(records.has(`${FEDERATION_TRANSACTION_KEY_PREFIX}${flow.id}`)).toBe(false);
		expect(trail).toEqual([]);
	});
	it("lets a session drop that throws propagate rather than answer the refusal", async () => {
		const { app, records } = buildApp();
		const flow = await startFormPost(app);
		const logger = spyLogger();
		const { app: broken, records: brokenRecords } = buildApp({
			failDestroy: true,
			logger,
			dropThrows: true,
		});
		for (const [key, value] of records) brokenRecords.set(key, value);

		const res = await request(broken)
			.post("/oauth/federation/apple/callback")
			.set("Cookie", flow.cookie)
			.type("form")
			.send({ state: "not-the-state", code: "c" });

		expect(res.status).toBe(500);
		expect(res.body).toEqual({ unhandled: "drop failed" });
		expect(logger.warn).toHaveBeenCalledTimes(1);
		expect(logger.warn.mock.calls[0]?.[0]).toMatchObject({ err: { detail: "store down" } });
	});
});
