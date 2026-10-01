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
 * The session package's `renewSession`, through the `loginCompletion` it
 * provides, over express-session's own `MemoryStore`: the signed-in state
 * moves to a regenerated id and the old id names nothing in the store; a
 * `regenerate` or `save` the store fails is answered as its outage, writes
 * nothing, and leaves no signed-in state saved under a new id.
 */

import {
	admitPrimary,
	cookieClaim,
	createInMemoryUserSessionStore,
	passwordPrimary,
	type SessionRenewalResult,
} from "@o3co/auth-provider-core";
import { createTestCsrfGuard, resolverForTests } from "@o3co/auth-provider-core/testing";
import express from "express";
import session, { MemoryStore } from "express-session";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { createLoginCompletion } from "#/login-completion.mjs";

const COOKIE = "renewal.session";
const SUBJECT = "user-1";
const USER = { id: SUBJECT, username: "alice" };

/** A `MemoryStore` whose `destroy` (express-session's regeneration) and `set` (a save) fail while the switches say. */
function failingStore(): {
	readonly store: MemoryStore;
	readonly fail: { regenerate: boolean; save: boolean };
	readonly sessions: () => Record<string, Record<string, unknown>>;
} {
	const store = new MemoryStore();
	const fail = { regenerate: false, save: false };
	const destroy = store.destroy.bind(store);
	const set = store.set.bind(store);
	store.destroy = (sid, cb) => {
		if (fail.regenerate) {
			cb?.(new Error("cookie store down"));
			return;
		}
		destroy(sid, cb);
	};
	store.set = (sid, data, cb) => {
		if (fail.save) {
			cb?.(new Error("cookie store down"));
			return;
		}
		set(sid, data, cb);
	};
	const sessions = () =>
		Object.fromEntries(
			Object.entries((store as unknown as { sessions: Record<string, string> }).sessions).map(
				([id, raw]) => [id, JSON.parse(raw) as Record<string, unknown>],
			),
		);
	return { store, fail, sessions };
}

/** The session id a response's cookie names, or `undefined` when it sets none. */
function cookieSessionId(res: request.Response): string | undefined {
	const cookies = (res.headers["set-cookie"] as unknown as string[] | undefined) ?? [];
	const cookie = cookies.find((c) => c.startsWith(`${COOKIE}=`));
	if (cookie === undefined) return undefined;
	const value = decodeURIComponent(cookie.slice(COOKIE.length + 1).split(";")[0] ?? "");
	return value.slice(2, value.lastIndexOf("."));
}

/**
 * An app that signs a browser in through the completion's `establishSession`,
 * with a field another flow left beside the signed-in state, and renews it
 * through `renewSession`; `/whoami` answers how admission reads the cookie.
 */
function setup() {
	const cookieStore = failingStore();
	const userSessionStore = createInMemoryUserSessionStore();
	const completion = createLoginCompletion({
		userSessionStore,
		sessionTtlMs: 3_600_000,
		csrf: createTestCsrfGuard(),
	});
	const reported: string[] = [];
	const app = express();
	app.use(
		session({
			name: COOKIE,
			secret: "renewal-secret",
			resave: false,
			saveUninitialized: false,
			store: cookieStore.store,
		}),
	);
	app.post("/sign-in", async (req, res) => {
		const admission = await admitPrimary(
			{
				userSessionStore: undefined,
				subjectRevocation: undefined,
				requirements: resolverForTests([]),
				acrTable: {},
				logger: undefined,
				auditSink: undefined,
			},
			passwordPrimary({
				subject: SUBJECT,
				user: USER,
				claims: {},
				authTime: new Date(),
				redirectTo: "https://rp.example.test/after",
				request: {},
			}),
		);
		if (admission.outcome !== "establish")
			throw new Error(`admission answered ${admission.outcome}`);
		const result = await completion.establishSession(admission.establishment, {
			req,
			reporter: () => ({
				storeUnavailable: () => {},
				cleanupFailed: () => {},
				subjectIndexWriteFailed: () => {},
			}),
		});
		(req.session as unknown as Record<string, unknown>).parkedByAnotherFlow = "parked";
		res.json(result);
	});
	app.post("/renew", async (req, res) => {
		const result: SessionRenewalResult = await completion.renewSession({
			req,
			reporter: { storeUnavailable: (store, step) => reported.push(`${store}:${step}`) },
		});
		res.status(result.outcome === "renewed" ? 200 : 503).json(result);
	});
	app.get("/whoami", (req, res) => {
		res.json(cookieClaim(req));
	});
	return { app, cookieStore, userSessionStore, reported };
}

/** Signs a browser in: the response that set its cookie, its id, and the record's `sid`. */
async function signIn(app: express.Express) {
	const res = await request(app).post("/sign-in");
	expect(res.body).toMatchObject({ outcome: "established" });
	return { raw: res, id: cookieSessionId(res) as string, sid: res.body.sid as string };
}

/** The browser's cookie, as the response that set it carries it. */
const cookieOf = (res: request.Response): string =>
	(
		(res.headers["set-cookie"] as unknown as string[]).find((c) => c.startsWith(`${COOKIE}=`)) ?? ""
	).split(";")[0] as string;

describe("renewSession over express-session's MemoryStore", () => {
	it("moves isAuthenticated, user and sid to a new id, drops every other field, and leaves the old id naming nothing", async () => {
		const { app, cookieStore, userSessionStore, reported } = setup();
		const signedIn = await signIn(app);
		const old = cookieOf(signedIn.raw);
		expect(cookieStore.sessions()[signedIn.id]).toMatchObject({
			redirectTo: "https://rp.example.test/after",
			parkedByAnotherFlow: "parked",
		});

		const renewed = await request(app).post("/renew").set("Cookie", old);
		expect(renewed.status).toBe(200);
		expect(renewed.body).toEqual({ outcome: "renewed" });
		expect(reported).toEqual([]);
		const id = cookieSessionId(renewed) as string;
		expect(id).toBeDefined();
		expect(id).not.toBe(signedIn.id);

		const held = cookieStore.sessions();
		expect(Object.keys(held)).toEqual([id]);
		const { cookie: _cookie, ...fields } = held[id] as Record<string, unknown>;
		expect(fields).toEqual({ isAuthenticated: true, user: USER, sid: signedIn.sid });

		expect((await request(app).get("/whoami").set("Cookie", cookieOf(renewed))).body).toMatchObject(
			{
				authenticated: true,
				subject: SUBJECT,
				sid: signedIn.sid,
			},
		);
		expect((await request(app).get("/whoami").set("Cookie", old)).body).toMatchObject({
			authenticated: false,
		});
		expect(await userSessionStore.get(signedIn.sid)).toMatchObject({
			sid: signedIn.sid,
			sub: SUBJECT,
		});
	});

	it("a save the store fails: unavailable at save, reported once, no new id saved, and the old id naming nothing", async () => {
		const { app, cookieStore, reported } = setup();
		const signedIn = await signIn(app);
		const old = cookieOf(signedIn.raw);
		cookieStore.fail.save = true;

		const res = await request(app).post("/renew").set("Cookie", old);
		expect(res.status).toBe(503);
		expect(res.body).toEqual({ outcome: "unavailable", store: "cookie_session", step: "save" });
		expect(reported).toEqual(["cookie_session:save"]);
		expect(cookieSessionId(res)).toBeUndefined();
		expect(cookieStore.sessions()).toEqual({});

		cookieStore.fail.save = false;
		expect((await request(app).get("/whoami").set("Cookie", old)).body).toMatchObject({
			authenticated: false,
		});
	});

	it("a regeneration the store fails: unavailable at regenerate, reported once, nothing written — the store holds what it held", async () => {
		const { app, cookieStore, reported } = setup();
		const signedIn = await signIn(app);
		const before = cookieStore.sessions();
		cookieStore.fail.regenerate = true;

		const res = await request(app).post("/renew").set("Cookie", cookieOf(signedIn.raw));
		expect(res.status).toBe(503);
		expect(res.body).toEqual({
			outcome: "unavailable",
			store: "cookie_session",
			step: "regenerate",
		});
		expect(reported).toEqual(["cookie_session:regenerate"]);
		expect(cookieSessionId(res)).toBeUndefined();
		expect(cookieStore.sessions()).toEqual(before);
	});

	it("a session that is not signed in stays so: no signed-in field is written on the new id", async () => {
		const { app, cookieStore } = setup();
		const res = await request(app).post("/renew");
		expect(res.body).toEqual({ outcome: "renewed" });
		for (const held of Object.values(cookieStore.sessions())) {
			expect(held).not.toHaveProperty("isAuthenticated");
			expect(held).not.toHaveProperty("user");
			expect(held).not.toHaveProperty("sid");
		}
	});
});
