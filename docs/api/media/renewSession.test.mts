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
 *
 * And the race the renewal nonce closes: a request in flight on the old id
 * saves after the renewal — express-session's save overwrites whatever the
 * store holds — and puts the old id back, signed in on the same `sid`. Once
 * the escalation is recorded with the renewal's nonce, core's admission
 * refuses that id, and admits the renewed one.
 */

import {
	admitPrimary,
	admitSession,
	cookieClaim,
	createInMemoryUserSessionStore,
	isRenewalNonce,
	passwordPrimary,
	type SessionRenewalResult,
} from "@o3co/auth-provider-core";
import { createTestCsrfGuard, resolverForTests } from "@o3co/auth-provider-core/testing";
import express from "express";
import session, { MemoryStore } from "express-session";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { createLoginCompletion } from "#/login-completion.mjs";
import { fakeSessionLifecycle, openingLifecycleStore } from "./_helpers/sessionLifecycle.mjs";

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
	const sessionLifecycleStore = openingLifecycleStore();
	const completion = createLoginCompletion({
		userSessionStore,
		sessionLifecycle: fakeSessionLifecycle(),
		sessionTtlMs: 3_600_000,
		csrf: createTestCsrfGuard(),
	});
	const reported: string[] = [];
	// A request on the old id, held while the renewal runs: it writes the
	// session it loaded, as the federation start writes its state.
	let entered: () => void = () => {};
	const inFlightEntered = new Promise<void>((resolve) => {
		entered = resolve;
	});
	let release: () => void = () => {};
	const held = new Promise<void>((resolve) => {
		release = resolve;
	});
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
	// The step-up's finish: renew, then record the escalation on the record
	// the renewed session names — expecting the nonce the cookie session held
	// when the request came in, with the renewal's nonce ("bound"), or (to
	// show the race) without either ("unbound"). `?held` holds the request,
	// its session loaded, until the test releases it.
	app.post("/renew", async (req, res) => {
		const sid = req.session?.sid;
		const expected = cookieClaim(req).renewalNonce;
		if (req.query.held !== undefined) {
			entered();
			await held;
		}
		const result: SessionRenewalResult = await completion.renewSession({
			req,
			reporter: { storeUnavailable: (store, step) => reported.push(`${store}:${step}`) },
		});
		let recorded: readonly string[] | null | undefined;
		if (result.outcome === "renewed" && sid !== undefined && req.query.record !== undefined) {
			const answer = await userSessionStore.recordSecondFactor(sid, {
				amr: String(req.query.amr ?? "otp,mfa").split(","),
				at: new Date(),
				...(req.query.record === "bound"
					? {
							renewalNonce: result.renewalNonce,
							...(expected === undefined ? {} : { expectedRenewalNonce: expected }),
						}
					: {}),
			});
			recorded = answer === null ? null : (answer.amr ?? []);
		}
		res
			.status(result.outcome === "renewed" ? 200 : 503)
			.json(recorded === undefined ? result : { ...result, recorded });
	});
	app.post("/in-flight", async (req, res) => {
		entered();
		await held;
		(req.session as unknown as Record<string, unknown>).federationState = "state";
		res.json({ ok: true });
	});
	app.get("/whoami", (req, res) => {
		res.json(cookieClaim(req));
	});
	app.get("/admit", async (req, res) => {
		const admission = await admitSession(
			{
				userSessionStore,
				sessionLifecycleStore,
				subjectRevocation: undefined,
				requirements: resolverForTests([], { actions: { "test.use": { grade: "use" } } }),
				acrTable: {},
				logger: undefined,
				auditSink: undefined,
			},
			{ claim: cookieClaim(req), action: "test.use" },
		);
		res.json(
			admission.outcome === "admitted"
				? { outcome: admission.outcome, amr: admission.session?.amr }
				: admission,
		);
	});
	return { app, cookieStore, userSessionStore, reported, inFlightEntered, release };
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
		expect(renewed.body).toEqual({ outcome: "renewed", renewalNonce: expect.any(String) });
		expect(reported).toEqual([]);
		const id = cookieSessionId(renewed) as string;
		expect(id).toBeDefined();
		expect(id).not.toBe(signedIn.id);

		const held = cookieStore.sessions();
		expect(Object.keys(held)).toEqual([id]);
		const { cookie: _cookie, ...fields } = held[id] as Record<string, unknown>;
		expect(isRenewalNonce(renewed.body.renewalNonce)).toBe(true);
		expect(fields).toEqual({
			isAuthenticated: true,
			user: USER,
			sid: signedIn.sid,
			renewalNonce: renewed.body.renewalNonce,
		});

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
		expect(res.body).toEqual({ outcome: "renewed", renewalNonce: expect.any(String) });
		for (const held of Object.values(cookieStore.sessions())) {
			expect(held).not.toHaveProperty("isAuthenticated");
			expect(held).not.toHaveProperty("user");
			expect(held).not.toHaveProperty("sid");
		}
	});
});

describe("the renewal race: a request in flight on the old id saves after the renewal", () => {
	/** Signs in, holds a writing request on the old id, renews (recording as `record` says), then lets it save. */
	async function race(record: "bound" | "unbound") {
		const setUp = setup();
		const { app, cookieStore, inFlightEntered, release } = setUp;
		const signedIn = await signIn(app);
		const old = cookieOf(signedIn.raw);
		const inFlight = request(app)
			.post("/in-flight")
			.set("Cookie", old)
			.then((res) => res);
		await inFlightEntered;
		const renewed = await request(app).post(`/renew?record=${record}`).set("Cookie", old);
		expect(renewed.status).toBe(200);
		// The old id is destroyed by the renewal …
		expect(cookieStore.sessions()[signedIn.id]).toBeUndefined();
		release();
		await inFlight;
		// … and the request in flight saves it back, signed in on the same sid.
		expect(cookieStore.sessions()[signedIn.id]).toMatchObject({
			isAuthenticated: true,
			sid: signedIn.sid,
			federationState: "state",
		});
		expect(cookieStore.sessions()[signedIn.id]).not.toHaveProperty("renewalNonce");
		return { ...setUp, old, renewed: cookieOf(renewed) };
	}

	it("with the escalation recorded with the renewal's nonce, the old id saved back is not_live (renewed), and the renewed one is admitted with the escalation", async () => {
		const { app, old, renewed } = await race("bound");
		expect((await request(app).get("/admit").set("Cookie", old)).body).toEqual({
			outcome: "not_live",
			reason: "renewed",
		});
		expect((await request(app).get("/admit").set("Cookie", renewed)).body).toEqual({
			outcome: "admitted",
			amr: ["pwd", "otp", "mfa"],
		});
	});

	it("without the nonce on the record, the old id saved back is admitted to the escalated session: the race the binding closes", async () => {
		const { app, old } = await race("unbound");
		expect((await request(app).get("/admit").set("Cookie", old)).body).toEqual({
			outcome: "admitted",
			amr: ["pwd", "otp", "mfa"],
		});
	});
});

describe("two step-ups, and two completions of one", () => {
	it("a second step-up from the renewed session records, expecting the first's nonce; the first renewed id then names nothing", async () => {
		const { app } = setup();
		const signedIn = await signIn(app);
		const first = await request(app)
			.post("/renew?record=bound&amr=otp,mfa")
			.set("Cookie", cookieOf(signedIn.raw));
		expect(first.body).toMatchObject({ outcome: "renewed", recorded: ["pwd", "otp", "mfa"] });
		const second = await request(app)
			.post("/renew?record=bound&amr=hwk,mfa")
			.set("Cookie", cookieOf(first));
		expect(second.body).toMatchObject({
			outcome: "renewed",
			recorded: ["pwd", "otp", "mfa", "hwk"],
		});
		expect((await request(app).get("/admit").set("Cookie", cookieOf(second))).body).toEqual({
			outcome: "admitted",
			amr: ["pwd", "otp", "mfa", "hwk"],
		});
		expect((await request(app).get("/admit").set("Cookie", cookieOf(first))).body).toEqual({
			outcome: "unauthenticated",
		});
	});

	it("of two step-ups started from one cookie, the one that records second is refused, and its renewed id never gains the first's factor", async () => {
		const { app, inFlightEntered, release } = setup();
		const signedIn = await signIn(app);
		const old = cookieOf(signedIn.raw);
		// B loads the old session and is held; A renews and records hwk.
		const b = request(app)
			.post("/renew?held=1&record=bound&amr=otp,mfa")
			.set("Cookie", old)
			.then((res) => res);
		await inFlightEntered;
		const a = await request(app).post("/renew?record=bound&amr=hwk,mfa").set("Cookie", old);
		expect(a.body).toMatchObject({ outcome: "renewed", recorded: ["pwd", "hwk", "mfa"] });
		release();
		const bAnswer = await b;
		// B renewed from the session it had loaded, and its completion is refused.
		expect(bAnswer.body).toMatchObject({ outcome: "renewed", recorded: null });
		expect((await request(app).get("/admit").set("Cookie", cookieOf(bAnswer))).body).toEqual({
			outcome: "not_live",
			reason: "renewed",
		});
		expect((await request(app).get("/admit").set("Cookie", cookieOf(a))).body).toEqual({
			outcome: "admitted",
			amr: ["pwd", "hwk", "mfa"],
		});
	});
});
