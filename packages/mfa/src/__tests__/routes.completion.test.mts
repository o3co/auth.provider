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
 * The login's completion after a verified second factor, through the
 * composed application: the login resumes through core's `resumePrimary` and
 * is finished by the session package's login completion — the session the
 * password login would have written, with the second factor recorded, or
 * another requirement's interruption — and what it refuses. Sealed data
 * copied to another subject does not open. See ADR
 * 2026-09-28-session-admission, D5, and ADR
 * 2026-09-25-multi-factor-authentication, F1 step 5 and D11.
 */

import {
	type CookieCarrier,
	cookieClaim,
	createMemoryMfaFactorStore,
	createMemoryMfaTransactionStore,
	defineModule,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import type { Request, Response } from "express";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	ALICE,
	BOB,
	boot,
	configFor,
	disposeAll,
	events,
	sessionIdSet,
} from "./moduleHarness.mjs";
import {
	beginLogin,
	EXTRA_INTERRUPTION,
	extraRequirement,
	freezeClock,
	seedTotp,
	setsCsrfToken,
	T0,
	thawClock,
	totpCode,
	verify,
} from "./routesHarness.mjs";

beforeEach(() => freezeClock());
afterEach(async () => {
	await disposeAll();
	thawClock();
});

/** A route that answers the claim core reads off the presented cookie session: GET `/__test__/session`. */
const sessionReader = defineModule({
	name: "test:session-reader",
	contributes: {
		routes: [
			() => ({
				id: "test-session-reader",
				mountPath: "/__test__",
				after: ["session-middleware"],
				handler: ((req: Request, res: Response, next: () => void) => {
					if (req.method !== "GET" || req.path !== "/session") {
						next();
						return;
					}
					const { authenticated, sid, subject } = cookieClaim(req as CookieCarrier);
					res.json({ authenticated, sid: sid ?? null, subject: subject ?? null });
				}) as never,
			}),
		],
	},
});

describe("a verified second factor completes the login", () => {
	it("as the password login would have: the browser signed in on the new session, and the session record the one it names", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record, secret } = await seedTotp(factorStore);
		const { app, userSessionStore } = await boot({
			config: configFor("required"),
			factorStore,
			extraModules: [sessionReader],
		});
		const { agent, transaction } = await beginLogin(app);
		const before = await agent.get("/__test__/session");
		expect(before.body).toEqual({ authenticated: false, sid: null, subject: null });

		expect((await verify(agent, transaction, record.id, totpCode(secret))).status).toBe(200);

		const after = await agent.get("/__test__/session");
		expect(after.body).toMatchObject({ authenticated: true, subject: ALICE.id });
		const stored = await (userSessionStore as UserSessionStore).get(after.body.sid as string);
		expect(stored).toMatchObject({
			sub: ALICE.id,
			authTime: expect.any(Date),
			amr: ["pwd", "otp", "mfa"],
			authentication: { primary: "pwd", mfaAt: new Date(T0) },
		});
	});

	it("answers another requirement that interrupts the resumed login: its 403 with a fresh CSRF token, its ceremony opened on a regenerated session with the second factor in the continuation, and no session written", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record, secret } = await seedTotp(factorStore);
		const extra = extraRequirement();
		const { app, handle, userSessionStore } = await boot({
			config: configFor("required", {}, {}, ["mfa", extra.name]),
			factorStore,
			extraModules: [extra.module, sessionReader],
		});
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
		const { agent, transaction, boundTo } = await beginLogin(app);

		const res = await verify(agent, transaction, record.id, totpCode(secret));

		expect(res.status).toBe(403);
		expect(res.body).toEqual(EXTRA_INTERRUPTION.body);
		const regenerated = sessionIdSet(res);
		expect(regenerated).toBeDefined();
		expect(regenerated).not.toBe(boundTo);
		const guard = handle.components.csrfGuard;
		if (guard === undefined) throw new Error("the composition holds no CSRF guard");
		expect(setsCsrfToken(res, guard)).toBe(true);
		expect(extra.opened).toEqual([
			{
				sessionId: regenerated,
				continuation: expect.objectContaining({
					interruptedBy: extra.name,
					done: [{ requirement: "mfa", adds: { amr: ["otp", "mfa"], mfaAtMs: T0 } }],
				}),
			},
		]);
		expect(create).not.toHaveBeenCalled();
		expect((await agent.get("/__test__/session")).body).toMatchObject({ authenticated: false });
	});

	it("answers a login core will not resume 401 login_required, once at warn, and writes no session", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record, secret } = await seedTotp(factorStore);
		const store = createMemoryMfaTransactionStore();
		const { app, userSessionStore, logger } = await boot({
			config: configFor("required"),
			factorStore,
			transactionStore: {
				...store,
				// What a record consumed answers: its continuation waits on a requirement
				// this deployment no longer has.
				consume: async (...args) => {
					const consumed = await store.consume(...args);
					return consumed === null || consumed.continuation === undefined
						? consumed
						: { ...consumed, continuation: { ...consumed.continuation, interruptedBy: "gone" } };
				},
			},
		});
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
		const { agent, transaction } = await beginLogin(app);

		const res = await verify(agent, transaction, record.id, totpCode(secret));

		expect(res.status).toBe(401);
		expect(res.body).toEqual({ error: "login_required", error_description: "Log in again" });
		expect(events(logger, "warn")).toEqual(["mfa_login_not_resumed"]);
		expect(events(logger, "error")).toEqual([]);
		expect(create).not.toHaveBeenCalled();
	});
});

describe("a factor's sealed data (D11)", () => {
	it("copied to another subject's record does not open there: 503 once, mfa_factor_unreadable, and no session", async () => {
		const factorStore = createMemoryMfaFactorStore();
		// Bob's record carries data sealed to alice's record of the same id.
		const { record, secret } = await seedTotp(factorStore, BOB.id, { sealedFor: ALICE.id });
		const { app, userSessionStore, logger } = await boot({
			config: configFor("required"),
			factorStore,
		});
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
		const { agent, transaction } = await beginLogin(app, BOB);

		const res = await verify(agent, transaction, record.id, totpCode(secret));

		expect(res.status).toBe(503);
		expect(events(logger, "error")).toEqual(["mfa_factor_unreadable"]);
		expect(logger.error.mock.calls[0]?.[0]).toMatchObject({
			kind: "totp",
			factorId: record.id,
			state: "unreadable",
		});
		expect(create).not.toHaveBeenCalled();
	});
});
