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
 * The login's interruption through the composed application: `createApp` with
 * the session package's login, the MFA package's modules and core's memory MFA
 * stores, driven by a supertest agent holding the cookie jar. The cases are
 * the ones their names state. See ADR 2026-09-25-multi-factor-authentication,
 * flows "Password login → second factor → session" and "First login with no
 * factor", as ADR 2026-09-28-session-admission ("Establishment") amends them.
 */

import {
	createMemoryMfaFactorStore,
	createMemoryMfaTransactionStore,
	defineModule,
	type MfaTransactionStore,
	passwordSessionAuthentication,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import type { Request, Response } from "express";
import request from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	ALICE,
	boot,
	configFor,
	disposeAll,
	events,
	login,
	sessionIdSet,
} from "./moduleHarness.mjs";
import { factorRecord, unreachableFactorStore } from "./requirementHarness.mjs";

afterEach(disposeAll);

/**
 * A route that plants a session before the login — what an attacker who
 * fixes a victim's session id holds — and one that reads it back: GET
 * `/__test__/plant` writes the session and answers its id; GET
 * `/__test__/planted` answers what the presented session holds.
 */
const plantingModule = defineModule({
	name: "test:session-planter",
	contributes: {
		routes: [
			() => ({
				id: "test-session-planter",
				mountPath: "/__test__",
				after: ["session-middleware"],
				handler: ((req: Request, res: Response, next: () => void) => {
					const session = req.session as unknown as Record<string, unknown>;
					if (req.method === "GET" && req.path === "/plant") {
						session.planted = "yes";
						res.json({ id: req.sessionID });
						return;
					}
					if (req.method === "GET" && req.path === "/planted") {
						res.json({ planted: session.planted ?? null });
						return;
					}
					next();
				}) as never,
			}),
		],
	},
});

const SESSION_STORE_UNAVAILABLE = {
	error: "temporarily_unavailable",
	error_description: "Session store unavailable",
};

/** Admission's outage answer when the one reporting it is a requirement (core's `describeAdmissionOutage`). */
const REQUIREMENT_UNAVAILABLE = {
	error: "temporarily_unavailable",
	error_description: "session requirement unavailable",
};

/** A factor store holding one TOTP factor for alice. */
async function aliceEnrolled() {
	const store = createMemoryMfaFactorStore();
	await store.create(factorRecord(ALICE.id, "totp"));
	return store;
}

/** A transaction store whose `create` is a spy. */
function watchedTransactions(): { store: MfaTransactionStore; create: ReturnType<typeof vi.fn> } {
	const store = createMemoryMfaTransactionStore();
	const create = vi.fn(store.create);
	return { store: { ...store, create }, create };
}

describe("a password login under required, the subject holding a factor (F1 step 2)", () => {
	it("is answered 403 mfa_required with the closed body, the transaction bound to the regenerated session and carrying the login's continuation, and no UserSession written", async () => {
		const { app, userSessionStore, transactionStore } = await boot({
			config: configFor("required"),
			factorStore: await aliceEnrolled(),
		});
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
		const { res } = await login(app, { redirect_to: "https://app.example/after" });

		expect(res.status).toBe(403);
		expect(res.body).toEqual({
			error: "mfa_required",
			transaction: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
			expires_in: 600,
		});

		const transaction = await transactionStore.get(res.body.transaction as string);
		// Bound to the session the browser now holds: the one the login regenerated.
		const regenerated = sessionIdSet(res);
		expect(regenerated).toBeDefined();
		expect(transaction).toMatchObject({
			purpose: "login",
			binding: { kind: "session", id: regenerated },
			subject: ALICE.id,
			redirectTo: "https://app.example/after",
			enrollment: "none",
			continuation: {
				interruptedBy: "mfa",
				done: [],
				primary: {
					subject: ALICE.id,
					recorded: passwordSessionAuthentication(),
					redirectTo: "https://app.example/after",
				},
			},
		});
		expect(transaction?.expiresAtMs).toBe((transaction?.createdAtMs ?? 0) + 600_000);
		expect(create).not.toHaveBeenCalled();
	});
});

describe("session fixation, end to end (the MFA ADR's D27)", () => {
	it("binds the transaction to a session id the login minted: one the browser held before — planted — is not it, and holds nothing afterwards", async () => {
		const { app, transactionStore } = await boot({
			config: configFor("required"),
			factorStore: await aliceEnrolled(),
			extraModules: [plantingModule],
		});
		const agent = request.agent(app);
		const planted = await agent.get("/__test__/plant");
		const plantedId = planted.body.id as string;
		expect(sessionIdSet(planted)).toBe(plantedId);
		// The CSRF token is stateless: fetching it touches no session.
		const csrf = await agent.get("/session/csrf");
		expect(sessionIdSet(csrf)).toBeUndefined();
		const res = await agent
			.post("/session/login")
			.set(csrf.body.header_name as string, csrf.body.csrf_token as string)
			.send({ username: ALICE.username, password: ALICE.password });
		expect(res.status).toBe(403);
		const transaction = await transactionStore.get(res.body.transaction as string);
		expect(transaction?.binding).toStrictEqual({ kind: "session", id: sessionIdSet(res) });
		expect(transaction?.binding.id).not.toBe(plantedId);
		// The planted id is dead: presented again, it carries nothing.
		const replanted = await request(app)
			.get("/__test__/planted")
			.set("Cookie", (planted.headers["set-cookie"] as unknown as string[])[0] as string);
		expect(replanted.body).toEqual({ planted: null });
	});
});

describe("the transaction's life, as configured (D8)", () => {
	it("lives mfa.transactionTtlSeconds: the 403's expires_in and the transaction's expiry are the setting's, not the default's", async () => {
		const { app, transactionStore } = await boot({
			config: configFor("required", { transactionTtlSeconds: 120 }),
			factorStore: await aliceEnrolled(),
		});
		const { res } = await login(app);
		expect(res.status).toBe(403);
		expect(res.body.expires_in).toBe(120);
		const transaction = await transactionStore.get(res.body.transaction as string);
		expect((transaction?.expiresAtMs ?? 0) - (transaction?.createdAtMs ?? 0)).toBe(120_000);
	});
});

describe("a password login under required, the subject holding no record (F3 step 1; owner decision 2)", () => {
	it("is answered 403 mfa_enrollment_required with the kinds that may be enrolled and whether an email proof comes first, and no UserSession written", async () => {
		const { app, userSessionStore, transactionStore } = await boot({
			config: configFor("required"),
		});
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
		const { res } = await login(app);
		expect(res.status).toBe(403);
		expect(res.body).toEqual({
			error: "mfa_enrollment_required",
			transaction: expect.any(String),
			expires_in: 600,
			hints: { enrollable: ["totp"], email_proof: false },
		});
		expect(await transactionStore.get(res.body.transaction as string)).toMatchObject({
			binding: { kind: "session", id: sessionIdSet(res) },
			enrollment: "required",
			emailProof: "not_required",
		});
		expect(create).not.toHaveBeenCalled();
	});
});

describe("a password login under optional, the subject holding no record", () => {
	it("is established as it always was: 200, a UserSession recorded as a password login's, no transaction opened", async () => {
		const watched = watchedTransactions();
		const { app, userSessionStore } = await boot({
			config: configFor("optional"),
			transactionStore: watched.store,
		});
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
		const { res } = await login(app);
		expect(res.status).toBe(200);
		expect(res.body).toEqual({ message: "Logged in successfully" });
		expect(create).toHaveBeenCalledTimes(1);
		expect(create.mock.calls[0]?.[0]).toMatchObject({
			sub: ALICE.id,
			...passwordSessionAuthentication(),
		});
		expect(watched.create).not.toHaveBeenCalled();
	});

	it("is still interrupted for the second factor of a subject who holds one", async () => {
		const { app } = await boot({
			config: configFor("optional"),
			factorStore: await aliceEnrolled(),
		});
		const { res } = await login(app);
		expect(res.status).toBe(403);
		expect(res.body.error).toBe("mfa_required");
	});
});

describe("a password login whose transaction cannot be kept (F1 step 2)", () => {
	it("is answered 503 after the regeneration, the cookie session dropped, one error line, and no UserSession written", async () => {
		const store = createMemoryMfaTransactionStore();
		const { app, userSessionStore, logger } = await boot({
			config: configFor("required"),
			factorStore: await aliceEnrolled(),
			transactionStore: {
				...store,
				create: async () => {
					throw new Error("transaction store unreachable");
				},
			},
		});
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
		const { res } = await login(app);
		expect(res.status).toBe(503);
		expect(res.body).toEqual(SESSION_STORE_UNAVAILABLE);
		// The regenerated session is abandoned: the browser is handed none.
		expect(sessionIdSet(res)).toBeUndefined();
		expect(events(logger, "error")).toEqual(["login_store_unavailable"]);
		expect(logger.error.mock.calls[0]?.[0]).toMatchObject({ store: "mfa", step: "open" });
		expect(create).not.toHaveBeenCalled();
	});
});

describe("a password login while the factor store is down (F1 step 1)", () => {
	it("is answered 503 once, with one error line and nothing written — no UserSession, no transaction", async () => {
		const watched = watchedTransactions();
		const { app, userSessionStore, logger } = await boot({
			config: configFor("optional"),
			factorStore: unreachableFactorStore(),
			transactionStore: watched.store,
		});
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
		const { res } = await login(app);
		expect(res.status).toBe(503);
		expect(res.body).toEqual(REQUIREMENT_UNAVAILABLE);
		expect(events(logger, "error")).toEqual(["session_admission_unavailable"]);
		expect(logger.error.mock.calls[0]?.[0]).toMatchObject({
			store: "mfa",
			phase: "establishment",
		});
		expect(create).not.toHaveBeenCalled();
		expect(watched.create).not.toHaveBeenCalled();
		// Nothing was regenerated: the browser is handed no new session.
		expect(sessionIdSet(res)).toBeUndefined();
	});
});
