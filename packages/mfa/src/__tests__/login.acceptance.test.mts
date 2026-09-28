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
 * The login's interruption through the composed application (the MFA ADR's
 * F1 steps 1–2 and F3 step 1, as the session-admission ADR's D5 amends
 * them): `createApp` with the session package's login, the MFA package's
 * modules and core's memory MFA stores, driven by a supertest agent holding
 * the cookie jar.
 *
 * - `required`, a factor on record → `403 mfa_required` with the closed body
 *   (`error`, `transaction`, `expires_in`), the express session regenerated
 *   and the transaction bound to the id the browser now holds, carrying the
 *   login's continuation; no `UserSession` is written;
 * - `required`, no record → `403 mfa_enrollment_required`, with
 *   `hints.enrollable` and `hints.email_proof`;
 * - `optional`, no record → `200`, the session written as it always was;
 * - the factor store down → `503` once, one error line, nothing written —
 *   no `UserSession`, no transaction.
 */

import {
	createMemoryMfaFactorStore,
	createMemoryMfaTransactionStore,
	type MfaTransactionStore,
	passwordSessionAuthentication,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
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

const SESSION_STORE_UNAVAILABLE = {
	error: "temporarily_unavailable",
	error_description: "Session store unavailable",
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
			sessionId: regenerated,
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
			sessionId: sessionIdSet(res),
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
		expect(res.body).toEqual(SESSION_STORE_UNAVAILABLE);
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
