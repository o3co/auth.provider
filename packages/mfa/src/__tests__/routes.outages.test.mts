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
 * Every store the MFA routes read or write, down, through the composed
 * application: each outage is answered `503 temporarily_unavailable` and
 * logged once at error, and none is ever read as "no factor", a wrong code or
 * a session. See ADR 2026-09-25-multi-factor-authentication, D11 and D28.
 */

import {
	createInMemoryUserSessionStore,
	createMemoryMfaFactorStore,
	createMemoryMfaTransactionStore,
	type MfaFactorStore,
	type MfaTransactionStore,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { boot, configFor, disposeAll, events } from "./moduleHarness.mjs";
import {
	beginLogin,
	extraRequirement,
	freezeClock,
	mfaPost,
	readTransaction,
	seedTotp,
	storedData,
	thawClock,
	totpCode,
	verify,
} from "./routesHarness.mjs";

beforeEach(() => freezeClock());
afterEach(async () => {
	await disposeAll();
	thawClock();
});

const MFA_UNAVAILABLE = {
	error: "temporarily_unavailable",
	error_description: "MFA temporarily unavailable",
};

const SESSION_STORE_UNAVAILABLE = {
	error: "temporarily_unavailable",
	error_description: "Session store unavailable",
};

const down = (): never => {
	throw new Error("the store is down: 10.0.0.7:6379 ECONNREFUSED");
};

/**
 * `store` with `method` down once `armed()` answers true: the login's own
 * reads and writes go through before the test arms it.
 */
function downWhenArmed<T extends object>(store: T, method: keyof T): { store: T; arm(): void } {
	let armed = false;
	const original = store[method] as unknown as (...args: unknown[]) => unknown;
	return {
		arm: () => {
			armed = true;
		},
		store: {
			...store,
			[method]: (...args: unknown[]) => (armed ? down() : original.apply(store, args)),
		},
	};
}

describe("the transaction store down", () => {
	it.each(["get", "reserveAttempt", "consume"] as const)(
		"at %s: a verification is answered 503 once, and no session is written",
		async (method) => {
			const factorStore = createMemoryMfaFactorStore();
			const { record, secret } = await seedTotp(factorStore);
			const failing = downWhenArmed<MfaTransactionStore>(createMemoryMfaTransactionStore(), method);
			const { app, logger, userSessionStore } = await boot({
				config: configFor("required"),
				factorStore,
				transactionStore: failing.store,
			});
			const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
			const { agent, transaction } = await beginLogin(app);
			failing.arm();

			const res = await verify(agent, transaction, record.id, totpCode(secret));

			expect(res.status).toBe(503);
			expect(res.body).toEqual(MFA_UNAVAILABLE);
			expect(events(logger, "error")).toEqual(["mfa_store_unavailable"]);
			expect(logger.error.mock.calls[0]?.[0]).toMatchObject({
				route: "verify",
				store: "mfa_transaction",
				step: method,
				err: expect.objectContaining({ name: "Error" }),
			});
			expect(create).not.toHaveBeenCalled();
			expect((await storedData(factorStore, record)).record.version).toBe(0);
		},
	);

	it.each(["transaction", "challenge"] as const)(
		"at get: the %s route is answered 503 once",
		async (route) => {
		const factorStore = createMemoryMfaFactorStore();
		const { record } = await seedTotp(factorStore);
		const failing = downWhenArmed<MfaTransactionStore>(createMemoryMfaTransactionStore(), "get");
		const { app, logger } = await boot({
			config: configFor("required"),
			factorStore,
			transactionStore: failing.store,
		});
		const { agent, transaction } = await beginLogin(app);
		failing.arm();

		const res =
			route === "transaction"
				? await readTransaction(agent, transaction)
				: await mfaPost(agent, "/challenge", { transaction_id: transaction, factor_id: record.id });

		expect(res.status).toBe(503);
		expect(res.body).toEqual(MFA_UNAVAILABLE);
		expect(events(logger, "error")).toEqual(["mfa_store_unavailable"]);
		expect(logger.error.mock.calls[0]?.[0]).toMatchObject({
			route,
			store: "mfa_transaction",
			step: "get",
		});
		},
	);
});

describe("the factor store down", () => {
	it.each([["transaction"], ["challenge"], ["verify"]] as const)(
		"at list: %s is answered 503 once — never as a subject with no factor",
		async (route) => {
			const factorStore = createMemoryMfaFactorStore();
			const { record, secret } = await seedTotp(factorStore);
			const failing = downWhenArmed<MfaFactorStore>(factorStore, "list");
			const { app, logger, transactionStore } = await boot({
				config: configFor("required"),
				factorStore: failing.store,
			});
			const { agent, transaction } = await beginLogin(app);
			failing.arm();

			const res =
				route === "transaction"
					? await readTransaction(agent, transaction)
					: route === "challenge"
						? await mfaPost(agent, "/challenge", {
								transaction_id: transaction,
								factor_id: record.id,
							})
						: await verify(agent, transaction, record.id, totpCode(secret));

			expect(res.status).toBe(503);
			expect(res.body).toEqual(MFA_UNAVAILABLE);
			expect(events(logger, "error")).toEqual(["mfa_store_unavailable"]);
			expect(logger.error.mock.calls[0]?.[0]).toMatchObject({
				route,
				store: "mfa_factor",
				step: "list",
			});
			expect((await transactionStore.get(transaction))?.attempts).toBe(0);
		},
	);

	it("at update, after the transaction was consumed: 503 once, no session, the step unspent — the user starts again from the password", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record, secret } = await seedTotp(factorStore);
		const failing = downWhenArmed<MfaFactorStore>(factorStore, "update");
		const { app, logger, userSessionStore, transactionStore } = await boot({
			config: configFor("required"),
			factorStore: failing.store,
		});
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
		const { agent, transaction } = await beginLogin(app);
		failing.arm();

		const res = await verify(agent, transaction, record.id, totpCode(secret));

		expect(res.status).toBe(503);
		expect(res.body).toEqual(MFA_UNAVAILABLE);
		expect(events(logger, "error")).toEqual(["mfa_store_unavailable"]);
		expect(logger.error.mock.calls[0]?.[0]).toMatchObject({
			route: "verify",
			store: "mfa_factor",
			step: "update",
		});
		expect(create).not.toHaveBeenCalled();
		expect(await transactionStore.get(transaction)).toBeNull();
		expect((await storedData(factorStore, record)).data.lastUsedStep).toBe(0);
	});
});

describe("a factor whose data does not open (D11)", () => {
	it("is answered 503 once, mfa_factor_unreadable naming the key it needs, and spends no attempt — never a wrong code", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record, secret } = await seedTotp(factorStore);
		// The ring the deployment runs with lost the key the factor was sealed under.
		const { app, logger, transactionStore } = await boot({
			config: configFor("required", {
				encryptionKeys: [{ key: Buffer.alloc(32, 7).toString("base64") }],
			}),
			factorStore,
		});
		const { agent, transaction } = await beginLogin(app);

		const res = await verify(agent, transaction, record.id, totpCode(secret));

		expect(res.status).toBe(503);
		expect(res.body).toEqual(MFA_UNAVAILABLE);
		expect(events(logger, "error")).toEqual(["mfa_factor_unreadable"]);
		expect(logger.error.mock.calls[0]?.[0]).toMatchObject({
			route: "verify",
			kind: "totp",
			factorId: record.id,
			state: "key_unavailable",
			keyId: expect.stringMatching(/^k[A-Za-z0-9_-]{16}$/),
		});
		expect((await transactionStore.get(transaction))?.attempts).toBe(0);
	});
});

describe("the session stores down at the login's completion", () => {
	it("the user-session store at create: 503 once, in the session store's words", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record, secret } = await seedTotp(factorStore);
		const sessions = createInMemoryUserSessionStore();
		const failing = downWhenArmed<UserSessionStore>(sessions, "create");
		const { app, logger } = await boot({
			config: configFor("required"),
			factorStore,
			userSessionStore: failing.store,
		});
		const { agent, transaction } = await beginLogin(app);
		failing.arm();

		const res = await verify(agent, transaction, record.id, totpCode(secret));

		expect(res.status).toBe(503);
		expect(res.body).toEqual(SESSION_STORE_UNAVAILABLE);
		expect(events(logger, "error")).toEqual(["mfa_store_unavailable"]);
		expect(logger.error.mock.calls[0]?.[0]).toMatchObject({
			route: "verify",
			store: "user_session",
			step: "create",
		});
	});

	it("another requirement's store, asked as the login resumes: 503 once, admission's words and line", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record, secret } = await seedTotp(factorStore);
		const extra = extraRequirement({ admitPrimary: async () => down() });
		const { app, logger } = await boot({
			config: configFor("required", {}, {}, ["mfa", extra.name]),
			factorStore,
			extraModules: [extra.module],
		});
		const { agent, transaction } = await beginLogin(app);

		const res = await verify(agent, transaction, record.id, totpCode(secret));

		expect(res.status).toBe(503);
		expect(res.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "session requirement unavailable",
		});
		expect(events(logger, "error")).toEqual(["session_admission_unavailable"]);
		expect(logger.error.mock.calls[0]?.[0]).toMatchObject({ store: extra.name });
	});
});
