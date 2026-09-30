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
 * A verification that must not complete, through the composed application:
 * a store that answers outside its port's contract, a factor whose `amrFor`
 * answers outside what it declares, and — under `required` — a factor that
 * does not count for a subject who holds no counting factor it can use.
 * Each fails closed: nothing is established, and what the store answered is
 * never read as a verdict. See ADR 2026-09-25-multi-factor-authentication,
 * F1 step 5, F3, D14 and D28.
 */

import {
	createMemoryMfaFactorStore,
	createMemoryMfaTransactionStore,
	type MfaFactor,
	type MfaFactorStore,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { createTestMfaFactor } from "@o3co/auth-provider-core/testing";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { BOB, boot, configFor, disposeAll, events, login } from "./moduleHarness.mjs";
import {
	beginLogin,
	contributing,
	freezeClock,
	recordingAuditSink,
	seedFactor,
	seedTotp,
	storedData,
	thawClock,
	totpCode,
	verify,
	wrongCode,
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

describe("a transaction store answering outside its contract", () => {
	it.each<[string, unknown]>([
		["a count that is not a number", { ok: true, attempts: Number.NaN }],
		["a reservation counting nothing", { ok: true, attempts: 0 }],
		["a reservation past the limit", { ok: true, attempts: 6 }],
		["an ok that is truthy but not true", { ok: "yes", attempts: 1 }],
	])("at reserveAttempt, %s: 503 once, and no proof is checked", async (_label, answer) => {
		const factorStore = createMemoryMfaFactorStore();
		const { record, secret } = await seedTotp(factorStore);
		const inner = createMemoryMfaTransactionStore();
		const audit = recordingAuditSink();
		const { app, logger, userSessionStore } = await boot({
			config: configFor("required"),
			factorStore,
			auditSink: audit,
			transactionStore: { ...inner, reserveAttempt: async () => answer as never },
		});
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
		const { agent, transaction } = await beginLogin(app);

		const answers = [];
		for (let n = 0; n < 3; n++) {
			answers.push(await verify(agent, transaction, record.id, wrongCode(secret)));
		}
		answers.push(await verify(agent, transaction, record.id, totpCode(secret)));

		for (const res of answers) {
			expect(res.status).toBe(503);
			expect(res.body).toEqual(MFA_UNAVAILABLE);
		}
		expect(events(logger, "error")).toEqual(Array(4).fill("mfa_store_unavailable"));
		expect(logger.error.mock.calls[0]?.[0]).toMatchObject({
			route: "verify",
			store: "mfa_transaction",
			step: "reserveAttempt",
		});
		expect(audit.of("mfa.verify.failure")).toEqual([]);
		expect(audit.of("mfa.verified")).toEqual([]);
		expect(create).not.toHaveBeenCalled();
		expect((await storedData(factorStore, record)).record.version).toBe(0);
	});

	it("at consume, another login's transaction: 503 once — the factor not advanced and no session, for either subject", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record, secret } = await seedTotp(factorStore);
		await seedTotp(factorStore, BOB.id);
		const inner = createMemoryMfaTransactionStore();
		let bobs: string | undefined;
		const { app, logger, userSessionStore } = await boot({
			config: configFor("required"),
			factorStore,
			transactionStore: {
				...inner,
				consume: async (id, version) => {
					const own = await inner.consume(id, version);
					return own === null || bobs === undefined ? own : inner.consume(bobs, 0);
				},
			},
		});
		const alice = await beginLogin(app);
		const bob = await login(app, { username: BOB.username, password: BOB.password });
		bobs = bob.res.body.transaction as string;
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");

		const res = await verify(alice.agent, alice.transaction, record.id, totpCode(secret));

		expect(res.status).toBe(503);
		expect(res.body).toEqual(MFA_UNAVAILABLE);
		expect(events(logger, "error")).toEqual(["mfa_store_unavailable"]);
		expect(logger.error.mock.calls[0]?.[0]).toMatchObject({
			route: "verify",
			store: "mfa_transaction",
			step: "consume",
		});
		expect(create).not.toHaveBeenCalled();
		expect((await storedData(factorStore, record)).record.version).toBe(0);
	});

	it("at consume, the transaction under another subject: 503 once, and nothing written", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record, secret } = await seedTotp(factorStore);
		const inner = createMemoryMfaTransactionStore();
		const { app, logger, userSessionStore } = await boot({
			config: configFor("required"),
			factorStore,
			transactionStore: {
				...inner,
				consume: async (id, version) => {
					const own = await inner.consume(id, version);
					return own === null ? own : { ...own, subject: BOB.id };
				},
			},
		});
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
		const { agent, transaction } = await beginLogin(app);

		const res = await verify(agent, transaction, record.id, totpCode(secret));

		expect(res.status).toBe(503);
		expect(events(logger, "error")).toEqual(["mfa_store_unavailable"]);
		expect(create).not.toHaveBeenCalled();
		expect((await storedData(factorStore, record)).record.version).toBe(0);
	});
});

/** A factor store whose `update` answers `answer(written)` in place of what it wrote. */
const answering = (
	store: MfaFactorStore,
	answer: (written: Awaited<ReturnType<MfaFactorStore["update"]>>) => unknown,
): MfaFactorStore => ({
	...store,
	update: async (...args) => answer(await store.update(...args)) as never,
});

describe("a factor store answering outside its contract at update", () => {
	it.each<[string, (written: Awaited<ReturnType<MfaFactorStore["update"]>>) => unknown]>([
		["nothing, for a compare-and-set it lost or won", () => undefined],
		["true", () => true],
		["the record as it was before", (written) => written && { ...written, version: 0 }],
		["another factor", (written) => written && { ...written, id: "another-factor-id-000" }],
	])("%s: 503 once, never a verification", async (_label, answer) => {
		const factorStore = createMemoryMfaFactorStore();
		const { record, secret } = await seedTotp(factorStore);
		const audit = recordingAuditSink();
		const { app, logger, userSessionStore } = await boot({
			config: configFor("required"),
			factorStore: answering(factorStore, answer),
			auditSink: audit,
		});
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
		const { agent, transaction } = await beginLogin(app);

		const res = await verify(agent, transaction, record.id, totpCode(secret));

		expect(res.status).toBe(503);
		expect(res.body).toEqual(MFA_UNAVAILABLE);
		expect(events(logger, "error")).toEqual(["mfa_store_unavailable"]);
		expect(logger.error.mock.calls[0]?.[0]).toMatchObject({
			route: "verify",
			store: "mfa_factor",
			step: "update",
		});
		expect(audit.of("mfa.verified")).toEqual([]);
		expect(create).not.toHaveBeenCalled();
	});
});

describe("a factor whose amrFor answers outside what it declares", () => {
	it.each<[string, readonly string[]]>([
		["nothing", []],
		["a value it does not declare", ["hwk"]],
	])(
		"answering %s: 503 once, the transaction not consumed, the factor not advanced",
		async (_label, amr) => {
			const factorStore = createMemoryMfaFactorStore();
			const record = await seedFactor(factorStore, "test", { secret: "s3cret" });
			const factor: MfaFactor = {
				...createTestMfaFactor({ kind: "test", amrValues: ["otp"] }),
				amrFor: () => amr,
			};
			const { app, logger, userSessionStore, transactionStore } = await boot({
				config: configFor("required"),
				factorStore,
				extraModules: [contributing(factor)],
			});
			const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
			const { agent, transaction } = await beginLogin(app);

			const res = await verify(agent, transaction, record.id, "s3cret");

			expect(res.status).toBe(503);
			expect(res.body).toEqual(MFA_UNAVAILABLE);
			expect(events(logger, "error")).toEqual(["mfa_factor_unreadable"]);
			expect(logger.error.mock.calls[0]?.[0]).toMatchObject({
				route: "verify",
				kind: "test",
				state: "verification",
			});
			expect(await transactionStore.get(transaction)).not.toBeNull();
			expect((await storedData(factorStore, record)).record.version).toBe(0);
			expect(create).not.toHaveBeenCalled();
		},
	);
});

/** A factor that does not count, as a recovery code does not: `recovery`, and `mfa` beside it. */
const notCounting = (): MfaFactor =>
	createTestMfaFactor({ kind: "rc", counting: false, amrValues: ["recovery"] });

describe("a factor that does not count, under required (F3)", () => {
	it("does not complete the login of a subject with no counting factor it can use: 403 mfa_enrollment_required, the transaction kept and nothing written", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const record = await seedFactor(factorStore, "rc", { secret: "look-up" });
		const audit = recordingAuditSink();
		const { app, userSessionStore, transactionStore } = await boot({
			config: configFor("required"),
			factorStore,
			auditSink: audit,
			extraModules: [contributing(notCounting())],
		});
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
		const { agent, transaction } = await beginLogin(app);

		const res = await verify(agent, transaction, record.id, "look-up");

		expect(res.status).toBe(403);
		expect(res.body.error).toBe("mfa_enrollment_required");
		expect(create).not.toHaveBeenCalled();
		expect(await transactionStore.get(transaction)).not.toBeNull();
		expect((await storedData(factorStore, record)).record.version).toBe(0);
		expect(audit.of("mfa.verified")).toEqual([]);
	});

	it("does not count a counting factor whose data does not open as one the subject can use", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const record = await seedFactor(factorStore, "rc", { secret: "look-up" });
		// A TOTP record sealed to another subject's: it does not open for alice.
		await seedTotp(factorStore, undefined, { sealedFor: BOB.id });
		const { app, userSessionStore } = await boot({
			config: configFor("required"),
			factorStore,
			extraModules: [contributing(notCounting())],
		});
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
		const { agent, transaction } = await beginLogin(app);

		const res = await verify(agent, transaction, record.id, "look-up");

		expect(res.status).toBe(403);
		expect(create).not.toHaveBeenCalled();
	});

	it("completes the login of a subject who holds a counting factor it can use", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const record = await seedFactor(factorStore, "rc", { secret: "look-up" });
		await seedTotp(factorStore);
		const { app } = await boot({
			config: configFor("required"),
			factorStore,
			extraModules: [contributing(notCounting())],
		});
		const { agent, transaction } = await beginLogin(app);

		expect((await verify(agent, transaction, record.id, "look-up")).status).toBe(200);
	});

	it("completes the login under optional, where nobody is required to hold one", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const record = await seedFactor(factorStore, "rc", { secret: "look-up" });
		const { app } = await boot({
			config: configFor("optional"),
			factorStore,
			extraModules: [contributing(notCounting())],
		});
		const { agent, transaction } = await beginLogin(app);

		expect((await verify(agent, transaction, record.id, "look-up")).status).toBe(200);
	});
});
