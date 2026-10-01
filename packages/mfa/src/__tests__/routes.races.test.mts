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
 * Verifications that race, through the composed application: attempts are
 * reserved before a proof is checked, the transaction is consumed before the
 * factor moves on, and a factor whose compare-and-set was lost is read and
 * checked again. See ADR 2026-09-25-multi-factor-authentication, F1 step 5,
 * F6 and D8.
 */

import {
	createMemoryMfaFactorStore,
	createMemoryMfaTransactionStore,
	type MfaFactorStore,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { boot, configFor, disposeAll } from "./moduleHarness.mjs";
import {
	beginLogin,
	freezeClock,
	recordingAuditSink,
	STEP0,
	seedTotp,
	storedData,
	suiteSealing,
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

describe("N verifications at once", () => {
	it("spends N attempts on N wrong codes sent at once", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record, secret } = await seedTotp(factorStore);
		const { app, transactionStore } = await boot({
			// The subject lock is set past this suite's codes: the transaction's limit is what it counts.
			config: configFor("required", {
				maxAttemptsPerTransaction: 10,
				lockout: { threshold: 99, weeklyBudget: 100 },
			}),
			factorStore,
		});
		const { agent, transaction } = await beginLogin(app);

		const answers = await Promise.all(
			Array.from({ length: 7 }, () => verify(agent, transaction, record.id, wrongCode(secret))),
		);

		expect(answers.map((res) => res.status)).toEqual(Array(7).fill(401));
		expect(answers.map((res) => res.body.attempts_remaining).sort()).toEqual([3, 4, 5, 6, 7, 8, 9]);
		expect((await transactionStore.get(transaction))?.attempts).toBe(7);
	});

	it("checks no more than the transaction allows when more wrong codes than that are sent at once, and ends it", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record, secret } = await seedTotp(factorStore);
		const audit = recordingAuditSink();
		const { app, transactionStore } = await boot({
			config: configFor("required", { maxAttemptsPerTransaction: 3 }),
			factorStore,
			auditSink: audit,
		});
		const { agent, transaction } = await beginLogin(app);

		const answers = await Promise.all(
			Array.from({ length: 6 }, () => verify(agent, transaction, record.id, wrongCode(secret))),
		);

		// Three are checked and refused; each of the rest finds the attempts spent
		// (401, exhausted), or the transaction the first of those ended gone (400).
		const reasons = audit.of("mfa.verify.failure").map((event) => event.details?.reason);
		expect(reasons.filter((reason) => reason === "invalid")).toHaveLength(3);
		const exhausted = reasons.filter((reason) => reason === "exhausted").length;
		const gone = answers.filter((res) => res.status === 400);
		expect(answers.filter((res) => res.status === 401)).toHaveLength(3 + exhausted);
		expect(exhausted + gone.length).toBe(3);
		expect(gone.every((res) => res.body.error === "invalid_request")).toBe(true);
		expect(await transactionStore.get(transaction)).toBeNull();
	});

	it("establishes one session from N right codes sent at once: one verification consumes the transaction, the rest find it spent", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record, secret } = await seedTotp(factorStore);
		const { app, userSessionStore } = await boot({ config: configFor("required"), factorStore });
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
		const { agent, transaction } = await beginLogin(app);

		const answers = await Promise.all(
			Array.from({ length: 5 }, () => verify(agent, transaction, record.id, totpCode(secret))),
		);

		expect(answers.map((res) => res.status).sort()).toEqual([200, 400, 400, 400, 400]);
		expect(create).toHaveBeenCalledTimes(1);
		expect((await storedData(factorStore, record)).record.version).toBe(1);
	});

	it("establishes one session from the same code in two logins at once", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record, secret } = await seedTotp(factorStore);
		const { app, userSessionStore } = await boot({ config: configFor("required"), factorStore });
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
		const first = await beginLogin(app);
		const second = await beginLogin(app);
		const code = totpCode(secret);

		const answers = await Promise.all([
			verify(first.agent, first.transaction, record.id, code),
			verify(second.agent, second.transaction, record.id, code),
		]);

		expect(answers.map((res) => res.status).sort()).toEqual([200, 401]);
		expect(create).toHaveBeenCalledTimes(1);
		expect((await storedData(factorStore, record)).data.lastUsedStep).toBe(STEP0);
	});
});

describe("consume before advance", () => {
	it("consumes the transaction before it writes the factor", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record, secret } = await seedTotp(factorStore);
		const transactionStore = createMemoryMfaTransactionStore();
		const order: string[] = [];
		const consume = transactionStore.consume;
		const update = factorStore.update;
		const { app } = await boot({
			config: configFor("required"),
			factorStore: {
				...factorStore,
				update: async (...args) => {
					order.push("advance");
					return update(...args);
				},
			},
			transactionStore: {
				...transactionStore,
				consume: async (...args) => {
					order.push("consume");
					return consume(...args);
				},
			},
		});
		const { agent, transaction } = await beginLogin(app);

		expect((await verify(agent, transaction, record.id, totpCode(secret))).status).toBe(200);

		expect(order).toEqual(["consume", "advance"]);
	});

	it("writes nothing to the factor when the verification loses the transaction: 400 invalid_request, no session, the step still unspent", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record, secret } = await seedTotp(factorStore);
		const transactionStore = createMemoryMfaTransactionStore();
		const update = vi.fn(factorStore.update);
		const { app, userSessionStore } = await boot({
			config: configFor("required"),
			factorStore: { ...factorStore, update },
			transactionStore: { ...transactionStore, consume: async () => null },
		});
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
		const { agent, transaction } = await beginLogin(app);

		const res = await verify(agent, transaction, record.id, totpCode(secret));

		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_request");
		expect(update).not.toHaveBeenCalled();
		expect(create).not.toHaveBeenCalled();
		expect((await storedData(factorStore, record)).data.lastUsedStep).toBe(0);
	});
});

/**
 * A factor store whose first `update` loses its compare-and-set: another
 * write lands `concurrent`'s data on the record first, as a concurrent use
 * or a rename would.
 */
function losingFirstUpdate(
	store: MfaFactorStore,
	concurrent: (data: Record<string, unknown>) => Record<string, unknown>,
): { readonly store: MfaFactorStore; readonly calls: () => number } {
	let calls = 0;
	return {
		calls: () => calls,
		store: {
			...store,
			update: async (subject, id, expectedVersion, next) => {
				calls++;
				if (calls === 1) {
					const current = (await store.list(subject)).find((entry) => entry.id === id);
					if (current === undefined) throw new Error("no such factor");
					const binding = { subject, id, kind: current.kind };
					const opened = suiteSealing().openFactorData(binding, current.data);
					if (opened.state !== "ok") throw new Error("the factor does not open");
					await store.update(subject, id, current.version, {
						data: suiteSealing().sealFactorData(binding, concurrent(opened.value)),
						label: "renamed",
						lastUsedAt: current.lastUsedAt,
					});
				}
				return store.update(subject, id, expectedVersion, next);
			},
		},
	};
}

describe("a factor whose compare-and-set was lost", () => {
	it("is read and checked again: after a write that spent nothing, the code still counts and the login completes", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record, secret } = await seedTotp(factorStore);
		const losing = losingFirstUpdate(factorStore, (data) => data);
		const { app } = await boot({ config: configFor("required"), factorStore: losing.store });
		const { agent, transaction } = await beginLogin(app);

		const res = await verify(agent, transaction, record.id, totpCode(secret));

		expect(res.status).toBe(200);
		expect(losing.calls()).toBe(2);
		const after = await storedData(factorStore, record);
		expect(after.data.lastUsedStep).toBe(STEP0);
		// The concurrent write stands beside this one.
		expect(after.record.label).toBe("renamed");
		expect(after.record.version).toBe(2);
	});

	it("is read and checked again: after a write that spent the code's step, the code is refused as replayed, and no session is written", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record, secret } = await seedTotp(factorStore);
		const losing = losingFirstUpdate(factorStore, (data) => ({ ...data, lastUsedStep: STEP0 }));
		const audit = recordingAuditSink();
		const { app, userSessionStore } = await boot({
			config: configFor("required"),
			factorStore: losing.store,
			auditSink: audit,
		});
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
		const { agent, transaction } = await beginLogin(app);

		const res = await verify(agent, transaction, record.id, totpCode(secret));

		expect(res.status).toBe(401);
		expect(res.body.error).toBe("mfa_invalid");
		expect(create).not.toHaveBeenCalled();
		expect(audit.of("mfa.verify.failure").map((event) => event.details?.reason)).toEqual([
			"replayed",
		]);
		expect(audit.of("mfa.verified")).toEqual([]);
	});
});
