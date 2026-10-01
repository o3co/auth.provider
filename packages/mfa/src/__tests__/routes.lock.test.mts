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
 * The subject lock's refusal at `POST /session/mfa/verify` (the MFA ADR's
 * D21, F1 step 5), through the composed application: `429 mfa_locked` with
 * the hold, `Retry-After` and the kinds that still work, `mfa.locked` for
 * every refusal and `mfa.locked.first` once an episode, and what a store
 * that cannot reserve or settle does to the answer.
 */

import { randomBytes } from "node:crypto";
import {
	createMemoryMfaFactorStore,
	createMemoryMfaTransactionStore,
	HARDWARE_KEY_AMR,
	type MfaFactor,
	type MfaFactorStore,
	type MfaTransactionStore,
	type Module,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createRecoveryCodeFactor, generateRecoveryCodes } from "#/recovery/factor.mjs";
import { createMfaSealing } from "#/sealing.mjs";
import { BOB, boot, configFor, disposeAll, events } from "./moduleHarness.mjs";
import {
	beginLogin,
	contributing,
	freezeClock,
	newFactorId,
	recordingAuditSink,
	seedFactor,
	seedTotp,
	suiteSealing,
	T0,
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

/** An exempt factor another package might contribute, as WebAuthn's is: it counts, and its proof is not guessed. */
const keyFactor: MfaFactor = {
	kind: "key",
	amrValues: [HARDWARE_KEY_AMR],
	amrFor: () => [HARDWARE_KEY_AMR],
	addsMfa: true,
	counting: true,
	guessable: false,
	describe: () => ({}),
	verify: async ({ factor }) => ({ ok: true, factorId: factor.id }),
	beginEnrollment: async () => {
		throw new Error("not enrolled here");
	},
	completeEnrollment: async () => {
		throw new Error("not enrolled here");
	},
};

/** A recovery-code set of `count` codes as the suite's ring digests them. */
const recoverySet = (count = 3) => {
	const set = generateRecoveryCodes(
		createRecoveryCodeFactor({ count }),
		suiteSealing().digestsFor("recovery_code"),
	);
	if (set === undefined) throw new Error("no set");
	return set;
};

/** Boots `required` with `lockout`, alice's TOTP factor seeded, and an audit sink. */
async function held(
	lockout: Record<string, number>,
	options: {
		readonly factorStore?: MfaFactorStore;
		readonly transactionStore?: MfaTransactionStore;
		readonly extraModules?: readonly Module[];
	} = {},
) {
	const factorStore = options.factorStore ?? createMemoryMfaFactorStore();
	const totp = await seedTotp(factorStore);
	const audit = recordingAuditSink();
	const booted = await boot({
		config: configFor("required", { lockout }),
		factorStore,
		auditSink: audit,
		...(options.transactionStore === undefined
			? {}
			: { transactionStore: options.transactionStore }),
		...(options.extraModules === undefined ? {} : { extraModules: options.extraModules }),
	});
	return { ...booted, factorStore, totp, audit };
}

describe("a held subject's guessable proof", () => {
	it("is 429 mfa_locked, with the hold, Retry-After in whole seconds rounded up, the exempt kinds the subject holds in code-unit order, and the attempts left", async () => {
		const factorStore = createMemoryMfaFactorStore();
		await seedFactor(factorStore, "recovery_code", recoverySet().data);
		await seedFactor(factorStore, "key", {});
		const { app, totp } = await held(
			{ threshold: 2 },
			{ factorStore, extraModules: [contributing(keyFactor)] },
		);
		const { agent, transaction } = await beginLogin(app);
		for (let n = 0; n < 2; n++) {
			expect(
				(await verify(agent, transaction, totp.record.id, wrongCode(totp.secret))).status,
			).toBe(401);
		}
		vi.setSystemTime(T0 + 500);

		const res = await verify(agent, transaction, totp.record.id, totpCode(totp.secret));

		expect(res.status, JSON.stringify(res.body)).toBe(429);
		expect(res.headers["retry-after"]).toBe("900");
		expect(res.headers["cache-control"]).toBe("no-store");
		expect(res.body).toEqual({
			error: "mfa_locked",
			error_description: "Too many failed attempts: try again later, or use another second factor",
			hold: "backoff",
			usable_kinds: ["key", "recovery_code"],
			attempts_remaining: 2,
		});
	});

	it("carries no Retry-After for the hard hold, which no time lifts, and offers no later try", async () => {
		const { app, totp } = await held({ threshold: 2, hardLimit: 2 });
		const { agent, transaction } = await beginLogin(app);
		for (let n = 0; n < 2; n++) {
			await verify(agent, transaction, totp.record.id, wrongCode(totp.secret));
		}

		const res = await verify(agent, transaction, totp.record.id, totpCode(totp.secret));

		expect(res.status).toBe(429);
		expect(res.headers["retry-after"]).toBeUndefined();
		expect(res.body).toEqual({
			error: "mfa_locked",
			error_description: "Too many failed attempts: use another second factor",
			hold: "hard",
			usable_kinds: [],
			attempts_remaining: 2,
		});
	});

	/** The 429 a subject holding alice's TOTP factor and `seed`'s records is answered once held. */
	async function heldWith(seed: (factorStore: MfaFactorStore) => Promise<unknown>) {
		const factorStore = createMemoryMfaFactorStore();
		await seed(factorStore);
		const { app, totp } = await held(
			{ threshold: 1 },
			{ factorStore, extraModules: [contributing(keyFactor)] },
		);
		const { agent, transaction } = await beginLogin(app);
		await verify(agent, transaction, totp.record.id, wrongCode(totp.secret));
		const res = await verify(agent, transaction, totp.record.id, totpCode(totp.secret));
		expect(res.status).toBe(429);
		return res;
	}

	it("lists a recovery set with no code left, because the subject holds it", async () => {
		const res = await heldWith((factorStore) =>
			seedFactor(factorStore, "recovery_code", { codes: [] }),
		);

		expect(res.body.usable_kinds).toEqual(["recovery_code"]);
	});

	it("lists a recovery set whose key left the ring, because the subject holds it", async () => {
		const gone = createMfaSealing({ ring: [{ id: "k-gone", key: randomBytes(32) }] });
		const set = generateRecoveryCodes(
			createRecoveryCodeFactor({ count: 3 }),
			gone.digestsFor("recovery_code"),
		);
		const res = await heldWith((factorStore) =>
			seedFactor(factorStore, "recovery_code", set?.data ?? {}),
		);

		expect(res.body.usable_kinds).toEqual(["recovery_code"]);
	});

	it("lists an exempt kind whose data does not open, because the subject holds it", async () => {
		const res = await heldWith(async (factorStore) => {
			// Sealed to another subject's record: it does not open as alice's.
			const id = newFactorId();
			await factorStore.create({
				id,
				subject: "u-alice",
				kind: "key",
				label: undefined,
				binding: "password",
				createdAt: new Date(T0 - 86_400_000),
				lastUsedAt: undefined,
				version: 0,
				data: suiteSealing().sealFactorData({ subject: BOB.id, id, kind: "key" }, {}),
			});
		});

		expect(res.body.usable_kinds).toEqual(["key"]);
	});

	it("lists no guessable kind, and each exempt kind once however many records hold it", async () => {
		const res = await heldWith(async (factorStore) => {
			await seedFactor(factorStore, "key", {});
			await seedFactor(factorStore, "key", {});
			await seedTotp(factorStore);
		});

		expect(res.body.usable_kinds).toEqual(["key"]);
	});

	it("writes no session, spends one of the transaction's attempts, and leaves the factor as it was", async () => {
		const { app, totp, userSessionStore, transactionStore, factorStore } = await held({
			threshold: 1,
		});
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
		const { agent, transaction } = await beginLogin(app);
		await verify(agent, transaction, totp.record.id, wrongCode(totp.secret));

		const res = await verify(agent, transaction, totp.record.id, totpCode(totp.secret));

		expect(res.status).toBe(429);
		expect(create).not.toHaveBeenCalled();
		expect((await transactionStore.get(transaction))?.attempts).toBe(2);
		expect((await factorStore.list("u-alice"))[0]?.version).toBe(0);
	});
});

describe("the audit of a refusal", () => {
	it("records mfa.locked for every refusal, and mfa.locked.first once an episode with the hold and the factor's binding", async () => {
		const { app, totp, audit } = await held({ threshold: 1 });
		const { agent, transaction } = await beginLogin(app);
		await verify(agent, transaction, totp.record.id, wrongCode(totp.secret));

		await verify(agent, transaction, totp.record.id, totpCode(totp.secret));
		await verify(agent, transaction, totp.record.id, totpCode(totp.secret));

		expect(audit.of("mfa.locked").map((event) => event.details)).toEqual([
			{ kind: "totp", purpose: "login", hold: "backoff" },
			{ kind: "totp", purpose: "login", hold: "backoff" },
		]);
		const first = audit.of("mfa.locked.first");
		expect(first).toHaveLength(1);
		expect(first[0]).toMatchObject({
			subject: "u-alice",
			details: { kind: "totp", purpose: "login", hold: "backoff", binding: "password" },
		});
	});

	it("records mfa.locked.first again for the next episode, once an attempt was let through", async () => {
		const { app, totp, audit } = await held({ threshold: 1, weeklyBudget: 100 });
		const first = await beginLogin(app);
		await verify(first.agent, first.transaction, totp.record.id, wrongCode(totp.secret));
		await verify(first.agent, first.transaction, totp.record.id, totpCode(totp.secret));

		vi.setSystemTime(T0 + 900_000);
		const next = await beginLogin(app);
		await verify(next.agent, next.transaction, totp.record.id, wrongCode(totp.secret));
		await verify(next.agent, next.transaction, totp.record.id, totpCode(totp.secret));

		expect(audit.of("mfa.locked")).toHaveLength(2);
		expect(audit.of("mfa.locked.first")).toHaveLength(2);
	});
});

describe("what reserves no subject attempt", () => {
	/** Boots `required` over a transaction store whose `reserveSubjectAttempt` is watched. */
	async function watched(
		options: { readonly factorStore?: MfaFactorStore; readonly maxAttempts?: number } = {},
	) {
		const store = createMemoryMfaTransactionStore();
		const reserveSubjectAttempt = vi.fn(store.reserveSubjectAttempt);
		const factorStore = options.factorStore ?? createMemoryMfaFactorStore();
		const booted = await boot({
			config: configFor("required", { maxAttemptsPerTransaction: options.maxAttempts ?? 5 }),
			factorStore,
			transactionStore: { ...store, reserveSubjectAttempt },
		});
		return { ...booted, reserveSubjectAttempt };
	}

	it("an exhausted transaction: 401 exhausted, the subject's attempts untouched", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const totp = await seedTotp(factorStore);
		const { app, reserveSubjectAttempt } = await watched({ factorStore, maxAttempts: 2 });
		const { agent, transaction } = await beginLogin(app);
		for (let n = 0; n < 2; n++) {
			await verify(agent, transaction, totp.record.id, wrongCode(totp.secret));
		}
		reserveSubjectAttempt.mockClear();

		const res = await verify(agent, transaction, totp.record.id, totpCode(totp.secret));

		expect(res.status).toBe(401);
		expect(res.body.attempts_remaining).toBe(0);
		expect(reserveSubjectAttempt).not.toHaveBeenCalled();
	});

	it("a factor store that cannot list the subject's factors: 503, the subject's attempts untouched", async () => {
		const memory = createMemoryMfaFactorStore();
		const totp = await seedTotp(memory);
		let down = false;
		const factorStore: MfaFactorStore = {
			...memory,
			list: async (subject) => {
				if (down) throw new Error("factor store unreachable");
				return memory.list(subject);
			},
		};
		const { app, reserveSubjectAttempt } = await watched({ factorStore });
		const { agent, transaction } = await beginLogin(app);
		down = true;

		const res = await verify(agent, transaction, totp.record.id, totpCode(totp.secret));

		expect(res.status).toBe(503);
		expect(reserveSubjectAttempt).not.toHaveBeenCalled();
	});

	it("a factor whose data does not open: 503, the subject's attempts untouched", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const totp = await seedTotp(factorStore, "u-alice", { sealedFor: BOB.id });
		const { app, reserveSubjectAttempt } = await watched({ factorStore });
		const { agent, transaction } = await beginLogin(app);

		const res = await verify(agent, transaction, totp.record.id, totpCode(totp.secret));

		expect(res.status).toBe(503);
		expect(reserveSubjectAttempt).not.toHaveBeenCalled();
	});
});

describe("the subject lock's store", () => {
	it("answers 503 when it cannot reserve, logged once, and never checks the proof", async () => {
		const store = createMemoryMfaTransactionStore();
		const checked = vi.fn(async ({ factor }: { factor: { id: string } }) => ({
			ok: true as const,
			factorId: factor.id,
		}));
		const probe: MfaFactor = { ...keyFactor, kind: "probe", guessable: true, verify: checked };
		const factorStore = createMemoryMfaFactorStore();
		const record = await seedFactor(factorStore, "probe", {});
		const { app, logger, audit } = await held(
			{},
			{
				factorStore,
				extraModules: [contributing(probe)],
				transactionStore: {
					...store,
					reserveSubjectAttempt: async () => {
						throw new Error("store unreachable");
					},
				},
			},
		);
		const { agent, transaction } = await beginLogin(app);

		const res = await verify(agent, transaction, record.id, "123456");

		expect(res.status).toBe(503);
		expect(checked).not.toHaveBeenCalled();
		expect((await factorStore.list("u-alice")).find((r) => r.id === record.id)?.version).toBe(0);
		expect(events(logger, "error")).toEqual(["mfa_store_unavailable"]);
		expect(logger.error.mock.calls[0]?.[0]).toMatchObject({
			route: "verify",
			store: "mfa_transaction",
			step: "reserveSubjectAttempt",
		});
		expect(audit.of("mfa.verified")).toEqual([]);
	});

	it("leaves the answer standing when a settle fails: one warning, mfa_subject_lock_unsettled", async () => {
		const store = createMemoryMfaTransactionStore();
		const { app, totp, logger } = await held(
			{},
			{
				transactionStore: {
					...store,
					settleSubjectAttempt: async () => {
						throw new Error("store unreachable");
					},
				},
			},
		);
		const { agent, transaction } = await beginLogin(app);

		const res = await verify(agent, transaction, totp.record.id, totpCode(totp.secret));

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		const unsettled = logger.warn.mock.calls.filter(
			(call) => call[1] === "mfa_subject_lock_unsettled",
		);
		expect(unsettled).toHaveLength(1);
		expect(unsettled[0]?.[0]).toMatchObject({
			sub: "u-alice",
			kind: "totp",
			step: "settleSubjectAttempt",
			outcome: "success",
		});
	});
});
