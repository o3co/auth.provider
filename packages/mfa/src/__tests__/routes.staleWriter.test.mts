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
 * Writers past their lease, through the composed application: what the
 * factor store's fence under the lease refuses. A lease the store let go, or
 * never held, lets a second writer run beside the first; every write of the
 * subject's factor set is conditional on the set as the writer read it under
 * its lease, so the one that lands second finds the set changed and writes
 * nothing. The reset's own removal is unconditional, and its reverse race
 * stays: a stalled reset still removes what was bound after it.
 */

import {
	createMemoryMfaFactorStore,
	createMemoryMfaTransactionStore,
	type MfaFactorRecord,
	type MfaFactorStore,
	type MfaTransactionStore,
	type SubjectRevocationReport,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createMfaSubjectLeases } from "#/factorSet.mjs";
import { RECOVERY_CODE_FACTOR_KIND } from "#/recovery/factor.mjs";
import { createMfaReset } from "#/reset.mjs";
import { ALICE, boot, configFor, disposeAll, events } from "./moduleHarness.mjs";
import {
	addRecord,
	beginEnrollment,
	beginFirstBinding,
	completeEnrollment,
	enrollFromAccount,
	freezeClock,
	mfaPost,
	newFactorId,
	recordingAuditSink,
	seedTotp,
	signInWithTotp,
	T0,
	thawClock,
	totpProofOf,
} from "./routesHarness.mjs";

beforeEach(() => freezeClock());
afterEach(async () => {
	await disposeAll();
	thawClock();
	vi.restoreAllMocks();
});

/** A revocation that ended every session of the subject's. */
const COMPLETE: SubjectRevocationReport = {
	sessionsRevoked: [],
	sessionsFailed: [],
	tokensRevoked: true,
	grantsRequested: false,
	grantsRevoked: [],
	grantsFailed: [],
	grantsRetired: [],
	grantsRetireFailed: [],
	unavailable: [],
	failures: [],
	complete: true,
	federationGrants: { requested: "revoke", applied: "revoke" },
};

/** A call held until `open()`: `reached` resolves when the first one arrives. */
function gate() {
	let arrive: () => void = () => {};
	const reached = new Promise<void>((resolve) => {
		arrive = resolve;
	});
	let open: () => void = () => {};
	const opened = new Promise<void>((resolve) => {
		open = resolve;
	});
	return {
		reached,
		open,
		async pass(): Promise<void> {
			arrive();
			await opened;
		},
	};
}

/** `store`'s `createIf` held at `held` once, for the first record `which` picks. */
function holdingAdd(
	store: MfaFactorStore,
	which: (record: MfaFactorRecord) => boolean,
	held: ReturnType<typeof gate>,
): void {
	let armed = true;
	const createIf = store.createIf.bind(store);
	vi.spyOn(store, "createIf").mockImplementation(async (record, expected) => {
		if (armed && which(record)) {
			armed = false;
			await held.pass();
		}
		return createIf(record, expected);
	});
}

/** Each acquire of the subject's lease on `store`, the tokens it gave. */
function leaseTokens(store: MfaTransactionStore): string[] {
	const tokens: string[] = [];
	const acquire = store.acquireSubjectLease.bind(store);
	vi.spyOn(store, "acquireSubjectLease").mockImplementation(async (...args) => {
		const answer = await acquire(...args);
		if (answer.outcome === "acquired") tokens.push(answer.token);
		return answer;
	});
	return tokens;
}

/**
 * Lets every acquire of the subject's lease on `store` through, and finds
 * none held at its release, as a store that dropped a lease early would:
 * two writers then run beside each other.
 */
function leaseAdmittingEveryWriter(store: MfaTransactionStore): void {
	let tokens = 0;
	vi.spyOn(store, "acquireSubjectLease").mockImplementation(async () => ({
		outcome: "acquired",
		token: `admitted-${++tokens}`,
	}));
	vi.spyOn(store, "releaseSubjectLease").mockResolvedValue(false);
}

/** Holds each first-binding mark `store` is asked to note until `n` are. */
function notingTogether(store: MfaTransactionStore, n: number): void {
	let arrived = 0;
	let release: () => void = () => {};
	const all = new Promise<void>((resolve) => {
		release = resolve;
	});
	const note = store.noteFirstBinding.bind(store);
	vi.spyOn(store, "noteFirstBinding").mockImplementation(async (...args) => {
		arrived += 1;
		if (arrived >= n) release();
		await all;
		return note(...args);
	});
}

/** An operator reset over `stores`, with a revocation that ends every session. */
const resetOver = (stores: {
	readonly factorStore: MfaFactorStore;
	readonly transactionStore: MfaTransactionStore;
}) =>
	createMfaReset({
		factorStore: stores.factorStore,
		transactionStore: stores.transactionStore,
		subjectRevocationService: { revokeAllForSubject: async () => COMPLETE },
		mailWired: false,
		leases: createMfaSubjectLeases({ store: stores.transactionStore, storeTimeoutMs: 1_000 }),
	});

/** Alice's records of `kind` as `store` holds them. */
const ofKind = async (store: MfaFactorStore, kind: string) =>
	(await store.list(ALICE.id)).filter((record) => record.kind === kind);

describe("a first binding whose factor's write stalls past its lease while a reset runs", () => {
	it("writes nothing after the reset: the reset reads complete and stays so, and the binding is refused, 401 login_required", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const transactionStore = createMemoryMfaTransactionStore();
		const stalled = gate();
		holdingAdd(factorStore, (record) => record.kind === "totp", stalled);
		const tokens = leaseTokens(transactionStore);
		const { app } = await boot({ config: configFor("required"), factorStore, transactionStore });
		const { agent, transaction } = await beginFirstBinding(app);
		const begun = await beginEnrollment(agent, transaction, "totp");

		const binding = completeEnrollment(agent, transaction, totpProofOf(begun.body.secret));
		await stalled.reached;
		// The binding's lease ends while its factor's write is on its way.
		const held = tokens.at(-1);
		if (held === undefined) throw new Error("the binding held no lease");
		expect(await transactionStore.releaseSubjectLease(ALICE.id, held)).toBe(true);
		const report = await resetOver({ factorStore, transactionStore }).resetMfaForSubject(ALICE.id);
		expect(report.complete).toBe(true);
		stalled.open();
		const res = await binding;

		expect(res.status, JSON.stringify(res.body)).toBe(401);
		expect(res.body).toEqual({ error: "login_required", error_description: "Log in again" });
		expect(await factorStore.list(ALICE.id)).toEqual([]);
	});
});

describe("a reset whose removal stalls past its lease while a first binding runs (the reverse race)", () => {
	it("still removes the factor bound after it — the reset always wins — and says it overran, so the operator runs it again and the user binds again", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const transactionStore = createMemoryMfaTransactionStore();
		const tokens = leaseTokens(transactionStore);
		const stalled = gate();
		const removeAll = factorStore.removeAllForSubject.bind(factorStore);
		vi.spyOn(factorStore, "removeAllForSubject").mockImplementation(async (subject) => {
			await stalled.pass();
			return removeAll(subject);
		});
		const { app } = await boot({ config: configFor("required"), factorStore, transactionStore });

		const reset = resetOver({ factorStore, transactionStore }).resetMfaForSubject(ALICE.id);
		await stalled.reached;
		// The reset's lease ends while its removal is on its way; a login binds a first factor.
		const held = tokens.at(-1);
		if (held === undefined) throw new Error("the reset held no lease");
		expect(await transactionStore.releaseSubjectLease(ALICE.id, held)).toBe(true);
		const { agent, transaction } = await beginFirstBinding(app);
		const begun = await beginEnrollment(agent, transaction, "totp");
		const bound = await completeEnrollment(agent, transaction, totpProofOf(begun.body.secret));
		expect(bound.status, JSON.stringify(bound.body)).toBe(200);
		expect(await ofKind(factorStore, "totp")).toHaveLength(1);
		stalled.open();
		const report = await reset;

		// The residual: the binding made after the reset began is gone with it.
		expect(await factorStore.list(ALICE.id)).toEqual([]);
		expect(report.complete).toBe(false);
		expect(report).toMatchObject({ overran: true });
	});
});

describe("two first bindings of one subject past a lease the store does not hold", () => {
	it("lets exactly one bind: the other's factor is never written, 401 login_required, nothing removed, no mfa.first_binding_conflict", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const audit = recordingAuditSink();
		const { app, transactionStore } = await boot({
			config: configFor("required"),
			factorStore,
			auditSink: audit,
		});
		leaseAdmittingEveryWriter(transactionStore);
		// Both completions read the set under their lease, and pass their checks, before either writes.
		notingTogether(transactionStore, 2);
		const removeIf = vi.spyOn(factorStore, "removeIf");
		const owner = await beginFirstBinding(app);
		const other = await beginFirstBinding(app);
		const ownerBegun = await beginEnrollment(owner.agent, owner.transaction, "totp");
		const otherBegun = await beginEnrollment(other.agent, other.transaction, "totp");

		const answers = await Promise.all([
			completeEnrollment(owner.agent, owner.transaction, totpProofOf(ownerBegun.body.secret)),
			completeEnrollment(other.agent, other.transaction, totpProofOf(otherBegun.body.secret)),
		]);

		expect(answers.map((res) => res.status).sort()).toEqual([200, 401]);
		expect(answers.find((res) => res.status === 401)?.body.error).toBe("login_required");
		expect(await ofKind(factorStore, "totp")).toHaveLength(1);
		expect(await ofKind(factorStore, RECOVERY_CODE_FACTOR_KIND)).toHaveLength(1);
		expect(removeIf).not.toHaveBeenCalled();
		expect(audit.of("mfa.first_binding_conflict")).toEqual([]);
		expect(audit.of("mfa.factor.enrolled")).toHaveLength(1);
	});
});

describe("two removals of the last two counting factors past a lease the store does not hold", () => {
	it("lets one through: the other finds the set changed and removes nothing, so a counting factor stands — each answered 409 mfa_factors_changed, as a write past its lease is", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const first = await seedTotp(factorStore);
		const second = await seedTotp(factorStore);
		const audit = recordingAuditSink();
		const booted = await boot({ config: configFor("required"), factorStore, auditSink: audit });
		const { agent } = await signInWithTotp(
			booted.app,
			booted.userSessionStore as UserSessionStore,
			first,
		);
		leaseAdmittingEveryWriter(booted.transactionStore);
		// Both removals read the set, and each finds the other factor standing, before either writes.
		let arrived = 0;
		let release: () => void = () => {};
		const both = new Promise<void>((resolve) => {
			release = resolve;
		});
		const removeIf = factorStore.removeIf.bind(factorStore);
		vi.spyOn(factorStore, "removeIf").mockImplementation(async (...args) => {
			arrived += 1;
			if (arrived === 2) release();
			await both;
			return removeIf(...args);
		});

		const answers = await Promise.all([
			mfaPost(agent, "/factors/remove", { factor_id: first.record.id }),
			mfaPost(agent, "/factors/remove", { factor_id: second.record.id }),
		]);

		expect(answers.map((res) => [res.status, res.body.error])).toEqual([
			[409, "mfa_factors_changed"],
			[409, "mfa_factors_changed"],
		]);
		expect(await ofKind(factorStore, "totp")).toHaveLength(1);
		expect(audit.of("mfa.factor.removed")).toHaveLength(1);
	});
});

describe("a removal racing a binding past a lease the store does not hold", () => {
	it("removes nothing when a factor was bound between its read and its write: 409 mfa_factors_changed, every factor standing", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const kept = await seedTotp(factorStore);
		const removed = await seedTotp(factorStore);
		const booted = await boot({ config: configFor("required"), factorStore });
		const { agent } = await signInWithTotp(
			booted.app,
			booted.userSessionStore as UserSessionStore,
			kept,
		);
		const begun = await enrollFromAccount(agent, "totp");
		expect(begun.status, JSON.stringify(begun.body)).toBe(200);
		leaseAdmittingEveryWriter(booted.transactionStore);
		const stalled = gate();
		let armed = true;
		const removeIf = factorStore.removeIf.bind(factorStore);
		vi.spyOn(factorStore, "removeIf").mockImplementation(async (...args) => {
			if (armed) {
				armed = false;
				await stalled.pass();
			}
			return removeIf(...args);
		});

		const removal = mfaPost(agent, "/factors/remove", { factor_id: removed.record.id });
		await stalled.reached;
		const bound = await completeEnrollment(
			agent,
			begun.body.transaction as string,
			totpProofOf(begun.body.secret),
		);
		expect(bound.status, JSON.stringify(bound.body)).toBe(200);
		stalled.open();
		const res = await removal;

		expect(res.status, JSON.stringify(res.body)).toBe(409);
		expect(res.body.error).toBe("mfa_factors_changed");
		const ids = (await ofKind(factorStore, "totp")).map((record) => record.id);
		expect(ids).toHaveLength(3);
		expect(ids).toContain(removed.record.id);
	});
});

describe("a first binding's recovery codes when another counting factor lands before them", () => {
	it("writes no codes past mfa.maxFactorsPerSubject: the factor binds, its codes not issued, the subject at the limit, said at warn as a conflict", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const stalled = gate();
		holdingAdd(factorStore, (record) => record.kind === RECOVERY_CODE_FACTOR_KIND, stalled);
		const { app, logger } = await boot({
			config: configFor("required", { maxFactorsPerSubject: 2 }),
			factorStore,
		});
		const { agent, transaction } = await beginFirstBinding(app);
		const begun = await beginEnrollment(agent, transaction, "totp");

		const binding = completeEnrollment(agent, transaction, totpProofOf(begun.body.secret));
		await stalled.reached;
		// A binding past its lease, that read this one's factor, adds a counting factor beside it.
		await addRecord(factorStore, {
			id: newFactorId(),
			subject: ALICE.id,
			kind: "totp",
			label: undefined,
			binding: "mfa",
			createdAt: new Date(T0),
			lastUsedAt: undefined,
			version: 0,
			data: "sealed",
		});
		stalled.open();
		const res = await binding;

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(res.body).not.toHaveProperty("recovery_codes");
		expect(res.body.recovery_codes_issued).toBe(false);
		expect(await factorStore.list(ALICE.id)).toHaveLength(2);
		expect(await ofKind(factorStore, RECOVERY_CODE_FACTOR_KIND)).toEqual([]);
		// The set lost to another writer: a conflict, not an outage.
		expect(events(logger, "warn")).toContain("mfa_recovery_codes_conflict");
		expect(events(logger, "error")).not.toContain("mfa_recovery_codes_unwritten");
	});
});
