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
 * The account page's regeneration of the signed-in subject's recovery codes,
 * `POST /session/mfa/recovery-codes`, admitted as `mfa.manage`: a new set
 * answered once, every set that stood retired by the subject's recovery-set
 * floor and removed, run whole under the subject's lease; the set marked
 * shown just before its codes are answered.
 */

import { randomBytes } from "node:crypto";
import {
	type AppConfig,
	createMemoryMfaFactorStore,
	createMemoryMfaTransactionStore,
	type MfaFactorRecord,
	type MfaFactorStore,
	type MfaTransactionStore,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { createRecordingMailSender } from "@o3co/auth-provider-core/testing";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FACTOR_SET_STORE_CALLS } from "#/factorSet.mjs";
import { createRecoveryCodeFactor, generateRecoveryCodes } from "#/recovery/factor.mjs";
import { createMfaSealing } from "#/sealing.mjs";
import { mfaRecoveryCodeFactorConfigForTests } from "#/testing/index.mjs";
import {
	ALICE,
	BOB,
	boot,
	configFor,
	directoryEntries,
	disposeAll,
	events,
	spyLogger,
	WitnessingUserRepository,
} from "./moduleHarness.mjs";
import {
	beginLogin,
	freezeClock,
	loggedText,
	mfaPost,
	newFactorId,
	recordingAuditSink,
	recoverySet,
	STEP_UP_REQUIRED,
	seedFactor,
	seedTotp,
	signInWithTotp,
	storedData,
	suiteSealing,
	T0,
	thawClock,
	verify,
} from "./routesHarness.mjs";

beforeEach(() => freezeClock());
afterEach(async () => {
	await disposeAll();
	thawClock();
	vi.restoreAllMocks();
});

const SHOWN = /^[0-9A-HJKMNP-TV-Z]{4}(?:-[0-9A-HJKMNP-TV-Z]{4}){3}$/;
const UNAVAILABLE = {
	error: "temporarily_unavailable",
	error_description: "MFA temporarily unavailable",
};
const FACTORS_CHANGED = {
	error: "mfa_factors_changed",
	error_description: "The account's second factors changed: read them again",
};
const FACTORS_BUSY = {
	error: "mfa_factors_busy",
	error_description: "The account's second factors are being changed: try again",
};
const CONFLICT = {
	error: "mfa_recovery_codes_conflict",
	error_description:
		"The recovery codes were regenerated elsewhere at the same time: read them again",
};
const NO_COUNTING_FACTOR = {
	error: "mfa_enrollment_required",
	error_description:
		"Recovery codes are issued beside a second factor that counts: enroll one first",
};
const NOT_ISSUED = {
	error: "invalid_request",
	error_description: "Recovery codes are not issued here",
};

/** Boots `mode` with an audit sink and a recording sender; the factor store given, or a memory one. */
async function composed(
	options: {
		readonly mode?: "optional" | "required";
		readonly factorStore?: MfaFactorStore;
		readonly requireEmailProof?: "when-mail" | "always" | "never";
		readonly recoveryCodes?: boolean;
	} = {},
) {
	const factorStore = options.factorStore ?? createMemoryMfaFactorStore();
	const transactionStore: MfaTransactionStore = createMemoryMfaTransactionStore();
	const audit = recordingAuditSink();
	const logger = spyLogger();
	const users = new WitnessingUserRepository(directoryEntries());
	const booted = await boot({
		config: {
			...configFor(
				options.mode ?? "required",
				options.requireEmailProof === undefined
					? {}
					: { enrollment: { requireEmailProof: options.requireEmailProof } },
			),
			...(options.recoveryCodes === false
				? mfaRecoveryCodeFactorConfigForTests({ enabled: false })
				: {}),
		} as AppConfig,
		factorStore,
		transactionStore,
		auditSink: audit,
		userRepository: users,
		mailSender: createRecordingMailSender(),
		logger,
	});
	return {
		...booted,
		factorStore,
		transactionStore,
		userSessionStore: booted.userSessionStore as UserSessionStore,
		audit,
		logger,
	};
}

/** Alice holding TOTP and a set of three codes, signed in with her TOTP code now: recent MFA. */
async function signedIn(built: Awaited<ReturnType<typeof composed>>) {
	const totp = await seedTotp(built.factorStore);
	const old = recoverySet(3);
	const set = await seedFactor(built.factorStore, "recovery_code", old.data);
	const { agent } = await signInWithTotp(built.app, built.userSessionStore, totp);
	return { agent, totp, old: { record: set, codes: old.codes } };
}

const regenerate = (agent: ReturnType<typeof request.agent>) =>
	mfaPost(agent, "/recovery-codes", {});

/** Alice's recovery-code sets as stored: each with its data opened. */
async function setsOf(factorStore: MfaFactorStore, subject: string = ALICE.id) {
	const records = (await factorStore.list(subject)).filter(
		(record) => record.kind === "recovery_code",
	);
	return Promise.all(records.map((record) => storedData(factorStore, record)));
}

/** A login of alice through `set`'s record with `code`: the verification's answer. */
async function loginWithCode(
	built: Awaited<ReturnType<typeof composed>>,
	record: Pick<MfaFactorRecord, "id">,
	code: string | undefined,
) {
	const { agent, transaction } = await beginLogin(built.app);
	return verify(agent, transaction, record.id, code);
}

describe("POST /session/mfa/recovery-codes", () => {
	it("answers a new set of codes once, writes it shown at the next generation, raises the floor to it, removes the set that stood, and records mfa.recovery_codes.generated", async () => {
		const built = await composed();
		const { agent } = await signedIn(built);

		const res = await regenerate(agent);

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(res.headers["cache-control"]).toBe("no-store");
		expect(res.body).toEqual({ recovery_codes: expect.any(Array) });
		const codes = res.body.recovery_codes as string[];
		expect(codes).toHaveLength(10);
		for (const code of codes) expect(code).toMatch(SHOWN);
		const sets = await setsOf(built.factorStore);
		expect(sets).toHaveLength(1);
		expect(sets[0]?.record).toMatchObject({ binding: "mfa", createdAt: new Date(T0) });
		expect(sets[0]?.data).toMatchObject({ generation: 1, shown: true });
		expect(await built.transactionStore.recoverySetFloor(ALICE.id)).toBe(1);
		expect(built.audit.of("mfa.recovery_codes.generated")).toEqual([
			expect.objectContaining({
				subject: ALICE.id,
				details: { kind: "recovery_code", binding: "mfa", by: "user", regenerated: true },
			}),
		]);
		expect(loggedText(built.logger)).not.toContain(codes[0] as string);
		expect(JSON.stringify(built.audit.events)).not.toContain(codes[0] as string);
	});

	it("leaves only the new codes to sign in with: one verifies, and the old set's are gone", async () => {
		const built = await composed();
		const { agent, old } = await signedIn(built);
		const res = await regenerate(agent);
		const [fresh] = await setsOf(built.factorStore);
		if (fresh === undefined) throw new Error("no set");

		expect((await loginWithCode(built, old.record, old.codes[0])).status).toBe(400);
		const signed = await loginWithCode(built, fresh.record, res.body.recovery_codes[0]);
		expect(signed.status, JSON.stringify(signed.body)).toBe(200);
		expect(signed.body.recovery_codes_remaining).toBe(9);
	});

	it("retires every earlier set: a second regeneration's floor refuses the first's codes, even from a set left stored", async () => {
		const built = await composed();
		const { agent } = await signedIn(built);
		const first = await regenerate(agent);
		const [firstSet] = await setsOf(built.factorStore);
		if (firstSet === undefined) throw new Error("no set");
		vi.spyOn(built.factorStore, "remove").mockRejectedValueOnce(new Error("remove failed"));

		const second = await regenerate(agent);

		expect(second.status, JSON.stringify(second.body)).toBe(200);
		expect((await setsOf(built.factorStore)).map((set) => set.data.generation).sort()).toEqual([
			1, 2,
		]);
		const refused = await loginWithCode(built, firstSet.record, first.body.recovery_codes[0]);
		expect(refused.status, JSON.stringify(refused.body)).toBe(401);
		expect(refused.body).toMatchObject({ error: "mfa_invalid" });
		expect(built.audit.of("mfa.recovery_codes.generated").at(-1)?.details).toEqual({
			kind: "recovery_code",
			binding: "mfa",
			by: "user",
			regenerated: true,
			unreplaced: true,
		});
		expect(events(built.logger, "error")).toEqual(["mfa_recovery_codes_unreplaced"]);
	});

	it("removes every set that stood, those it cannot use included: one sealed for another subject, one whose digests' key the ring lost", async () => {
		const built = await composed();
		const { agent } = await signedIn(built);
		const copied: MfaFactorRecord = {
			id: newFactorId(),
			subject: ALICE.id,
			kind: "recovery_code",
			label: undefined,
			binding: "password",
			createdAt: new Date(T0 - 1_000),
			lastUsedAt: undefined,
			version: 0,
			data: suiteSealing().sealFactorData(
				{ subject: BOB.id, id: "elsewhere", kind: "recovery_code" },
				recoverySet(2).data,
			),
		};
		await built.factorStore.create(copied);
		const lost = generateRecoveryCodes(
			createRecoveryCodeFactor({ count: 2 }),
			createMfaSealing({ ring: [{ id: "k-gone", key: randomBytes(32) }] }).digestsFor(
				"recovery_code",
			),
			5,
		);
		if (lost === undefined) throw new Error("no set");
		await seedFactor(built.factorStore, "recovery_code", lost.data);

		const res = await regenerate(agent);

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		const sets = await setsOf(built.factorStore);
		expect(sets.map((set) => set.data.generation)).toEqual([6]);
	});

	it("refuses a session without recent MFA: 403 step_up_required, nothing written", async () => {
		const built = await composed();
		const { agent } = await signedIn(built);
		vi.setSystemTime(Date.now() + 301_000);
		const create = vi.spyOn(built.factorStore, "create");

		const res = await regenerate(agent);

		expect(res.status, JSON.stringify(res.body)).toBe(403);
		expect(res.body).toMatchObject(STEP_UP_REQUIRED);
		expect(create).not.toHaveBeenCalled();
	});

	it("refuses a POST without the CSRF token, reading nothing", async () => {
		const built = await composed();
		const { agent } = await signedIn(built);
		const listed = vi.spyOn(built.factorStore, "list");

		const res = await agent.post("/session/mfa/recovery-codes").send({});

		expect(res.status).toBe(403);
		expect(listed).not.toHaveBeenCalled();
	});

	it("refuses a signed-out browser: 401 login_required", async () => {
		const built = await composed();
		const res = await regenerate(request.agent(built.app));
		expect(res.status).toBe(401);
		expect(res.body).toMatchObject({ error: "login_required" });
	});

	it("refuses a subject with no record that may count, whom mfa.manage admits on a recent primary: 409 mfa_enrollment_required, nothing written", async () => {
		const built = await composed({ mode: "optional", requireEmailProof: "never" });
		const set = recoverySet(3);
		const record = await seedFactor(built.factorStore, "recovery_code", set.data);
		const { agent, transaction } = await beginLogin(built.app);
		expect((await verify(agent, transaction, record.id, set.codes[0])).status).toBe(200);
		const create = vi.spyOn(built.factorStore, "create");

		const res = await regenerate(agent);

		expect(res.status, JSON.stringify(res.body)).toBe(409);
		expect(res.body).toEqual(NO_COUNTING_FACTOR);
		expect(create).not.toHaveBeenCalled();
		expect(await built.transactionStore.recoverySetFloor(ALICE.id)).toBe(0);
	});

	it("answers 400 while the recovery-code factor is off, taking no lease", async () => {
		const built = await composed({ recoveryCodes: false });
		const totp = await seedTotp(built.factorStore);
		const { agent } = await signInWithTotp(built.app, built.userSessionStore, totp);
		const acquire = vi.spyOn(built.transactionStore, "acquireSubjectLease");

		const res = await regenerate(agent);

		expect(res.status, JSON.stringify(res.body)).toBe(400);
		expect(res.body).toEqual(NOT_ISSUED);
		expect(acquire).not.toHaveBeenCalled();
	});
});

describe("a regeneration's answer", () => {
	it("answers no codes when the set cannot be marked shown: 503, said once, the set left unshown and the list saying so", async () => {
		const built = await composed();
		const { agent } = await signedIn(built);
		vi.spyOn(built.factorStore, "update").mockRejectedValueOnce(new Error("update failed"));

		const res = await regenerate(agent);

		expect(res.status, JSON.stringify(res.body)).toBe(503);
		expect(res.body).toEqual(UNAVAILABLE);
		expect(events(built.logger, "error")).toEqual(["mfa_recovery_codes_unwritten"]);
		expect((await setsOf(built.factorStore)).map((set) => set.data.shown)).toEqual([false]);
		expect(built.audit.of("mfa.recovery_codes.generated")).toEqual([]);
		const listed = await agent.get("/session/mfa/factors");
		expect(
			(listed.body.factors as { kind: string; recovery_codes_shown?: boolean }[])
				.filter((factor) => factor.kind === "recovery_code")
				.map((factor) => factor.recovery_codes_shown),
		).toEqual([false]);
	});

	it("keeps the old codes when the floor cannot be raised: 503, its own set removed", async () => {
		const built = await composed();
		const { agent, old } = await signedIn(built);
		vi.spyOn(built.transactionStore, "raiseRecoverySetFloor").mockRejectedValueOnce(
			new Error("down"),
		);

		const res = await regenerate(agent);

		expect(res.status, JSON.stringify(res.body)).toBe(503);
		expect((await setsOf(built.factorStore)).map((set) => set.record.id)).toEqual([old.record.id]);
		expect((await loginWithCode(built, old.record, old.codes[0])).status).toBe(200);
	});

	it("loses to another set written at its generation first: 409 mfa_recovery_codes_conflict, its own set removed, no codes, said at warn", async () => {
		const memory = createMemoryMfaFactorStore();
		const built = await composed({ factorStore: memory });
		const { agent } = await signedIn(built);
		const create = memory.create.bind(memory);
		let other: MfaFactorRecord | undefined;
		vi.spyOn(memory, "create").mockImplementationOnce(async (record) => {
			await create(record);
			// A second writer the lease let in wrote a set of the same generation a moment earlier.
			const id = newFactorId();
			other = {
				...record,
				id,
				createdAt: new Date(T0 - 1),
				data: suiteSealing().sealFactorData(
					{ subject: ALICE.id, id, kind: "recovery_code" },
					{ ...recoverySet(2).data, generation: 1, shown: true },
				),
			};
			await create(other);
		});
		built.logger.warn.mockClear();

		const res = await regenerate(agent);

		expect(res.status, JSON.stringify(res.body)).toBe(409);
		expect(res.body).toEqual(CONFLICT);
		expect((await setsOf(built.factorStore)).map((set) => set.record.id)).toEqual([other?.id]);
		expect(events(built.logger, "warn")).toEqual(["mfa_recovery_codes_conflict"]);
		expect(built.audit.of("mfa.recovery_codes.generated")).toEqual([]);
	});

	it("answers 503 when the records cannot be listed under the lease, nothing written", async () => {
		const built = await composed();
		const { agent } = await signedIn(built);
		const list = built.factorStore.list.bind(built.factorStore);
		// Admission's read answers; the one under the lease does not.
		vi.spyOn(built.factorStore, "list")
			.mockImplementationOnce(list)
			.mockRejectedValueOnce(new Error("list failed"));
		const create = vi.spyOn(built.factorStore, "create");

		const res = await regenerate(agent);

		expect(res.status, JSON.stringify(res.body)).toBe(503);
		expect(create).not.toHaveBeenCalled();
		expect(events(built.logger, "error")).toEqual(["mfa_store_unavailable"]);
	});
});

describe("a regeneration under the subject's lease", () => {
	it("answers 409 mfa_factors_busy, with Retry-After, while another write holds the lease past the wait, writing nothing", async () => {
		const built = await composed();
		const { agent } = await signedIn(built);
		const store = built.transactionStore;
		const lease = await store.acquireSubjectLease(ALICE.id, {
			ttlMs: 60_000,
			generation: await store.subjectGeneration(ALICE.id),
		});
		expect(lease.outcome).toBe("acquired");
		const create = vi.spyOn(built.factorStore, "create");

		const res = await regenerate(agent);

		expect(res.status, JSON.stringify(res.body)).toBe(409);
		expect(res.body).toEqual(FACTORS_BUSY);
		expect(Number(res.headers["retry-after"])).toBeGreaterThanOrEqual(58);
		expect(create).not.toHaveBeenCalled();
	});

	it("refuses 409 mfa_factors_changed, nothing written, when a recovery or a reset moved the generation since the request was admitted", async () => {
		const built = await composed();
		const { agent } = await signedIn(built);
		const store = built.transactionStore;
		const acquire = store.acquireSubjectLease.bind(store);
		vi.spyOn(store, "acquireSubjectLease").mockImplementationOnce(async (subject, asked) => {
			await moveGeneration(store, subject);
			return acquire(subject, asked);
		});
		const create = vi.spyOn(built.factorStore, "create");

		const res = await regenerate(agent);

		expect(res.status, JSON.stringify(res.body)).toBe(409);
		expect(res.body).toEqual(FACTORS_CHANGED);
		expect(create).not.toHaveBeenCalled();
	});

	it("takes the start before the session's admission, and runs every write — the floor's raise among them — under one lease", async () => {
		const built = await composed();
		const { agent } = await signedIn(built);
		const store = built.transactionStore;
		const generation = vi.spyOn(store, "subjectGeneration");
		const acquire = vi.spyOn(store, "acquireSubjectLease");
		const release = vi.spyOn(store, "releaseSubjectLease");
		const raise = vi.spyOn(store, "raiseRecoverySetFloor");
		const create = vi.spyOn(built.factorStore, "create");
		const update = vi.spyOn(built.factorStore, "update");
		const removed = vi.spyOn(built.factorStore, "remove");

		expect((await regenerate(agent)).status).toBe(200);

		expect(acquire).toHaveBeenCalledTimes(1);
		expect(release).toHaveBeenCalledTimes(1);
		const after = acquire.mock.invocationCallOrder[0] ?? 0;
		const before = release.mock.invocationCallOrder[0] ?? 0;
		expect(generation.mock.invocationCallOrder[0] ?? Infinity).toBeLessThan(after);
		for (const spy of [create, raise, removed, update]) {
			for (const at of spy.mock.invocationCallOrder) {
				expect(at).toBeGreaterThan(after);
				expect(at).toBeLessThan(before);
			}
		}
		expect(raise.mock.calls[0]?.[1]).toMatchObject({
			setGeneration: 1,
			leaseToken: expect.any(String),
		});
	});

	it("answers the codes it marked shown when its lease ended before the release, saying the overrun at error", async () => {
		const built = await composed();
		const { agent } = await signedIn(built);
		vi.spyOn(built.transactionStore, "releaseSubjectLease").mockResolvedValue(false);

		const res = await regenerate(agent);

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(res.body.recovery_codes).toHaveLength(10);
		expect(events(built.logger, "error")).toEqual(["mfa_subject_lease_overrun"]);
		expect(built.audit.of("mfa.recovery_codes.generated")).toHaveLength(1);
	});
});

describe("a regeneration past the lease's call budget", () => {
	it("is cut off by the lease's time when its Store is slow: 503, the codes unshown, every set that stood already retired; run again, it sweeps the rest", async () => {
		const built = await composed();
		const { agent, old } = await signedIn(built);
		for (let n = 0; n < FACTOR_SET_STORE_CALLS + 5; n++) {
			await seedFactor(built.factorStore, "recovery_code", recoverySet(1).data);
		}
		const real = performance.now.bind(performance);
		let ahead = 0;
		vi.spyOn(performance, "now").mockImplementation(() => real() + ahead);
		const remove = built.factorStore.remove.bind(built.factorStore);
		const slow = vi.spyOn(built.factorStore, "remove").mockImplementation(async (...args) => {
			// Each removal takes a whole Store timeout (the default 5000 ms).
			ahead += 5_000;
			return remove(...args);
		});

		const cut = await regenerate(agent);

		expect(cut.status, JSON.stringify(cut.body)).toBe(503);
		expect(cut.body).toEqual(UNAVAILABLE);
		expect(events(built.logger, "error")).toEqual([
			"mfa_subject_lease_overrun",
			"mfa_recovery_codes_unwritten",
		]);
		const left = await setsOf(built.factorStore);
		expect(left.length).toBeGreaterThan(1);
		expect(left.filter((set) => set.data.generation === 1).map((set) => set.data.shown)).toEqual([
			false,
		]);
		expect(await built.transactionStore.recoverySetFloor(ALICE.id)).toBe(1);

		slow.mockImplementation(remove);
		const again = await regenerate(agent);

		expect(again.status, JSON.stringify(again.body)).toBe(200);
		expect((await setsOf(built.factorStore)).map((set) => set.data.generation)).toEqual([2]);
		expect((await loginWithCode(built, old.record, old.codes[0])).status).toBe(400);
	});
});

describe("the account page's list after a regeneration", () => {
	it("says whether each set's codes were shown", async () => {
		const built = await composed();
		const { agent } = await signedIn(built);
		await regenerate(agent);
		const unshown = generateRecoveryCodes(
			createRecoveryCodeFactor({ count: 2 }),
			suiteSealing().digestsFor("recovery_code"),
			1,
		);
		if (unshown === undefined) throw new Error("no set");
		await seedFactor(built.factorStore, "recovery_code", unshown.data);

		const res = await agent.get("/session/mfa/factors");

		expect(
			(res.body.factors as { kind: string; recovery_codes_shown?: boolean }[])
				.filter((factor) => factor.kind === "recovery_code")
				.map((factor) => factor.recovery_codes_shown),
		).toEqual([false, true]);
		expect(
			(res.body.factors as { kind: string; recovery_codes_shown?: boolean }[]).find(
				(factor) => factor.kind === "totp",
			),
		).not.toHaveProperty("recovery_codes_shown");
	});
});

/** The operator reset's step on the transaction store alone: the subject's generation moved on by one, under its lease. */
async function moveGeneration(store: MfaTransactionStore, subject: string): Promise<void> {
	await store.authorizeSubjectRecovery(subject, {
		operation: "reset",
		sid: undefined,
		recoveryId: newFactorId(),
		expiresAtMs: Date.now() + 60_000,
	});
	const lease = await store.acquireSubjectLease(subject, {
		ttlMs: 10_000,
		generation: await store.subjectGeneration(subject),
	});
	if (lease.outcome !== "acquired") throw new Error(`no lease: ${lease.outcome}`);
	await store.applySubjectRecovery(subject, {
		operation: "reset",
		sid: undefined,
		nowMs: Date.now(),
		leaseToken: lease.token,
		sessionsBoundaryMs: undefined,
		guessableBoundSinceMs: undefined,
	});
	await store.releaseSubjectLease(subject, lease.token);
}
