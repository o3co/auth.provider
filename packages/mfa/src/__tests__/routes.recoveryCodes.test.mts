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
	login,
	spyLogger,
	WitnessingUserRepository,
} from "./moduleHarness.mjs";
import {
	addRecord,
	beginLogin,
	freezeClock,
	loggedText,
	mfaPost,
	newFactorId,
	raiseRecoverySetFloor,
	readTransaction,
	recordingAuditSink,
	recoverySet,
	STEP_UP_REQUIRED,
	seedFactor,
	seedTotp,
	signIn,
	signInWithTotp,
	stepUp,
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
const REQUEST_STALE = {
	error: "mfa_request_stale",
	error_description: "The request took too long to be checked safely: try again",
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
		/** Whether alice's directory entry says she enrolled: by default, as a subject holding a factor; false for one holding none. */
		readonly enrolled?: boolean;
		/** More of the `mfa` section, laid over the suite's. */
		readonly mfa?: Record<string, unknown>;
	} = {},
) {
	const factorStore = options.factorStore ?? createMemoryMfaFactorStore();
	const transactionStore: MfaTransactionStore = createMemoryMfaTransactionStore();
	const audit = recordingAuditSink();
	const logger = spyLogger();
	const entries = directoryEntries();
	const alice = entries.get(ALICE.username);
	// A subject holding a factor whose directory says so: no login reconciles the witness, so no first-binding mark is noted.
	if (alice !== undefined) alice.mfaEnrolled = options.enrolled ?? true;
	const users = new WitnessingUserRepository(entries);
	const booted = await boot({
		config: {
			...configFor(options.mode ?? "required", {
				...(options.requireEmailProof === undefined
					? {}
					: { enrollment: { requireEmailProof: options.requireEmailProof } }),
				...(options.mfa ?? {}),
			}),
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
		vi.spyOn(built.factorStore, "removeIf").mockRejectedValueOnce(new Error("remove failed"));

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
		await addRecord(built.factorStore, copied);
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
		const create = vi.spyOn(built.factorStore, "createIf");

		const res = await regenerate(agent);

		expect(res.status, JSON.stringify(res.body)).toBe(403);
		expect(res.body).toMatchObject(STEP_UP_REQUIRED);
		expect(create).not.toHaveBeenCalled();
	});

	it("refuses a POST without the CSRF token, reading nothing", async () => {
		const built = await composed();
		const { agent } = await signedIn(built);
		const listed = vi.spyOn(built.factorStore, "list");
		const versioned = vi.spyOn(built.factorStore, "listVersioned");

		const res = await agent.post("/session/mfa/recovery-codes").send({});

		expect(res.status).toBe(403);
		expect(listed).not.toHaveBeenCalled();
		expect(versioned).not.toHaveBeenCalled();
	});

	it("refuses a signed-out browser: 401 login_required", async () => {
		const built = await composed();
		const res = await regenerate(request.agent(built.app));
		expect(res.status).toBe(401);
		expect(res.body).toMatchObject({ error: "login_required" });
	});

	it("refuses a subject with no record that may count, whom mfa.manage admits on a recent primary: 409 mfa_enrollment_required, nothing written", async () => {
		const built = await composed({ mode: "optional", requireEmailProof: "never", enrolled: false });
		const set = recoverySet(3);
		const record = await seedFactor(built.factorStore, "recovery_code", set.data);
		const { agent, transaction } = await beginLogin(built.app);
		expect((await verify(agent, transaction, record.id, set.codes[0])).status).toBe(200);
		const create = vi.spyOn(built.factorStore, "createIf");

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

describe("a regeneration's own checks under the lease", () => {
	it("sends a session signed in before the subject's first binding to log in again: a password-only session admitted while no factor stood, racing the owner's first binding, gets no codes", async () => {
		const built = await composed({ mode: "optional", requireEmailProof: "never", enrolled: false });
		const { agent } = await signIn(built.app, built.userSessionStore);
		const store = built.transactionStore;
		const acquire = store.acquireSubjectLease.bind(store);
		vi.spyOn(store, "acquireSubjectLease").mockImplementationOnce(async (subject, asked) => {
			// The owner's first binding lands between this request's admission and its lease.
			await store.noteFirstBinding(subject, Date.now(), Date.now() + 1_800_000);
			await seedTotp(built.factorStore);
			return acquire(subject, asked);
		});

		const res = await regenerate(agent);

		expect(res.status, JSON.stringify(res.body)).toBe(401);
		expect(res.body).toMatchObject({ error: "login_required" });
		expect(Number(res.headers["retry-after"])).toBeGreaterThan(0);
		expect(await setsOf(built.factorStore)).toEqual([]);
		expect(events(built.logger, "info")).toContain("mfa_first_binding_distrusted");
		expect(await built.transactionStore.recoverySetFloor(ALICE.id)).toBe(0);
	});

	it("refuses 409 mfa_request_stale, nothing written, a password-only request that stalled inside its admission past the owner's first-binding mark", async () => {
		const built = await composed({ mode: "optional", requireEmailProof: "never", enrolled: false });
		const { agent } = await signIn(built.app, built.userSessionStore);
		const store = built.transactionStore;
		const flag = store.emailProofRequiredAtNextBinding.bind(store);
		vi.spyOn(store, "emailProofRequiredAtNextBinding").mockImplementationOnce(async (subject) => {
			// The first-binding gate's read stalls after the recency check: the owner binds,
			// noting the mark, and the mark (30 minutes here) lapses before the read answers.
			await store.noteFirstBinding(subject, Date.now(), Date.now() + 30 * 60_000);
			await seedTotp(built.factorStore);
			vi.setSystemTime(Date.now() + 31 * 60_000);
			return flag(subject);
		});

		const res = await regenerate(agent);

		expect(res.status, JSON.stringify(res.body)).toBe(409);
		expect(res.body).toEqual(REQUEST_STALE);
		expect(await setsOf(built.factorStore)).toEqual([]);
	});

	it.each([
		["refuses 409 mfa_request_stale", 26, 409],
		["answers", 24, 200],
	] as const)(
		"%s a request that reached its lease %i minutes after it began: a mark lives 30 minutes and a lease here, relied on 25",
		async (_, minutes, status) => {
			const built = await composed();
			const { agent } = await signedIn(built);
			const store = built.transactionStore;
			const acquire = store.acquireSubjectLease.bind(store);
			vi.spyOn(store, "acquireSubjectLease").mockImplementationOnce(async (subject, asked) => {
				// After the admission, before the lease: the store's own lease runs from here.
				vi.setSystemTime(Date.now() + minutes * 60_000);
				return acquire(subject, asked);
			});

			const res = await regenerate(agent);

			expect(res.status, JSON.stringify(res.body)).toBe(status);
			if (status === 409) expect(res.body).toEqual(REQUEST_STALE);
		},
	);

	it("sends to log in again a session signed in later than the mark by just over the skew: the owner's factor may still have been landing, up to a lease after its mark", async () => {
		const built = await composed({ mode: "optional", requireEmailProof: "never", enrolled: false });
		const store = built.transactionStore;
		// The owner's first binding notes its mark; its factor is still landing.
		await store.noteFirstBinding(ALICE.id, Date.now(), Date.now() + 1_800_000);
		// A sign-in dated 301 s after the mark: a clock just under the skew ahead, or a real wait.
		vi.setSystemTime(Date.now() + 301_000);
		const { agent } = await signIn(built.app, built.userSessionStore);
		const acquire = store.acquireSubjectLease.bind(store);
		vi.spyOn(store, "acquireSubjectLease").mockImplementationOnce(async (subject, asked) => {
			// The owner's factor lands between this request's admission and its lease.
			await seedTotp(built.factorStore);
			return acquire(subject, asked);
		});

		const res = await regenerate(agent);

		expect(res.status, JSON.stringify(res.body)).toBe(401);
		expect(res.body).toMatchObject({ error: "login_required" });
		expect(await setsOf(built.factorStore)).toEqual([]);
	});

	it("answers an ordinary regeneration at the shortest windows and the longest Store timeout: the stall bound stays positive", async () => {
		const built = await composed({
			mfa: { manage: { maxAgeSeconds: 60 }, transactionTtlSeconds: 60, storeTimeoutMs: 37_500 },
		});
		const { agent } = await signedIn(built);

		expect((await regenerate(agent)).status).toBe(200);
	});

	it("is 503, nothing written, when the subject's first-binding mark cannot be read", async () => {
		const built = await composed();
		const { agent } = await signedIn(built);
		vi.spyOn(built.transactionStore, "firstBindingAt").mockRejectedValue(new Error("down"));
		const create = vi.spyOn(built.factorStore, "createIf");

		const res = await regenerate(agent);

		expect(res.status, JSON.stringify(res.body)).toBe(503);
		expect(create).not.toHaveBeenCalled();
	});

	it("refuses 409 mfa_factor_limit, nothing written, a subject at mfa.maxFactorsPerSubject holding no recovery set", async () => {
		const built = await composed();
		const totp = await seedTotp(built.factorStore);
		for (let n = 1; n < 10; n++) await seedTotp(built.factorStore);
		const { agent } = await signInWithTotp(built.app, built.userSessionStore, totp);
		const create = vi.spyOn(built.factorStore, "createIf");

		const res = await regenerate(agent);

		expect(res.status, JSON.stringify(res.body)).toBe(409);
		expect(res.body).toEqual({
			error: "mfa_factor_limit",
			error_description: "The subject holds as many second factors as it may",
		});
		expect(create).not.toHaveBeenCalled();
	});

	it("replaces the set of a subject at mfa.maxFactorsPerSubject that holds one", async () => {
		const built = await composed();
		const { agent } = await signedIn(built);
		for (let n = 2; n < 10; n++) await seedTotp(built.factorStore);
		expect(await built.factorStore.list(ALICE.id)).toHaveLength(10);

		const res = await regenerate(agent);

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(await built.factorStore.list(ALICE.id)).toHaveLength(10);
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

	it("writes no set when another writer's set landed after the lease read the records: 409 mfa_recovery_codes_conflict, nothing removed, the floor untouched, no codes, said at warn", async () => {
		const memory = createMemoryMfaFactorStore();
		const built = await composed({ factorStore: memory });
		const { agent, old } = await signedIn(built);
		const createIf = memory.createIf.bind(memory);
		let other: MfaFactorRecord | undefined;
		vi.spyOn(memory, "createIf").mockImplementationOnce(async (record, expected) => {
			// A second writer past its lease writes a set of the same generation first.
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
			await addRecord(memory, other);
			return createIf(record, expected);
		});
		const removeIf = vi.spyOn(memory, "removeIf");
		built.logger.warn.mockClear();

		const res = await regenerate(agent);

		expect(res.status, JSON.stringify(res.body)).toBe(409);
		expect(res.body).toEqual(CONFLICT);
		expect((await setsOf(built.factorStore)).map((set) => set.record.id).sort()).toEqual(
			[old.record.id, other?.id].sort(),
		);
		expect(removeIf).not.toHaveBeenCalled();
		expect(await built.transactionStore.recoverySetFloor(ALICE.id)).toBe(0);
		expect(events(built.logger, "warn")).toEqual(["mfa_recovery_codes_conflict"]);
		expect(built.audit.of("mfa.recovery_codes.generated")).toEqual([]);
	});

	it("answers 503 when the records cannot be listed under the lease, nothing written", async () => {
		const built = await composed();
		const { agent } = await signedIn(built);
		// Admission's read answers; the one under the lease does not.
		vi.spyOn(built.factorStore, "listVersioned").mockRejectedValueOnce(new Error("list failed"));
		const create = vi.spyOn(built.factorStore, "createIf");

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
		const create = vi.spyOn(built.factorStore, "createIf");

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
		const create = vi.spyOn(built.factorStore, "createIf");

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
		const create = vi.spyOn(built.factorStore, "createIf");
		const update = vi.spyOn(built.factorStore, "update");
		const removed = vi.spyOn(built.factorStore, "removeIf");

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
		const remove = built.factorStore.removeIf.bind(built.factorStore);
		const slow = vi.spyOn(built.factorStore, "removeIf").mockImplementation(async (...args) => {
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

describe("a retired set left stored", () => {
	/** Alice after a regeneration whose sweep failed: the set that stood is still stored, below the floor. */
	async function leftStored(built: Awaited<ReturnType<typeof composed>>) {
		const signed = await signedIn(built);
		vi.spyOn(built.factorStore, "removeIf").mockRejectedValueOnce(new Error("remove failed"));
		const res = await regenerate(signed.agent);
		expect(res.status, JSON.stringify(res.body)).toBe(200);
		vi.restoreAllMocks();
		const [fresh] = (await setsOf(built.factorStore)).filter((set) => set.data.generation === 1);
		if (fresh === undefined) throw new Error("no new set");
		return { ...signed, fresh };
	}

	/** The recovery sets a login's transaction offers. */
	async function offered(built: Awaited<ReturnType<typeof composed>>) {
		const { agent, transaction } = await beginLogin(built.app);
		const res = await readTransaction(agent, transaction);
		expect(res.status, JSON.stringify(res.body)).toBe(200);
		return (res.body.factors as { id: string; kind: string }[])
			.filter((factor) => factor.kind === "recovery_code")
			.map((factor) => factor.id);
	}

	it("is not offered at the next login; the new set is", async () => {
		const built = await composed();
		const { old, fresh } = await leftStored(built);

		expect(await offered(built)).toEqual([fresh.record.id]);
		expect((await setsOf(built.factorStore)).map((set) => set.record.id)).toContain(old.record.id);
	});

	it("is listed retired, with neither its codes left nor whether they were shown; the new set usable", async () => {
		const built = await composed();
		const { agent, old, fresh } = await leftStored(built);

		const res = await agent.get("/session/mfa/factors");

		const sets = (res.body.factors as Record<string, unknown>[]).filter(
			(factor) => factor.kind === "recovery_code",
		);
		expect(sets).toEqual([
			expect.objectContaining({ id: old.record.id, state: "retired" }),
			expect.objectContaining({
				id: fresh.record.id,
				state: "usable",
				recovery_codes_remaining: 10,
				recovery_codes_shown: true,
			}),
		]);
		expect(sets[0]).not.toHaveProperty("recovery_codes_remaining");
		expect(sets[0]).not.toHaveProperty("recovery_codes_shown");
	});

	it("is still offered and listed as read when the floor cannot be read — locking nobody out — and its codes are still refused", async () => {
		const built = await composed();
		const { agent, old, fresh } = await leftStored(built);
		vi.spyOn(built.transactionStore, "recoverySetFloor").mockRejectedValue(new Error("down"));
		built.logger.warn.mockClear();

		expect((await offered(built)).sort()).toEqual([old.record.id, fresh.record.id].sort());
		const listed = await agent.get("/session/mfa/factors");
		expect(listed.status).toBe(200);
		expect(
			(listed.body.factors as { id: string; state: string }[]).find(
				(factor) => factor.id === old.record.id,
			)?.state,
		).toBe("usable");
		// Said at warn once per reading: the login's ask, the offers, the list.
		expect(events(built.logger, "warn")).toEqual([
			"mfa_recovery_set_floor_unread",
			"mfa_recovery_set_floor_unread",
			"mfa_recovery_set_floor_unread",
		]);
		expect(built.logger.warn.mock.calls[0]?.[0]).toMatchObject({ sub: ALICE.id });
		expect((await loginWithCode(built, old.record, old.codes[0])).status).toBe(503);
		vi.restoreAllMocks();
		expect((await loginWithCode(built, old.record, old.codes[0])).status).toBe(401);
	});

	it("never hides the newest set when a regeneration lands after the records were listed: a retired set read under the floor lists the records again", async () => {
		const built = await composed();
		const { agent } = await signedIn(built);
		expect((await regenerate(agent)).status).toBe(200);
		const [current] = await setsOf(built.factorStore);
		if (current === undefined) throw new Error("no set");
		const { agent: browser, transaction } = await beginLogin(built.app);
		let newest: MfaFactorRecord | undefined;
		const list = built.factorStore.list.bind(built.factorStore);
		vi.spyOn(built.factorStore, "list").mockImplementationOnce(async (subject) => {
			const snapshot = await list(subject);
			// Another regeneration lands after this listing: a newer set, and the floor raised to it.
			const next = generateRecoveryCodes(
				createRecoveryCodeFactor({ count: 2 }),
				suiteSealing().digestsFor("recovery_code"),
				2,
			);
			if (next === undefined) throw new Error("no set");
			newest = await seedFactor(built.factorStore, "recovery_code", next.data);
			await raiseRecoverySetFloor(built.transactionStore, 2);
			return snapshot;
		});

		const floor = vi.spyOn(built.transactionStore, "recoverySetFloor");
		const listed = vi.mocked(built.factorStore.list);
		listed.mockClear();

		const res = await readTransaction(browser, transaction);

		expect(
			(res.body.factors as { id: string; kind: string }[])
				.filter((factor) => factor.kind === "recovery_code")
				.map((factor) => factor.id),
		).toEqual([newest?.id]);
		// At most two listings and one floor read.
		expect(listed).toHaveBeenCalledTimes(2);
		expect(floor).toHaveBeenCalledTimes(1);
		expect(current.record.id).not.toBe(newest?.id);
	});

	it("lists the records again when no set it can read stands at the floor: a newer set is not missed behind an old one that no longer opens", async () => {
		const built = await composed();
		await seedTotp(built.factorStore);
		const old: MfaFactorRecord = {
			id: newFactorId(),
			subject: ALICE.id,
			kind: "recovery_code",
			label: undefined,
			binding: "password",
			createdAt: new Date(T0 - 2_000),
			lastUsedAt: undefined,
			version: 0,
			data: suiteSealing().sealFactorData(
				{ subject: BOB.id, id: "elsewhere", kind: "recovery_code" },
				recoverySet(2).data,
			),
		};
		await addRecord(built.factorStore, old);
		const { agent: browser, transaction } = await beginLogin(built.app);
		let newest: MfaFactorRecord | undefined;
		const list = built.factorStore.list.bind(built.factorStore);
		vi.spyOn(built.factorStore, "list").mockImplementationOnce(async (subject) => {
			const snapshot = await list(subject);
			const next = generateRecoveryCodes(
				createRecoveryCodeFactor({ count: 2 }),
				suiteSealing().digestsFor("recovery_code"),
				1,
			);
			if (next === undefined) throw new Error("no set");
			newest = await seedFactor(built.factorStore, "recovery_code", next.data);
			await raiseRecoverySetFloor(built.transactionStore, 1);
			return snapshot;
		});

		const res = await readTransaction(browser, transaction);

		expect(
			(res.body.factors as { id: string; kind: string }[])
				.filter((factor) => factor.kind === "recovery_code")
				.map((factor) => factor.id),
		).toContain(newest?.id);
	});

	it("lists the records again when the floor cannot be read, so a set written while the floor read hung is offered", async () => {
		const built = await composed();
		await leftStored(built);
		const { agent: browser, transaction } = await beginLogin(built.app);
		let newest: MfaFactorRecord | undefined;
		vi.spyOn(built.transactionStore, "recoverySetFloor").mockImplementationOnce(async () => {
			const next = generateRecoveryCodes(
				createRecoveryCodeFactor({ count: 2 }),
				suiteSealing().digestsFor("recovery_code"),
				2,
			);
			if (next === undefined) throw new Error("no set");
			newest = await seedFactor(built.factorStore, "recovery_code", next.data);
			throw new Error("down");
		});
		const listed = vi.spyOn(built.factorStore, "list");

		const res = await readTransaction(browser, transaction);

		expect(
			(res.body.factors as { id: string; kind: string }[])
				.filter((factor) => factor.kind === "recovery_code")
				.map((factor) => factor.id),
		).toContain(newest?.id);
		expect(listed).toHaveBeenCalledTimes(2);
	});

	it("reads no floor for a subject holding no recovery set: a password login's ask, the offers, the list and a step-up", async () => {
		const built = await composed();
		const totp = await seedTotp(built.factorStore);
		const floor = vi.spyOn(built.transactionStore, "recoverySetFloor");
		const { agent } = await signInWithTotp(built.app, built.userSessionStore, totp);

		await offered(built);
		await agent.get("/session/mfa/factors");
		expect((await stepUp(agent)).status).toBe(200);

		expect(floor).not.toHaveBeenCalled();
	});
});

describe("routing over a retired set: one reading of usable, the floor's", () => {
	/** Alice's TOTP, a record of a kind no longer installed, and a recovery set below the raised floor; signed in with the TOTP, which is then removed. */
	async function retiredOnly(
		options: { readonly mode?: "optional" | "required"; readonly signIn?: boolean } = {},
	) {
		const built = await composed({ mode: options.mode ?? "optional" });
		const totp = await seedTotp(built.factorStore);
		await seedFactor(built.factorStore, "uninstalled_kind", { anything: true });
		const set = recoverySet(3);
		const retired = await seedFactor(built.factorStore, "recovery_code", set.data);
		await raiseRecoverySetFloor(built.transactionStore, 1);
		const agent =
			options.signIn === false
				? undefined
				: (await signInWithTotp(built.app, built.userSessionStore, totp)).agent;
		await built.factorStore.remove(ALICE.id, totp.record.id);
		return { built, agent, retired, set };
	}

	it("answers a step-up 403 mfa_no_qualifying_factor when only a retired set and a kind no longer installed stand — never an empty transaction", async () => {
		const { built, agent } = await retiredOnly();
		if (agent === undefined) throw new Error("not signed in");
		const opened = vi.spyOn(built.transactionStore, "create");

		const res = await stepUp(agent);

		expect(res.status, JSON.stringify(res.body)).toBe(403);
		expect(res.body).toMatchObject({ error: "mfa_no_qualifying_factor" });
		expect(opened).not.toHaveBeenCalled();
	});

	it("opens the step-up as before when the floor cannot be read: an outage never hides the way in", async () => {
		const { built, agent } = await retiredOnly();
		if (agent === undefined) throw new Error("not signed in");
		vi.spyOn(built.transactionStore, "recoverySetFloor").mockRejectedValue(new Error("down"));
		built.logger.warn.mockClear();

		const res = await stepUp(agent);

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(events(built.logger, "warn")).toContain("mfa_recovery_set_floor_unread");
	});

	it("does not ask a password login for a second factor over a retired set alone: under optional the login is established, as over an exhausted set", async () => {
		const built = await composed({ mode: "optional", enrolled: false });
		await seedFactor(built.factorStore, "recovery_code", recoverySet(3).data);
		await raiseRecoverySetFloor(built.transactionStore, 1);

		const { res } = await login(built.app, { username: ALICE.username, password: ALICE.password });

		expect(res.status, JSON.stringify(res.body)).toBe(200);
	});

	it("still asks over a retired set alone when the floor cannot be read: an outage never lowers the bar", async () => {
		const built = await composed({ mode: "optional", enrolled: false });
		await seedFactor(built.factorStore, "recovery_code", recoverySet(3).data);
		await raiseRecoverySetFloor(built.transactionStore, 1);
		vi.spyOn(built.transactionStore, "recoverySetFloor").mockRejectedValue(new Error("down"));

		const { res } = await login(built.app, { username: ALICE.username, password: ALICE.password });

		expect(res.status, JSON.stringify(res.body)).toBe(403);
		expect(res.body).toMatchObject({ error: "mfa_required" });
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
