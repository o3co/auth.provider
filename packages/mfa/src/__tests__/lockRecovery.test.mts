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
 * The authorized-recovery entry (`lockRecovery.mts`) over core's memory
 * stores: an authorization minted for a factor that is not guessable, and a
 * release judged by the store on that authorization, the subjects' sessions
 * boundary and the guessable records it reads under the subject's lease.
 */

import {
	createMemoryMfaFactorStore,
	createMemoryMfaTransactionStore,
	DEFAULT_CLOCK_SKEW_MS,
	MFA_RECOVERY_AUTHORIZATION_MAX_MS,
	type MfaFactor,
	type MfaFactorRecord,
	type MfaFactorResolver,
	type MfaFactorStore,
	type MfaLockoutPolicy,
	type MfaTransactionStore,
	OTP_AMR,
} from "@o3co/auth-provider-core";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createMfaFactorSet, createMfaSubjectLeases } from "#/factorSet.mjs";
import { createMfaLockRecovery } from "#/lockRecovery.mjs";
import { createMfaEnrollmentWitness } from "#/witness.mjs";

const SUBJECT = "u-alice";
const SID = "sid-alice";
const T = 1_800_000_000_000;
const MANAGE_MS = 300_000;

/** A factor of `kind` as the entry reads one: whether it is guessable. */
const factorOf = (kind: string, guessable: boolean): MfaFactor => ({
	kind,
	amrValues: [OTP_AMR],
	amrFor: () => [OTP_AMR],
	addsMfa: true,
	counting: true,
	guessable,
	describe: () => ({}),
	verify: async () => ({ ok: false, reason: "invalid" }),
	beginEnrollment: async () => {
		throw new Error("not enrolled here");
	},
	completeEnrollment: async () => {
		throw new Error("not enrolled here");
	},
});

const resolverOf = (...factors: MfaFactor[]): MfaFactorResolver => {
	const byKind = new Map(factors.map((factor) => [factor.kind, factor] as const));
	return { get: (kind) => byKind.get(kind), entries: () => byKind.entries() };
};

/** TOTP (guessable) and a key (exempt) installed; "gone" is not. */
const FACTORS = resolverOf(factorOf("totp", true), factorOf("key", false));

/** A lock whose hard hold the tenth failure fixes, the backoff after the ninth lasting one second. */
const POLICY: MfaLockoutPolicy = {
	threshold: 9,
	baseSeconds: 1,
	maxSeconds: 1,
	memorySeconds: 86_400,
	weeklyBudget: 100,
	hardLimit: 10,
};

let clock = T;

afterEach(() => {
	clock = T;
	vi.restoreAllMocks();
});

/** The entry over memory stores on the suite's clock, the boundary `boundary` answers when given. */
function setup(
	options: {
		readonly boundary?: () => Promise<Date | null>;
		readonly store?: MfaTransactionStore;
		readonly factorStore?: MfaFactorStore;
	} = {},
) {
	const store = options.store ?? createMemoryMfaTransactionStore({ now: () => clock });
	const factorStore = options.factorStore ?? createMemoryMfaFactorStore();
	const factorSet = createMfaFactorSet({
		factors: FACTORS,
		factorStore,
		witness: createMfaEnrollmentWitness(undefined),
		leases: createMfaSubjectLeases({ store, storeTimeoutMs: 1_000 }),
	});
	const recovery = createMfaLockRecovery({
		store,
		factorSet,
		factors: FACTORS,
		...(options.boundary === undefined
			? {}
			: { subjectRevocation: { revokedBefore: options.boundary } }),
		manageMaxAgeMs: MANAGE_MS,
		now: () => clock,
	});
	return { store, factorStore, recovery };
}

/** One failure counted for the subject at `atMs`. */
async function failAt(store: MfaTransactionStore, atMs: number): Promise<void> {
	const reserved = await store.reserveSubjectAttempt(SUBJECT, atMs, POLICY);
	if (!reserved.ok) throw new Error(`refused: ${reserved.hold}`);
	await store.settleSubjectAttempt(SUBJECT, reserved.reservation, "failure");
}

/** The subject's run brought to the hard limit from `T`: the hard hold fixed at the tenth. */
async function latch(store: MfaTransactionStore): Promise<void> {
	for (let n = 0; n < 9; n++) await failAt(store, T + n);
	await failAt(store, T + 10_000);
	const after = await store.reserveSubjectAttempt(SUBJECT, T + 20_000, POLICY);
	expect(after).toMatchObject({ ok: false, hold: "hard" });
}

/** A record of `kind` for the subject, created at `atMs`, its data never opened by the entry. */
const recordOf = (id: string, kind: string, atMs: number): MfaFactorRecord => ({
	id,
	subject: SUBJECT,
	kind,
	label: undefined,
	binding: "mfa",
	createdAt: new Date(atMs),
	lastUsedAt: undefined,
	version: 0,
	data: "not-sealed",
});

describe("minting at an exempt verification", () => {
	it("records a recover authorization for the session, ending mfa.manage.maxAgeSeconds after the verification, for a factor that is not guessable", async () => {
		const { store, recovery } = setup();
		const authorize = vi.spyOn(store, "authorizeSubjectRecovery");

		expect(await recovery.authorize(SUBJECT, SID, "key", T)).toEqual({ outcome: "minted" });

		expect(authorize).toHaveBeenCalledTimes(1);
		const [subject, authorization] = authorize.mock.calls[0] as Parameters<
			MfaTransactionStore["authorizeSubjectRecovery"]
		>;
		expect(subject).toBe(SUBJECT);
		expect(authorization).toEqual({
			operation: "recover",
			sid: SID,
			recoveryId: expect.stringMatching(/^[A-Za-z0-9_-]{22}$/),
			expiresAtMs: T + MANAGE_MS,
		});
	});

	it("mints a fresh recovery id each time", async () => {
		const { store, recovery } = setup();
		const authorize = vi.spyOn(store, "authorizeSubjectRecovery");
		await recovery.authorize(SUBJECT, SID, "key", T);
		await recovery.authorize(SUBJECT, SID, "key", T);
		const ids = authorize.mock.calls.map(([, authorization]) => authorization.recoveryId);
		expect(new Set(ids).size).toBe(2);
	});

	it("mints nothing for a guessable factor, or a kind that is not installed", async () => {
		const { store, recovery } = setup();
		const authorize = vi.spyOn(store, "authorizeSubjectRecovery");

		expect(await recovery.authorize(SUBJECT, SID, "totp", T)).toEqual({ outcome: "not_exempt" });
		expect(await recovery.authorize(SUBJECT, SID, "gone", T)).toEqual({ outcome: "not_exempt" });

		expect(authorize).not.toHaveBeenCalled();
	});

	it("answers the store's outage when the authorization cannot be recorded", async () => {
		const { store, recovery } = setup();
		const cause = new Error("store down");
		vi.spyOn(store, "authorizeSubjectRecovery").mockRejectedValue(cause);

		expect(await recovery.authorize(SUBJECT, SID, "key", T)).toEqual({
			outcome: "unavailable",
			cause,
		});
	});
});

describe("the entry's configuration", () => {
	it("refuses an authorization lifetime past core's longest, MFA_RECOVERY_AUTHORIZATION_MAX_MS, and takes that one", () => {
		const store = createMemoryMfaTransactionStore({ now: () => clock });
		const factorSet = createMfaFactorSet({
			factors: FACTORS,
			factorStore: createMemoryMfaFactorStore(),
			witness: createMfaEnrollmentWitness(undefined),
			leases: createMfaSubjectLeases({ store, storeTimeoutMs: 1_000 }),
		});
		const options = { store, factorSet, factors: FACTORS };
		expect(() =>
			createMfaLockRecovery({
				...options,
				manageMaxAgeMs: MFA_RECOVERY_AUTHORIZATION_MAX_MS + 1,
			}),
		).toThrow(RangeError);
		expect(() =>
			createMfaLockRecovery({ ...options, manageMaxAgeMs: MFA_RECOVERY_AUTHORIZATION_MAX_MS }),
		).not.toThrow();
	});
});

describe("a release", () => {
	/** A boundary later than the failure at `T` by more than the skew, and no further ahead of the release's clock than it. */
	const AFTER_THE_ATTACK = new Date(T + DEFAULT_CLOCK_SKEW_MS + 60_000);

	it("with no authorization is refused exempt_proof_required, and changes nothing", async () => {
		const { store, recovery } = setup({ boundary: async () => AFTER_THE_ATTACK });
		await failAt(store, T);
		clock = T + DEFAULT_CLOCK_SKEW_MS + 120_000;

		expect(await recovery.release(SUBJECT, SID)).toEqual({
			outcome: "refused",
			reason: "exempt_proof_required",
		});
		expect(await store.subjectGeneration(SUBJECT)).toBe(0);
	});

	it("whose authorization has ended is refused exempt_proof_required", async () => {
		const { store, recovery } = setup({ boundary: async () => AFTER_THE_ATTACK });
		await failAt(store, T);
		clock = T + DEFAULT_CLOCK_SKEW_MS + 120_000;
		await recovery.authorize(SUBJECT, SID, "key", clock);
		clock += MANAGE_MS;

		expect(await recovery.release(SUBJECT, SID)).toEqual({
			outcome: "refused",
			reason: "exempt_proof_required",
		});
	});

	it("in another session than the authorization's is refused exempt_proof_required", async () => {
		const { store, recovery } = setup({ boundary: async () => AFTER_THE_ATTACK });
		await failAt(store, T);
		clock = T + DEFAULT_CLOCK_SKEW_MS + 120_000;
		await recovery.authorize(SUBJECT, "sid-other", "key", clock);

		expect(await recovery.release(SUBJECT, SID)).toEqual({
			outcome: "refused",
			reason: "exempt_proof_required",
		});
	});

	it("with no sessions boundary wired is refused no_revocation_boundary while a counted failure stands", async () => {
		const { store, recovery } = setup();
		await failAt(store, T);
		clock = T + 1_000;
		await recovery.authorize(SUBJECT, SID, "key", clock);

		expect(await recovery.release(SUBJECT, SID)).toEqual({
			outcome: "refused",
			reason: "no_revocation_boundary",
		});
	});

	it("with a boundary no later than the first counted failure and the skew is refused not_revoked_since", async () => {
		const { store, recovery } = setup({
			boundary: async () => new Date(T + DEFAULT_CLOCK_SKEW_MS),
		});
		await failAt(store, T);
		clock = T + DEFAULT_CLOCK_SKEW_MS + 1_000;
		await recovery.authorize(SUBJECT, SID, "key", clock);

		expect(await recovery.release(SUBJECT, SID)).toEqual({
			outcome: "refused",
			reason: "not_revoked_since",
		});
	});

	it("with a boundary after the attack began is released: the week and the run given back, the generation moved", async () => {
		const { store, recovery } = setup({ boundary: async () => AFTER_THE_ATTACK });
		await failAt(store, T);
		clock = T + DEFAULT_CLOCK_SKEW_MS + 120_000;
		await recovery.authorize(SUBJECT, SID, "key", clock);

		expect(await recovery.release(SUBJECT, SID)).toEqual({
			outcome: "released",
			applied: true,
			generation: 1,
			cleared: { week: true, run: true, hard: false },
		});
		expect(await store.subjectGeneration(SUBJECT)).toBe(1);
	});

	it("leaves the subject's lease free once it answers", async () => {
		const { store, recovery } = setup({ boundary: async () => AFTER_THE_ATTACK });
		clock = T + DEFAULT_CLOCK_SKEW_MS + 120_000;
		await recovery.authorize(SUBJECT, SID, "key", clock);
		await recovery.release(SUBJECT, SID);

		const lease = await store.acquireSubjectLease(SUBJECT, { ttlMs: 1_000, generation: 1 });
		expect(lease.outcome).toBe("acquired");
	});

	it("answers again what an applied authorization came to, applying nothing more", async () => {
		const { store, recovery } = setup({ boundary: async () => AFTER_THE_ATTACK });
		await failAt(store, T);
		clock = T + DEFAULT_CLOCK_SKEW_MS + 120_000;
		await recovery.authorize(SUBJECT, SID, "key", clock);
		await recovery.release(SUBJECT, SID);

		expect(await recovery.release(SUBJECT, SID)).toEqual({
			outcome: "released",
			applied: false,
			generation: 1,
		});
		expect(await store.subjectGeneration(SUBJECT)).toBe(1);
	});

	it("while the hard hold stands and no guessable factor was bound since, answers it held: the week given back, the hold kept", async () => {
		const factorStore = createMemoryMfaFactorStore();
		await factorStore.create(recordOf("totp-old", "totp", T - 1_000));
		const { store, recovery } = setup({ boundary: async () => AFTER_THE_ATTACK, factorStore });
		await latch(store);
		clock = T + DEFAULT_CLOCK_SKEW_MS + 120_000;
		await recovery.authorize(SUBJECT, SID, "key", clock);

		expect(await recovery.release(SUBJECT, SID)).toEqual({
			outcome: "held",
			hold: "hard",
			applied: true,
			generation: 1,
			cleared: { week: true, run: false, hard: false },
		});
		expect(await store.reserveSubjectAttempt(SUBJECT, clock, POLICY)).toMatchObject({
			ok: false,
			hold: "hard",
		});
	});

	it("lifts the hard hold once every guessable record was bound after it, with no sessions boundary asked", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { store, recovery } = setup({ factorStore });
		await latch(store);
		await factorStore.create(recordOf("totp-new", "totp", T + 10_000 + DEFAULT_CLOCK_SKEW_MS + 1));
		clock = T + DEFAULT_CLOCK_SKEW_MS + 120_000;
		await recovery.authorize(SUBJECT, SID, "key", clock);

		expect(await recovery.release(SUBJECT, SID)).toEqual({
			outcome: "released",
			applied: true,
			generation: 1,
			cleared: { week: false, run: true, hard: true },
		});
	});

	it("reads, as the guessable records' earliest time, every record of a kind that is not exempt — one whose data does not open, and one of a kind not installed, included — and leaves out an exempt kind", async () => {
		const factorStore = createMemoryMfaFactorStore();
		await factorStore.create(recordOf("exempt", "key", T - 9_000));
		await factorStore.create(recordOf("uninstalled", "gone", T - 8_000));
		await factorStore.create(recordOf("totp-b", "totp", T - 2_000));
		await factorStore.create(recordOf("totp-a", "totp", T - 3_000));
		const { store, recovery } = setup({ boundary: async () => AFTER_THE_ATTACK, factorStore });
		const apply = vi.spyOn(store, "applySubjectRecovery");
		clock = T + DEFAULT_CLOCK_SKEW_MS + 120_000;
		await recovery.authorize(SUBJECT, SID, "key", clock);

		await recovery.release(SUBJECT, SID);

		expect(apply).toHaveBeenCalledWith(
			SUBJECT,
			expect.objectContaining({
				operation: "recover",
				sid: SID,
				nowMs: clock,
				sessionsBoundaryMs: AFTER_THE_ATTACK.getTime(),
				guessableBoundSinceMs: T - 8_000,
			}),
		);
	});

	it("keeps the hard hold while a record of a kind not installed stands from before it: an uninstalled kind could be installed again", async () => {
		const factorStore = createMemoryMfaFactorStore();
		await factorStore.create(recordOf("uninstalled", "gone", T - 1_000));
		const { store, recovery } = setup({ boundary: async () => AFTER_THE_ATTACK, factorStore });
		await latch(store);
		clock = T + DEFAULT_CLOCK_SKEW_MS + 120_000;
		await recovery.authorize(SUBJECT, SID, "key", clock);

		expect(await recovery.release(SUBJECT, SID)).toMatchObject({ outcome: "held", hold: "hard" });
	});

	it("counts a record whose kind cannot be read, never throwing: the hard hold stands", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const unreadable = {
			...recordOf("odd", "totp", T - 1_000),
			get kind(): string {
				throw new Error("a lazy field could not load");
			},
		};
		vi.spyOn(factorStore, "list").mockResolvedValue([unreadable] as never);
		const { store, recovery } = setup({ boundary: async () => AFTER_THE_ATTACK, factorStore });
		await latch(store);
		clock = T + DEFAULT_CLOCK_SKEW_MS + 120_000;
		await recovery.authorize(SUBJECT, SID, "key", clock);

		expect(await recovery.release(SUBJECT, SID)).toMatchObject({ outcome: "held", hold: "hard" });
	});

	it("reads the generation again after a pause when it moved before its acquire, and applies", async () => {
		const { store, recovery } = setup({ boundary: async () => AFTER_THE_ATTACK });
		clock = T + DEFAULT_CLOCK_SKEW_MS + 120_000;
		await recovery.authorize(SUBJECT, SID, "key", clock);
		vi.spyOn(store, "acquireSubjectLease").mockResolvedValueOnce({ outcome: "stale" });

		expect(await recovery.release(SUBJECT, SID)).toMatchObject({
			outcome: "released",
			applied: true,
		});
		expect(store.acquireSubjectLease).toHaveBeenCalledTimes(2);
	});

	it("hands null as the guessable records' earliest time when only exempt records remain", async () => {
		const factorStore = createMemoryMfaFactorStore();
		await factorStore.create(recordOf("exempt", "key", T - 8_000));
		const { store, recovery } = setup({ boundary: async () => null, factorStore });
		const apply = vi.spyOn(store, "applySubjectRecovery");
		await recovery.authorize(SUBJECT, SID, "key", clock);

		await recovery.release(SUBJECT, SID);

		expect(apply).toHaveBeenCalledWith(
			SUBJECT,
			expect.objectContaining({ sessionsBoundaryMs: undefined, guessableBoundSinceMs: null }),
		);
	});

	it("answers the boundary's outage when it cannot be read, or reads as no date, applying nothing", async () => {
		for (const boundary of [
			async () => {
				throw new Error("down");
			},
			async () => "yesterday" as unknown as Date,
			// A proxied Date, as an ORM may hand one: its reads throw.
			async () => new Proxy(new Date(T), {}),
		]) {
			const { store, recovery } = setup({ boundary });
			const apply = vi.spyOn(store, "applySubjectRecovery");
			await recovery.authorize(SUBJECT, SID, "key", clock);

			expect(await recovery.release(SUBJECT, SID)).toMatchObject({
				outcome: "unavailable",
				store: "subject_revocation",
				step: "revokedBefore",
			});
			expect(apply).not.toHaveBeenCalled();
		}
	});

	it("answers the factor store's outage when the records cannot be read, applying nothing", async () => {
		const factorStore = createMemoryMfaFactorStore();
		vi.spyOn(factorStore, "list").mockRejectedValue(new Error("down"));
		const { store, recovery } = setup({ boundary: async () => null, factorStore });
		const apply = vi.spyOn(store, "applySubjectRecovery");
		await recovery.authorize(SUBJECT, SID, "key", clock);

		expect(await recovery.release(SUBJECT, SID)).toMatchObject({
			outcome: "unavailable",
			store: "mfa_factor",
			step: "list",
		});
		expect(apply).not.toHaveBeenCalled();
	});

	it("answers the transaction store's outage when the apply fails, or answers outside the port", async () => {
		for (const answer of [Promise.reject(new Error("down")), Promise.resolve({ outcome: "x" })]) {
			const { store, recovery } = setup({ boundary: async () => null });
			await recovery.authorize(SUBJECT, SID, "key", clock);
			vi.spyOn(store, "applySubjectRecovery").mockReturnValue(answer as never);

			expect(await recovery.release(SUBJECT, SID)).toMatchObject({
				outcome: "unavailable",
				store: "mfa_transaction",
				step: "applySubjectRecovery",
			});
		}
	});

	it("answers busy, applying nothing, while another write holds the subject's lease", async () => {
		const { store, recovery } = setup({ boundary: async () => null });
		await recovery.authorize(SUBJECT, SID, "key", clock);
		await store.acquireSubjectLease(SUBJECT, { ttlMs: 60_000, generation: 0 });
		const apply = vi.spyOn(store, "applySubjectRecovery");

		expect(await recovery.release(SUBJECT, SID)).toMatchObject({ outcome: "busy" });
		expect(apply).not.toHaveBeenCalled();
	});
});
