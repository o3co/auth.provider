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
 * `POST /session/mfa/lock/release`, through the composed application: an
 * authorization minted when a factor that is not guessable verifies — at a
 * login or a session's step-up — and the subject's own release of the lock on
 * it, held to the sessions boundary and, for the hard hold, to a rebind.
 */

import {
	createInMemorySubjectRevocation,
	createMemoryMfaFactorStore,
	createMemoryMfaTransactionStore,
	DEFAULT_CLOCK_SKEW_MS,
	type MfaFactorStore,
	type MfaTransactionStore,
	type SubjectRevocation,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ALICE, boot, configFor, disposeAll, events } from "./moduleHarness.mjs";
import {
	type Agent,
	beginLogin,
	completeEnrollment,
	enrollFromAccount,
	freezeClock,
	HARD_AT_TEN,
	mfaPost,
	recordingAuditSink,
	recoverySet,
	type SeededTotp,
	seedFactor,
	seedTotp,
	signInWithTotp,
	stepUp,
	thawClock,
	totpCode,
	totpProofOf,
	verify,
	wrongCode,
	wrongCodesToTheHardLimit,
} from "./routesHarness.mjs";

beforeEach(() => freezeClock());
afterEach(async () => {
	await disposeAll();
	thawClock();
});

const DAY = 86_400_000;

const EXEMPT_PROOF_REQUIRED = {
	error: "mfa_exempt_proof_required",
	error_description: "Verify a recovery code or a passkey first, then release",
};

/** Boots `required` with the lock at {@link HARD_AT_TEN}, alice's TOTP and a set of five recovery codes seeded, an audit sink, and the subjects' boundary unless `withoutBoundary`. */
async function composed(options: { readonly withoutBoundary?: boolean } = {}) {
	const factorStore: MfaFactorStore = createMemoryMfaFactorStore();
	const transactionStore: MfaTransactionStore = createMemoryMfaTransactionStore();
	const totp = await seedTotp(factorStore);
	const set = recoverySet(5);
	const codes = {
		record: await seedFactor(factorStore, "recovery_code", set.data),
		codes: set.codes,
	};
	const revocation: SubjectRevocation | undefined =
		options.withoutBoundary === true ? undefined : createInMemorySubjectRevocation();
	const audit = recordingAuditSink();
	const booted = await boot({
		config: configFor("required", { lockout: HARD_AT_TEN }),
		factorStore,
		transactionStore,
		auditSink: audit,
		...(revocation === undefined ? {} : { subjectRevocation: revocation }),
	});
	return { ...booted, factorStore, transactionStore, totp, codes, revocation, audit };
}

type Composed = Awaited<ReturnType<typeof composed>>;

/** A login of alice finished with recovery code `n`: the browser holding the session. */
async function signInWithCode(setup: Composed, n: number): Promise<Agent> {
	const { agent, transaction } = await beginLogin(setup.app);
	const res = await verify(agent, transaction, setup.codes.record.id, setup.codes.codes[n]);
	expect(res.status, JSON.stringify(res.body)).toBe(200);
	return agent;
}

/** The subject's own password change, as the Store reports it: every session of alice's ended now; the clock then moved past the revocation's skew. */
async function changePassword(setup: Composed): Promise<void> {
	if (setup.revocation === undefined) throw new Error("no boundary wired");
	const now = Date.now();
	await setup.revocation.revokeBefore(ALICE.id, new Date(now), new Date(now + DAY));
	freezeClock(now + 2_000);
}

/** A TOTP factor bound from the account page in `agent`'s session: its secret. */
async function bindTotp(agent: Agent): Promise<string> {
	const begun = await enrollFromAccount(agent, "totp");
	expect(begun.status, JSON.stringify(begun.body)).toBe(200);
	const done = await completeEnrollment(
		agent,
		begun.body.transaction as string,
		totpProofOf(begun.body.secret),
	);
	expect(done.status, JSON.stringify(done.body)).toBe(200);
	return begun.body.secret as string;
}

/** The record `factorId` removed from the account page in `agent`'s session. */
async function remove(agent: Agent, factorId: string): Promise<void> {
	const res = await mfaPost(agent, "/factors/remove", { factor_id: factorId });
	expect(res.status, JSON.stringify(res.body)).toBe(200);
}

/** A step-up in `agent`'s session verified with recovery code `n`. */
async function stepUpWithCode(setup: Composed, agent: Agent, n: number): Promise<void> {
	const opened = await stepUp(agent);
	expect(opened.status, JSON.stringify(opened.body)).toBe(200);
	const res = await verify(
		agent,
		opened.body.transaction as string,
		setup.codes.record.id,
		setup.codes.codes[n],
	);
	expect(res.status, JSON.stringify(res.body)).toBe(200);
}

const release = (agent: Agent) => mfaPost(agent, "/lock/release", {});

/**
 * Brings alice to the hard hold and checks it holds her right TOTP code, then,
 * unless `withinTheMargin`, moves the clock past the clock-skew allowance: a
 * factor bound within it of the hold is not read as bound after it. Answers
 * from when a rebind counts, as the release says it: the hold's time plus
 * that allowance.
 */
async function hardHeld(
	setup: Composed,
	totp: SeededTotp,
	options: { readonly withinTheMargin?: boolean } = {},
): Promise<string> {
	const third = await wrongCodesToTheHardLimit(setup.app, totp);
	const latchedAt = Date.now();
	const held = await verify(third.agent, third.transaction, totp.record.id, totpCode(totp.secret));
	expect(held.status, JSON.stringify(held.body)).toBe(429);
	expect(held.body.hold).toBe("hard");
	if (options.withinTheMargin !== true) freezeClock(Date.now() + DEFAULT_CLOCK_SKEW_MS + 60_000);
	return new Date(latchedAt + DEFAULT_CLOCK_SKEW_MS).toISOString();
}

describe("the release, end to end", () => {
	it("refuses until the password changed, then gives the week back and says the hard hold stands, then releases once the TOTP factor is replaced, and the new one verifies", async () => {
		const setup = await composed();
		const rebindAfter = await hardHeld(setup, setup.totp);

		const first = await signInWithCode(setup, 0);
		const refused = await release(first);
		expect(refused.status, JSON.stringify(refused.body)).toBe(409);
		expect(refused.body).toEqual({
			error: "mfa_lock_release_refused",
			error_description: "Change the account's password, sign in again, then release",
			reason: "not_revoked_since",
			rebind_after: rebindAfter,
		});

		await changePassword(setup);
		const second = await signInWithCode(setup, 1);
		const held = await release(second);
		expect(held.status, JSON.stringify(held.body)).toBe(200);
		expect(held.body).toEqual({
			lock: "held",
			hold: "hard",
			description:
				"Guessable second factors stay held until each is replaced: replace them, verify a recovery code or a passkey again, then release",
			rebind_after: rebindAfter,
		});
		expect(setup.audit.of("mfa.lock.recovered")).toEqual([
			expect.objectContaining({
				subject: ALICE.id,
				details: {
					operation: "recover",
					generation: 1,
					cleared: { week: true, run: false, hard: false },
				},
			}),
		]);

		const secret = await bindTotp(second);
		await remove(second, setup.totp.record.id);
		await stepUpWithCode(setup, second, 2);
		const released = await release(second);
		expect(released.status, JSON.stringify(released.body)).toBe(200);
		expect(released.body).toEqual({ lock: "released" });
		expect(setup.audit.of("mfa.lock.recovered")).toHaveLength(2);
		expect(setup.audit.of("mfa.lock.recovered")[1]?.details).toMatchObject({
			operation: "recover",
			generation: 2,
			cleared: { run: true, hard: true },
		});

		freezeClock(Date.now() + 60_000);
		const listed = await setup.factorStore.list(ALICE.id);
		const bound = listed.find((record) => record.kind === "totp");
		if (bound === undefined) throw new Error("no TOTP factor stands");
		const { agent, transaction } = await beginLogin(setup.app);
		const verified = await verify(agent, transaction, bound.id, totpProofOf(secret));
		expect(verified.status, JSON.stringify(verified.body)).toBe(200);
	});

	it("spends one recovery code in the page's order — the password changed, a sign-in with a code, the factor replaced, then the release", async () => {
		const setup = await composed();
		await hardHeld(setup, setup.totp);
		await changePassword(setup);

		const agent = await signInWithCode(setup, 0);
		await bindTotp(agent);
		await remove(agent, setup.totp.record.id);
		const released = await release(agent);

		expect(released.status, JSON.stringify(released.body)).toBe(200);
		expect(released.body).toEqual({ lock: "released" });
		const factors = await agent.get("/session/mfa/factors");
		const set = (
			factors.body.factors as { kind: string; recovery_codes_remaining?: number }[]
		).find(({ kind }) => kind === "recovery_code");
		expect(set?.recovery_codes_remaining).toBe(4);
	});

	it("answers held again, with the same rebind_after, for a TOTP factor rebound before it, and released for one rebound after it", async () => {
		const setup = await composed();
		const rebindAfter = await hardHeld(setup, setup.totp, { withinTheMargin: true });
		await changePassword(setup);
		const agent = await signInWithCode(setup, 0);
		const early = await setup.factorStore.list(ALICE.id);
		await bindTotp(agent);
		await remove(agent, setup.totp.record.id);
		const tooSoon = (await setup.factorStore.list(ALICE.id)).find(
			(record) => record.kind === "totp" && !early.some(({ id }) => id === record.id),
		);
		if (tooSoon === undefined) throw new Error("no TOTP factor bound");
		expect(tooSoon.createdAt.getTime()).toBeLessThanOrEqual(Date.parse(rebindAfter));

		const held = await release(agent);
		expect(held.status, JSON.stringify(held.body)).toBe(200);
		expect(held.body).toMatchObject({ lock: "held", hold: "hard", rebind_after: rebindAfter });

		freezeClock(Date.parse(rebindAfter) + 1_000);
		await stepUpWithCode(setup, agent, 1);
		const again = await release(agent);
		expect(again.status, JSON.stringify(again.body)).toBe(200);
		expect(again.body).toMatchObject({ lock: "held", hold: "hard", rebind_after: rebindAfter });

		await stepUpWithCode(setup, agent, 2);
		await bindTotp(agent);
		await remove(agent, tooSoon.id);
		await stepUpWithCode(setup, agent, 3);
		const released = await release(agent);
		expect(released.status, JSON.stringify(released.body)).toBe(200);
		expect(released.body).toEqual({ lock: "released" });
	});

	it("lets a subject the hard hold stands for complete a TOTP enrollment: the binding reserves none of the subject's attempts", async () => {
		const setup = await composed();
		await hardHeld(setup, setup.totp);
		const agent = await signInWithCode(setup, 0);
		const reserve = vi.spyOn(setup.transactionStore, "reserveSubjectAttempt");

		await bindTotp(agent);

		expect(reserve).not.toHaveBeenCalled();
	});
});

describe("minting the authorization", () => {
	it("mints nothing for a TOTP step-up: the release is refused 403", async () => {
		const setup = await composed();
		const { agent } = await signInWithTotp(
			setup.app,
			setup.userSessionStore as UserSessionStore,
			setup.totp,
		);
		const authorize = vi.spyOn(setup.transactionStore, "authorizeSubjectRecovery");
		freezeClock(Date.now() + 31_000);
		const opened = await stepUp(agent);
		const res = await verify(
			agent,
			opened.body.transaction as string,
			setup.totp.record.id,
			totpCode(setup.totp.secret),
		);
		expect(res.status, JSON.stringify(res.body)).toBe(200);

		const refused = await release(agent);

		expect(authorize).not.toHaveBeenCalled();
		expect(refused.status, JSON.stringify(refused.body)).toBe(403);
		expect(refused.body).toEqual(EXEMPT_PROOF_REQUIRED);
	});

	it("mints for a recovery-code step-up, for the session it verified in", async () => {
		const setup = await composed();
		const { agent, sid } = await signInWithTotp(
			setup.app,
			setup.userSessionStore as UserSessionStore,
			setup.totp,
		);
		const authorize = vi.spyOn(setup.transactionStore, "authorizeSubjectRecovery");

		await stepUpWithCode(setup, agent, 0);

		expect(authorize).toHaveBeenCalledWith(
			ALICE.id,
			expect.objectContaining({ operation: "recover", sid }),
		);
		expect((await release(agent)).status).toBe(200);
	});

	it("leaves the login's 200 as it is when the authorization cannot be recorded, said once at warn", async () => {
		const setup = await composed();
		vi.spyOn(setup.transactionStore, "authorizeSubjectRecovery").mockRejectedValue(
			new Error("store down"),
		);

		const agent = await signInWithCode(setup, 0);

		expect(events(setup.logger, "warn")).toContain("mfa_lock_recovery_unauthorized");
		expect((await release(agent)).body).toEqual(EXEMPT_PROOF_REQUIRED);
	});
});

describe("the release's answers", () => {
	it("answers a second press what the first came to, audited once", async () => {
		const setup = await composed();
		const agent = await signInWithCode(setup, 0);

		const first = await release(agent);
		const again = await release(agent);

		expect(first.status, JSON.stringify(first.body)).toBe(200);
		expect(again.status, JSON.stringify(again.body)).toBe(200);
		expect(again.body).toEqual(first.body);
		expect(setup.audit.of("mfa.lock.recovered")).toHaveLength(1);
	});

	it("is 409 no_revocation_boundary where no sessions boundary is wired, said once at boot", async () => {
		const setup = await composed({ withoutBoundary: true });
		const { agent: attacker, transaction } = await beginLogin(setup.app);
		const failed = await verify(
			attacker,
			transaction,
			setup.totp.record.id,
			wrongCode(setup.totp.secret),
		);
		expect(failed.status, JSON.stringify(failed.body)).toBe(401);
		const agent = await signInWithCode(setup, 0);

		const refused = await release(agent);

		expect(refused.status, JSON.stringify(refused.body)).toBe(409);
		expect(refused.body).toEqual({
			error: "mfa_lock_release_refused",
			error_description:
				"This deployment cannot give the hold back early: wait for it to end, or ask for a reset",
			reason: "no_revocation_boundary",
		});
		expect(
			events(setup.logger, "warn").filter((event) => event === "mfa_lock_release_unavailable"),
		).toHaveLength(1);
	});

	it("is 409 no_revocation_boundary with rebind_after while the hard hold stands where no sessions boundary is wired: a rebind is the way out", async () => {
		const setup = await composed({ withoutBoundary: true });
		const rebindAfter = await hardHeld(setup, setup.totp);
		const agent = await signInWithCode(setup, 0);

		const refused = await release(agent);

		expect(refused.status, JSON.stringify(refused.body)).toBe(409);
		expect(refused.body).toEqual({
			error: "mfa_lock_release_refused",
			error_description:
				"Guessable second factors stay held until each is replaced after rebind_after: replace them, then release, or ask for a reset",
			reason: "no_revocation_boundary",
			rebind_after: rebindAfter,
		});
	});

	it("is 403 mfa_exempt_proof_required without rebind_after while the hard hold stands", async () => {
		const setup = await composed();
		await hardHeld(setup, setup.totp);
		vi.spyOn(setup.transactionStore, "authorizeSubjectRecovery").mockRejectedValue(
			new Error("store down"),
		);
		const agent = await signInWithCode(setup, 0);
		const apply = vi.spyOn(setup.transactionStore, "applySubjectRecovery");

		const refused = await release(agent);

		expect(await apply.mock.results[0]?.value).toMatchObject({
			outcome: "refused",
			hard: true,
		});
		expect(refused.status, JSON.stringify(refused.body)).toBe(403);
		expect(refused.body).toEqual(EXEMPT_PROOF_REQUIRED);
	});

	it("lifts the hard hold on a rebind alone where no sessions boundary is wired", async () => {
		const setup = await composed({ withoutBoundary: true });
		await hardHeld(setup, setup.totp);
		const agent = await signInWithCode(setup, 0);
		await bindTotp(agent);
		await remove(agent, setup.totp.record.id);

		const released = await release(agent);

		expect(released.status, JSON.stringify(released.body)).toBe(200);
		expect(released.body).toEqual({ lock: "released" });
	});

	it("sits behind the CSRF guard: a release without the token applies nothing", async () => {
		const setup = await composed();
		const agent = await signInWithCode(setup, 0);
		const apply = vi.spyOn(setup.transactionStore, "applySubjectRecovery");

		const res = await agent.post("/session/mfa/lock/release").send({});

		expect(res.status).toBe(403);
		expect(apply).not.toHaveBeenCalled();
	});

	it("is admitted as mfa.manage: a sign-in whose second factor is no longer recent is stepped up first, nothing applied", async () => {
		const setup = await composed();
		const agent = await signInWithCode(setup, 0);
		const apply = vi.spyOn(setup.transactionStore, "applySubjectRecovery");
		freezeClock(Date.now() + 301_000);

		const res = await release(agent);

		expect(res.status, JSON.stringify(res.body)).toBe(403);
		expect(res.body.error).toBe("step_up_required");
		expect(apply).not.toHaveBeenCalled();
	});

	it("answers 503, logged once at error, when the store cannot apply", async () => {
		const setup = await composed();
		const agent = await signInWithCode(setup, 0);
		vi.spyOn(setup.transactionStore, "applySubjectRecovery").mockRejectedValue(new Error("down"));

		const res = await release(agent);

		expect(res.status, JSON.stringify(res.body)).toBe(503);
		expect(events(setup.logger, "error")).toEqual(["mfa_store_unavailable"]);
	});

	it("says from when a rebind counts in the answer alone, never in a log line", async () => {
		const setup = await composed();
		const rebindAfter = await hardHeld(setup, setup.totp);
		const refused = await release(await signInWithCode(setup, 0));
		await changePassword(setup);
		const held = await release(await signInWithCode(setup, 1));

		expect(refused.body.rebind_after).toBe(rebindAfter);
		expect(held.body.rebind_after).toBe(rebindAfter);
		const logged = JSON.stringify(
			(["info", "warn", "error"] as const).flatMap((level) => setup.logger[level].mock.calls),
		);
		expect(logged).not.toContain(rebindAfter);
		expect(logged).not.toContain(String(Date.parse(rebindAfter)));
		const audited = JSON.stringify(setup.audit.events);
		expect(setup.audit.of("mfa.lock.recovered")).toHaveLength(1);
		expect(audited).not.toContain(rebindAfter);
		expect(audited).not.toContain(String(Date.parse(rebindAfter)));
	});

	it("answers 503, logged once at error without the instant, when the store's rebind bound is past what a date holds", async () => {
		const BEYOND = 8_640_000_000_000_001;
		const setup = await composed();
		await hardHeld(setup, setup.totp);
		await changePassword(setup);
		const agent = await signInWithCode(setup, 0);
		const apply = setup.transactionStore.applySubjectRecovery.bind(setup.transactionStore);
		vi.spyOn(setup.transactionStore, "applySubjectRecovery").mockImplementation(
			async (...args) => ({ ...(await apply(...args)), rebindAfterMs: BEYOND }) as never,
		);

		const res = await release(agent);

		expect(res.status, JSON.stringify(res.body)).toBe(503);
		expect(res.body).not.toHaveProperty("rebind_after");
		expect(events(setup.logger, "error")).toEqual(["mfa_store_unavailable"]);
		expect(JSON.stringify(setup.logger.error.mock.calls)).not.toContain(String(BEYOND));
	});

	it("answers 409 mfa_factors_busy with Retry-After while another write holds the subject's lease", async () => {
		const setup = await composed();
		const agent = await signInWithCode(setup, 0);
		await setup.transactionStore.acquireSubjectLease(ALICE.id, { ttlMs: 60_000, generation: 0 });

		const res = await release(agent);

		expect(res.status, JSON.stringify(res.body)).toBe(409);
		expect(res.body.error).toBe("mfa_factors_busy");
		expect(Number(res.headers["retry-after"])).toBeGreaterThanOrEqual(1);
	});
});

describe("the hard hold before an exempt proof", () => {
	it("answers a login's 429 mfa_locked with no time: neither rebind_after nor the instant in any form", async () => {
		const setup = await composed();
		const third = await wrongCodesToTheHardLimit(setup.app, setup.totp);
		const rebindAfterMs = Date.now() + DEFAULT_CLOCK_SKEW_MS;

		const held = await verify(
			third.agent,
			third.transaction,
			setup.totp.record.id,
			totpCode(setup.totp.secret),
		);

		expect(held.status, JSON.stringify(held.body)).toBe(429);
		expect(held.body).toMatchObject({ error: "mfa_locked", hold: "hard" });
		expect(held.body).not.toHaveProperty("rebind_after");
		expect(held.headers["retry-after"]).toBeUndefined();
		const body = JSON.stringify(held.body);
		expect(body).not.toContain(new Date(rebindAfterMs).toISOString());
		expect(body).not.toContain(String(rebindAfterMs));
	});
});

describe("a login that has not passed its second factor", () => {
	it("acquires no lease of the subject's while its codes fail", async () => {
		const setup = await composed();
		const acquire = vi.spyOn(setup.transactionStore, "acquireSubjectLease");

		await wrongCodesToTheHardLimit(setup.app, setup.totp);

		expect(acquire).not.toHaveBeenCalled();
	});
});
