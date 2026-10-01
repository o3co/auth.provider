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
 * The subject lock in the verify path (the MFA ADR's D21, F1 step 5): over
 * core's memory transaction store under an injected clock, the schedule a
 * guessable proof is held to, what an exempt proof does to it, and how a
 * verification settles the attempt it reserved — then, through the composed
 * application, what a verification spends of it.
 */

import {
	createMemoryMfaFactorStore,
	createMemoryMfaTransactionStore,
	type MfaFactor,
	type MfaFactorStore,
	type MfaLockoutPolicy,
	type MfaTransactionStore,
	OTP_AMR,
} from "@o3co/auth-provider-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createMfaSubjectLock, type MfaSubjectLock } from "#/lock.mjs";
import { mfaConfigForTests } from "#/testing/index.mjs";
import { boot, configFor, disposeAll, events, MFA_KEY } from "./moduleHarness.mjs";
import {
	beginLogin,
	contributing,
	freezeClock,
	seedFactor,
	seedTotp,
	thawClock,
	totpCode,
	verify,
	wrongCode,
} from "./routesHarness.mjs";

const SUBJECT = "u-alice";
const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
const WEEK = 7 * DAY;

/** A TOTP code's factor, as the lock sees one: held to it. */
const GUESSABLE = { kind: "totp", guessable: true } as const;
/** A recovery code's, or a WebAuthn assertion's: exempt. */
const EXEMPT = { kind: "recovery_code", guessable: false } as const;

/** `mfa.lockout` as the MFA module's builder lays `lockout` over the reference defaults. */
const policyOf = (lockout: Partial<MfaLockoutPolicy> = {}): MfaLockoutPolicy =>
	mfaConfigForTests({ key: MFA_KEY, lockout }).mfa.lockout;

/** The lock as a verification at the suite's clock uses it: each attempt at the time it is made. */
interface TimedLock {
	enter(
		subject: string,
		factor: Pick<MfaFactor, "kind" | "guessable">,
	): ReturnType<MfaSubjectLock["enter"]>;
}

/** The lock over core's memory store, the store and every verification on one injected clock. */
function lockOver(
	lockout: Partial<MfaLockoutPolicy> = {},
	wrap: (store: MfaTransactionStore) => MfaTransactionStore = (store) => store,
) {
	let clock = 1_900_000_000_000;
	const store = wrap(createMemoryMfaTransactionStore({ now: () => clock }));
	const unsettled = vi.fn();
	const untimed = createMfaSubjectLock({ store, policy: policyOf(lockout), unsettled });
	const lock: TimedLock = { enter: (subject, factor) => untimed.enter(subject, factor, clock) };
	return {
		store,
		lock,
		unsettled,
		advance: (ms: number) => {
			clock += ms;
		},
	};
}

/** One guessable attempt let through and settled `outcome`. */
async function settled(
	lock: TimedLock,
	outcome: "failure" | "success" | "void",
	factor: { readonly kind: string; readonly guessable: boolean } = GUESSABLE,
): Promise<void> {
	const entered = await lock.enter(SUBJECT, factor);
	expect(entered.outcome).toBe("entered");
	if (entered.outcome === "entered") await entered.settle(outcome);
}

describe("the schedule a guessable proof is held to", () => {
	it("holds the subject for 15 minutes from the 5th consecutive failure, doubling with each further one up to the maximum", async () => {
		const { lock, advance } = lockOver({ weeklyBudget: 100 });
		for (let n = 0; n < 5; n++) await settled(lock, "failure");

		const holds: (number | null)[] = [];
		for (;;) {
			const refused = await lock.enter(SUBJECT, GUESSABLE);
			if (refused.outcome !== "locked") throw new Error(`not held: ${refused.outcome}`);
			expect(refused.hold).toBe("backoff");
			holds.push(refused.retryAfterMs);
			if (holds.length === 9) break;
			advance(refused.retryAfterMs as number);
			await settled(lock, "failure");
		}

		expect(holds).toEqual(
			[900, 1800, 3600, 7200, 14_400, 28_800, 57_600, 86_400, 86_400].map((s) => s * 1000),
		);
	});

	it("holds the subject weekly past ten failures in any seven days, until the oldest leaves the window", async () => {
		const { lock, advance } = lockOver({ threshold: 100 });
		for (let n = 0; n < 10; n++) {
			await settled(lock, "failure");
			advance(HOUR);
		}

		const refused = await lock.enter(SUBJECT, GUESSABLE);

		expect(refused).toMatchObject({ outcome: "locked", hold: "weekly" });
		const retryAfterMs = refused.outcome === "locked" ? (refused.retryAfterMs as number) : 0;
		expect(retryAfterMs).toBe(WEEK - 10 * HOUR);
		advance(retryAfterMs);
		expect((await lock.enter(SUBJECT, GUESSABLE)).outcome).toBe("entered");
	});

	it("holds the subject at the hard limit with no time to come back, however long it waits", async () => {
		const { lock, advance } = lockOver({ threshold: 3, hardLimit: 3 });
		for (let n = 0; n < 3; n++) await settled(lock, "failure");

		expect(await lock.enter(SUBJECT, GUESSABLE)).toEqual({
			outcome: "locked",
			hold: "hard",
			retryAfterMs: null,
			first: true,
		});
		advance(30 * DAY);
		expect(await lock.enter(SUBJECT, GUESSABLE)).toMatchObject({
			hold: "hard",
			retryAfterMs: null,
		});
	});

	it("refunds no weekly failure for the victim's own successes", async () => {
		const { lock } = lockOver({ threshold: 100, weeklyBudget: 3 });
		await settled(lock, "failure");
		await settled(lock, "success");
		await settled(lock, "failure");
		await settled(lock, "success");
		await settled(lock, "failure");

		expect(await lock.enter(SUBJECT, GUESSABLE)).toMatchObject({
			outcome: "locked",
			hold: "weekly",
		});
	});

	it("says the first refusal of an episode alone is first, and a new episode once an attempt was let through", async () => {
		const { lock, advance } = lockOver({ threshold: 2, weeklyBudget: 100 });
		await settled(lock, "failure");
		await settled(lock, "failure");

		const first = await lock.enter(SUBJECT, GUESSABLE);
		const second = await lock.enter(SUBJECT, GUESSABLE);
		advance(first.outcome === "locked" ? (first.retryAfterMs as number) : 0);
		await settled(lock, "failure");
		const next = await lock.enter(SUBJECT, GUESSABLE);

		expect(
			[first, second, next].map((refused) => refused.outcome === "locked" && refused.first),
		).toEqual([true, false, true]);
	});
});

describe("an exempt proof", () => {
	it("passes during every hold and reserves nothing", async () => {
		const { lock, store } = lockOver({ threshold: 3, hardLimit: 3 });
		for (let n = 0; n < 3; n++) await settled(lock, "failure");
		const reserve = vi.spyOn(store, "reserveSubjectAttempt");

		expect((await lock.enter(SUBJECT, EXEMPT)).outcome).toBe("entered");
		expect(reserve).not.toHaveBeenCalled();
	});

	it("ends the run and a hard hold once it succeeds, and refunds nothing of the week", async () => {
		const { lock } = lockOver({ threshold: 3, hardLimit: 3, weeklyBudget: 4 });
		for (let n = 0; n < 3; n++) await settled(lock, "failure");
		expect(await lock.enter(SUBJECT, GUESSABLE)).toMatchObject({ hold: "hard" });

		await settled(lock, "success", EXEMPT);

		await settled(lock, "failure");
		expect(await lock.enter(SUBJECT, GUESSABLE)).toMatchObject({ hold: "weekly" });
	});

	it("dates its success by its verification's time: an attempt reserved after that stays in the run", async () => {
		const { lock, advance } = lockOver({ threshold: 3, hardLimit: 3 });
		await settled(lock, "failure");
		await settled(lock, "failure");
		advance(1000);
		const exempt = await lock.enter(SUBJECT, EXEMPT);
		if (exempt.outcome !== "entered") throw new Error("not entered");
		advance(1000);
		await settled(lock, "failure");
		advance(1000);

		await exempt.settle("success");

		// The run holds the failure reserved after the exempt proof's time, and two more make it three.
		await settled(lock, "failure");
		await settled(lock, "failure");
		expect(await lock.enter(SUBJECT, GUESSABLE)).toMatchObject({ hold: "hard" });
	});

	it("records an exempt success only for a success: a refusal or a void leaves the run as it was", async () => {
		const { lock, store } = lockOver({ threshold: 3, hardLimit: 3 });
		for (let n = 0; n < 3; n++) await settled(lock, "failure");
		const note = vi.spyOn(store, "noteExemptSuccess");

		await settled(lock, "failure", EXEMPT);
		await settled(lock, "void", EXEMPT);

		expect(note).not.toHaveBeenCalled();
		expect(await lock.enter(SUBJECT, GUESSABLE)).toMatchObject({ hold: "hard" });
	});
});

describe("settling", () => {
	it("removes a void attempt: a right proof whose write was lost never counts", async () => {
		const { lock } = lockOver({ threshold: 2, weeklyBudget: 2 });
		for (let n = 0; n < 6; n++) await settled(lock, "void");

		expect((await lock.enter(SUBJECT, GUESSABLE)).outcome).toBe("entered");
	});

	it("settles an attempt once, whatever is asked after", async () => {
		const { lock, store } = lockOver();
		const settle = vi.spyOn(store, "settleSubjectAttempt");
		const entered = await lock.enter(SUBJECT, GUESSABLE);
		if (entered.outcome !== "entered") throw new Error("not entered");

		await entered.settle("failure");
		await entered.settle("success");

		expect(settle).toHaveBeenCalledTimes(1);
		expect(settle.mock.calls[0]?.[2]).toBe("failure");
	});

	it("never throws: a settle or an exempt success the store does not take is reported once, and the failure stands", async () => {
		const down = new Error("store unreachable");
		const { lock, unsettled } = lockOver({ threshold: 1 }, (store) => ({
			...store,
			settleSubjectAttempt: async () => {
				throw down;
			},
			noteExemptSuccess: async () => {
				throw down;
			},
		}));

		await settled(lock, "success");
		await settled(lock, "success", EXEMPT);

		expect(unsettled.mock.calls).toEqual([
			[
				{
					subject: SUBJECT,
					kind: "totp",
					step: "settleSubjectAttempt",
					outcome: "success",
					cause: down,
				},
			],
			[
				{
					subject: SUBJECT,
					kind: "recovery_code",
					step: "noteExemptSuccess",
					outcome: "success",
					cause: down,
				},
			],
		]);
		// Unsettled, the attempt still counts as a failure.
		expect(await lock.enter(SUBJECT, GUESSABLE)).toMatchObject({ outcome: "locked" });
	});
});

describe("the reservation", () => {
	it("holds a factor that does not say it is exempt", async () => {
		const { lock, store } = lockOver();
		const reserve = vi.spyOn(store, "reserveSubjectAttempt");

		await lock.enter(SUBJECT, { kind: "custom" } as unknown as MfaFactor);

		expect(reserve).toHaveBeenCalledTimes(1);
	});

	it("is an outage, never a pass, when the store cannot answer", async () => {
		const down = new Error("store unreachable");
		const { lock } = lockOver({}, (store) => ({
			...store,
			reserveSubjectAttempt: async () => {
				throw down;
			},
		}));

		expect(await lock.enter(SUBJECT, GUESSABLE)).toEqual({
			outcome: "unavailable",
			store: "mfa_transaction",
			step: "reserveSubjectAttempt",
			cause: down,
		});
	});

	it.each([
		["nothing", undefined],
		["a pass without its reservation", { ok: true }],
		["a pass with an empty reservation", { ok: true, reservation: "" }],
		["a hold it does not name", { ok: false, hold: "forever", retryAfterMs: 1, first: true }],
		[
			"a hard hold with a time to come back",
			{ ok: false, hold: "hard", retryAfterMs: 1, first: true },
		],
		["a backoff with none", { ok: false, hold: "backoff", retryAfterMs: null, first: true }],
		["a weekly hold already over", { ok: false, hold: "weekly", retryAfterMs: 0, first: true }],
		["a time that is no number", { ok: false, hold: "weekly", retryAfterMs: "1", first: true }],
		[
			"a refusal that does not say whether it is first",
			{ ok: false, hold: "hard", retryAfterMs: null },
		],
	])("is an outage, never a pass or a hold, when the store answers %s", async (_, answer) => {
		const { lock } = lockOver({}, (store) => ({
			...store,
			reserveSubjectAttempt: async () => answer as never,
		}));

		expect(await lock.enter(SUBJECT, GUESSABLE)).toMatchObject({
			outcome: "unavailable",
			store: "mfa_transaction",
			step: "reserveSubjectAttempt",
		});
	});
});

describe("a verification's attempt, through the routes", () => {
	beforeEach(() => freezeClock());
	afterEach(async () => {
		await disposeAll();
		thawClock();
	});

	it("spends N of the subject's attempts on N wrong TOTP codes sent at once", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const { record, secret } = await seedTotp(factorStore);
		const { app } = await boot({
			config: configFor("required", { lockout: { threshold: 3 } }),
			factorStore,
		});
		const first = await beginLogin(app);

		const answers = await Promise.all(
			Array.from({ length: 3 }, () =>
				verify(first.agent, first.transaction, record.id, wrongCode(secret)),
			),
		);
		expect(answers.map((res) => res.status)).toEqual([401, 401, 401]);

		const next = await beginLogin(app);
		const res = await verify(next.agent, next.transaction, record.id, totpCode(secret));
		expect(res.status, JSON.stringify(res.body)).toBe(429);
		expect(res.body).toMatchObject({ error: "mfa_locked", hold: "backoff" });
	});

	it("settles a right code whose factor write was lost, or failed, as void: neither a failure nor a success, the run going on", async () => {
		const memory = createMemoryMfaFactorStore();
		const { record, secret } = await seedTotp(memory);
		let write: "lost" | "down" | "as stored" = "lost";
		const factorStore: MfaFactorStore = {
			...memory,
			list: (subject) => memory.list(subject),
			update: async (...args) => {
				if (write === "lost") return null;
				if (write === "down") throw new Error("factor store unreachable");
				return memory.update(...args);
			},
		};
		const { app } = await boot({
			config: configFor("required", { lockout: { threshold: 2 } }),
			factorStore,
		});
		const wrong = async () => {
			const { agent, transaction } = await beginLogin(app);
			expect((await verify(agent, transaction, record.id, wrongCode(secret))).status).toBe(401);
		};
		await wrong();
		// Counted as failures, the second of these would be held; as successes, they would end the run.
		for (const how of ["lost", "down", "lost", "down"] as const) {
			write = how;
			const { agent, transaction } = await beginLogin(app);
			expect((await verify(agent, transaction, record.id, totpCode(secret))).status).toBe(503);
		}
		write = "as stored";
		await wrong();

		const { agent, transaction } = await beginLogin(app);
		const res = await verify(agent, transaction, record.id, totpCode(secret));
		expect(res.status, JSON.stringify(res.body)).toBe(429);
	});

	it("keeps a factor that throws a failure: a proof crafted to make it throw buys no free guess", async () => {
		const factorStore = createMemoryMfaFactorStore();
		await seedTotp(factorStore);
		const throwing: MfaFactor = {
			kind: "probe",
			amrValues: [OTP_AMR],
			amrFor: () => [OTP_AMR],
			addsMfa: true,
			counting: true,
			guessable: true,
			describe: () => ({}),
			verify: async () => {
				throw new Error("the factor could not read the proof");
			},
			beginEnrollment: async () => {
				throw new Error("not enrolled here");
			},
			completeEnrollment: async () => {
				throw new Error("not enrolled here");
			},
		};
		const probe = await seedFactor(factorStore, "probe", {});
		const { app, logger } = await boot({
			config: configFor("required", { lockout: { threshold: 2 } }),
			factorStore,
			extraModules: [contributing(throwing)],
		});
		for (let n = 0; n < 2; n++) {
			const { agent, transaction } = await beginLogin(app);
			expect((await verify(agent, transaction, probe.id, "crafted")).status).toBe(503);
		}

		const { agent, transaction } = await beginLogin(app);
		const res = await verify(agent, transaction, probe.id, "crafted");
		expect(res.status).toBe(429);
		expect(events(logger, "error")).toEqual(["mfa_factor_unreadable", "mfa_factor_unreadable"]);
	});
});
