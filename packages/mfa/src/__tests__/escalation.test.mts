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
 * The session's escalation (`escalation.mts`) against a recording
 * `loginCompletion` and a session-store double: each of its seven outcomes,
 * what it renewed, recorded and deleted on the way, what it logged, and
 * what a step-up answers it.
 */

import {
	type CsrfGuard,
	type LoginCompletion,
	newRenewalNonce,
	type SessionRenewalCall,
	type SessionRenewalResult,
	type SupportsSecondFactorUpdate,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import type { Request, Response } from "express";
import { describe, expect, it, vi } from "vitest";
import { OUTSIDE_CONTRACT } from "#/ceremony.mjs";
import { createSessionEscalation, ESCALATION_REFUSALS, type Escalation } from "#/escalation.mjs";
import { events, spyLogger } from "./moduleHarness.mjs";

const SESSION = { sid: "sid-alice", sub: "u-alice" } as const;
const EXPECTED = newRenewalNonce();
const ADDS = { amr: ["otp"], mfaAt: new Date(1_800_000_000_000) } as const;
const REACH: ReadonlySet<string> = new Set(["otp", "hwk"]);

const LOGIN_REQUIRED = { error: "login_required", error_description: "Log in again" };
const SESSION_STORE_UNAVAILABLE = {
	error: "temporarily_unavailable",
	error_description: "Session store unavailable",
};
const SESSION_NOT_SECURED = {
	error: "server_error",
	error_description: "The session could not be secured: sign in again",
};
const STEP_UP_UNRECORDED = {
	error: "server_error",
	error_description: "The step-up could not be recorded",
};

/** A `loginCompletion` whose renewal answers `renewal`, recording each call; it establishes nothing. */
const recordingLoginCompletion = (renewal: () => Promise<SessionRenewalResult>) => {
	const renewals: SessionRenewalCall[] = [];
	const completion: LoginCompletion = {
		establishSession: async () => {
			throw new Error("an escalation establishes no session");
		},
		answerInterruption: async () => {
			throw new Error("an escalation answers no interruption");
		},
		renewSession: async (call) => {
			renewals.push(call);
			return renewal();
		},
	};
	return { completion, renewals };
};

/** A session store whose `recordSecondFactor` answers `record`; `delete` records its ids, or rejects with `deleteFails`. */
const storeDouble = (record: () => Promise<unknown>, deleteFails?: Error) => {
	const recordSecondFactor = vi.fn(async (_sid: string, _event: unknown) => record());
	const deleted: string[] = [];
	const store = {
		recordSecondFactor,
		delete: async (sid: string) => {
			if (deleteFails !== undefined) throw deleteFails;
			deleted.push(sid);
		},
	} as unknown as UserSessionStore & SupportsSecondFactorUpdate;
	return { store, recordSecondFactor, deleted };
};

/** What the store answers for {@link SESSION} recorded with `renewalNonce`. */
const recordOf = (renewalNonce: string | undefined) => ({
	...SESSION,
	authTime: new Date(1_799_999_000_000),
	expiresAt: new Date(1_800_003_600_000),
	...(renewalNonce === undefined ? {} : { renewalNonce }),
});

const responseDouble = () => {
	const res = { status: vi.fn(), json: vi.fn() };
	res.status.mockReturnValue(res);
	return res;
};

interface Rig {
	readonly renewal?: () => Promise<SessionRenewalResult>;
	readonly record?: (renewalNonce: string) => Promise<unknown>;
	readonly deleteFails?: Error;
	readonly noStore?: boolean;
	readonly reach?: ReadonlySet<string> | undefined;
	readonly adds?: { readonly amr: readonly string[]; readonly mfaAt: Date };
}

/** One escalation of {@link SESSION} by `adds` over the doubles `rig` names, and everything it touched. */
const escalate = async (rig: Rig = {}) => {
	const renewalNonce = newRenewalNonce();
	const { completion, renewals } = recordingLoginCompletion(
		rig.renewal ?? (async () => ({ outcome: "renewed", renewalNonce })),
	);
	const double = storeDouble(
		() => (rig.record ?? (async (nonce) => recordOf(nonce)))(renewalNonce),
		rig.deleteFails,
	);
	const logger = spyLogger();
	const issued: unknown[] = [];
	const csrfGuard = { issue: (res: Response) => issued.push(res) } as unknown as CsrfGuard;
	const storeUnavailable = vi.fn();
	const reach = "reach" in rig ? rig.reach : REACH;
	const escalation = createSessionEscalation({
		secondFactorStore: rig.noStore === true ? undefined : double.store,
		loginCompletion: completion,
		reach: () => reach,
		csrfGuard,
		logger,
		storeUnavailable,
	});
	const req = {} as Request;
	const res = responseDouble();
	const outcome = await escalation.escalate(
		"step-up",
		req,
		res as unknown as Response,
		SESSION,
		EXPECTED,
		rig.adds ?? ADDS,
	);
	const answered = responseDouble();
	escalation.answer(answered as unknown as Response, outcome, { step_up: "verified" });
	return {
		outcome,
		renewalNonce,
		renewals,
		req,
		res,
		answered,
		recorded: double.recordSecondFactor.mock.calls,
		deleted: double.deleted,
		issued,
		logger,
		storeUnavailable,
	};
};

describe("createSessionEscalation", () => {
	it("escalated: renews, records once with the renewal and expected nonces, issues a CSRF token, answers 200", async () => {
		const run = await escalate();
		expect(run.outcome).toBe<Escalation>("escalated");
		expect(run.renewals).toHaveLength(1);
		expect(run.renewals[0]?.req).toBe(run.req);
		expect(run.recorded).toEqual([
			[
				SESSION.sid,
				{
					amr: ADDS.amr,
					at: ADDS.mfaAt,
					renewalNonce: run.renewalNonce,
					expectedRenewalNonce: EXPECTED,
				},
			],
		]);
		expect(run.issued).toEqual([run.res]);
		expect(run.deleted).toEqual([]);
		expect(run.answered.status).toHaveBeenCalledWith(200);
		expect(run.answered.json).toHaveBeenCalledWith({ step_up: "verified" });
	});

	it("the renewal's store outage is reported for the session", async () => {
		const cause = new Error("cookie store down");
		const { completion } = recordingLoginCompletion(async () => ({
			outcome: "renewed",
			renewalNonce: newRenewalNonce(),
		}));
		const storeUnavailable = vi.fn();
		const escalation = createSessionEscalation({
			secondFactorStore: storeDouble(async () => null).store,
			loginCompletion: {
				...completion,
				renewSession: async (call) => {
					call.reporter.storeUnavailable("cookie_session", "save", cause);
					return { outcome: "unavailable", store: "cookie_session", step: "save" };
				},
			},
			reach: () => REACH,
			csrfGuard: { issue: () => {} } as unknown as CsrfGuard,
			logger: spyLogger(),
			storeUnavailable,
		});
		await escalation.escalate(
			"verify",
			{} as Request,
			responseDouble() as unknown as Response,
			SESSION,
			EXPECTED,
			ADDS,
		);
		expect(storeUnavailable).toHaveBeenCalledWith("verify", "cookie_session", "save", cause, {
			sid: SESSION.sid,
		});
	});

	it("unrecordable_store: no step-up capability renews nothing, answers 401 login_required", async () => {
		const run = await escalate({ noStore: true });
		expect(run.outcome).toBe<Escalation>("unrecordable_store");
		expect(run.renewals).toEqual([]);
		expect(run.issued).toEqual([]);
		expect(run.answered.status).toHaveBeenCalledWith(401);
		expect(run.answered.json).toHaveBeenCalledWith(LOGIN_REQUIRED);
	});

	describe("invalid", () => {
		it("adds outside the requirement's reach renews nothing, logged, answers 500", async () => {
			const run = await escalate({ adds: { amr: ["otp", "swk"], mfaAt: ADDS.mfaAt } });
			expect(run.outcome).toBe<Escalation>("invalid");
			expect(run.renewals).toEqual([]);
			expect(run.recorded).toEqual([]);
			expect(events(run.logger, "error")).toEqual(["mfa_escalation_invalid"]);
			expect(run.answered.status).toHaveBeenCalledWith(500);
			expect(run.answered.json).toHaveBeenCalledWith(STEP_UP_UNRECORDED);
		});

		it("no mfa requirement registered renews nothing", async () => {
			const run = await escalate({ reach: undefined });
			expect(run.outcome).toBe<Escalation>("invalid");
			expect(run.renewals).toEqual([]);
		});

		it("a RangeError from the record is invalid, recorded once, logged", async () => {
			const run = await escalate({
				record: async () => {
					throw new RangeError("recordSecondFactor: at is ahead of the clock");
				},
			});
			expect(run.outcome).toBe<Escalation>("invalid");
			expect(run.recorded).toHaveLength(1);
			expect(events(run.logger, "error")).toEqual(["mfa_escalation_invalid"]);
			expect(run.storeUnavailable).not.toHaveBeenCalled();
			expect(run.issued).toEqual([]);
		});
	});

	describe("not_renewed", () => {
		it("a renewal that fails records nothing, answers 503", async () => {
			const run = await escalate({
				renewal: async () => ({ outcome: "unavailable", store: "cookie_session", step: "save" }),
			});
			expect(run.outcome).toBe<Escalation>("not_renewed");
			expect(run.recorded).toEqual([]);
			expect(run.answered.status).toHaveBeenCalledWith(503);
			expect(run.answered.json).toHaveBeenCalledWith(SESSION_STORE_UNAVAILABLE);
		});

		it("a renewal answering no renewal nonce is an outage outside the contract, nothing recorded", async () => {
			const run = await escalate({
				renewal: async () => ({ outcome: "renewed", renewalNonce: "not-a-nonce" }),
			});
			expect(run.outcome).toBe<Escalation>("not_renewed");
			expect(run.recorded).toEqual([]);
			expect(run.storeUnavailable).toHaveBeenCalledWith(
				"step-up",
				"cookie_session",
				"renewSession",
				OUTSIDE_CONTRACT,
				{ sid: SESSION.sid },
			);
		});
	});

	it("not_recorded: a null record is logged at info, nothing deleted, answers 401", async () => {
		const run = await escalate({ record: async () => null });
		expect(run.outcome).toBe<Escalation>("not_recorded");
		expect(run.recorded).toHaveLength(1);
		expect(events(run.logger, "info")).toEqual(["mfa_escalation_not_recorded"]);
		expect(run.deleted).toEqual([]);
		expect(run.issued).toEqual([]);
		expect(run.answered.status).toHaveBeenCalledWith(401);
		expect(run.answered.json).toHaveBeenCalledWith(LOGIN_REQUIRED);
	});

	describe("unbound", () => {
		it("a record without the renewal's nonce ends the session, answers 500", async () => {
			const run = await escalate({ record: async () => recordOf(newRenewalNonce()) });
			expect(run.outcome).toBe<Escalation>("unbound");
			expect(events(run.logger, "error")).toEqual(["mfa_escalation_unbound"]);
			expect(run.deleted).toEqual([SESSION.sid]);
			expect(run.issued).toEqual([]);
			expect(run.answered.status).toHaveBeenCalledWith(500);
			expect(run.answered.json).toHaveBeenCalledWith(SESSION_NOT_SECURED);
		});

		it("a delete that fails is reported, still unbound", async () => {
			const cause = new Error("session store down");
			const run = await escalate({ record: async () => recordOf(undefined), deleteFails: cause });
			expect(run.outcome).toBe<Escalation>("unbound");
			expect(run.storeUnavailable).toHaveBeenCalledWith(
				"step-up",
				"user_session",
				"delete",
				cause,
				{
					sid: SESSION.sid,
				},
			);
		});
	});

	describe("unavailable", () => {
		it("a record that rejects is reported once, never retried, answers 503", async () => {
			const cause = new Error("session store down");
			const run = await escalate({
				record: async () => {
					throw cause;
				},
			});
			expect(run.outcome).toBe<Escalation>("unavailable");
			expect(run.recorded).toHaveLength(1);
			expect(run.storeUnavailable).toHaveBeenCalledWith(
				"step-up",
				"user_session",
				"recordSecondFactor",
				cause,
				{ sid: SESSION.sid },
			);
			expect(run.deleted).toEqual([]);
			expect(run.issued).toEqual([]);
			expect(run.answered.status).toHaveBeenCalledWith(503);
			expect(run.answered.json).toHaveBeenCalledWith(SESSION_STORE_UNAVAILABLE);
		});

		it.each<[string, (nonce: string) => unknown]>([
			["another session's", (nonce) => ({ ...recordOf(nonce), sid: "sid-mallory" })],
			["another subject's", (nonce) => ({ ...recordOf(nonce), sub: "u-mallory" })],
			["not an object", (nonce) => nonce],
			["an array", (nonce) => [recordOf(nonce)]],
			["without authTime", (nonce) => ({ ...recordOf(nonce), authTime: undefined })],
			["with an expiresAt that is no Date", (nonce) => ({ ...recordOf(nonce), expiresAt: 0 })],
		])("a record that is %s is an outage outside the contract", async (_, answer) => {
			const run = await escalate({ record: async (nonce) => answer(nonce) });
			expect(run.outcome).toBe<Escalation>("unavailable");
			expect(run.storeUnavailable).toHaveBeenCalledWith(
				"step-up",
				"user_session",
				"recordSecondFactor",
				OUTSIDE_CONTRACT,
				{ sid: SESSION.sid },
			);
			expect(run.deleted).toEqual([]);
			expect(run.issued).toEqual([]);
		});
	});

	it("reads the requirement's reach at each escalation, never at construction", async () => {
		const reaches: (ReadonlySet<string> | undefined)[] = [undefined, REACH];
		const reach = vi.fn(() => reaches.shift());
		const options = {
			loginCompletion: recordingLoginCompletion(async () => ({
				outcome: "renewed",
				renewalNonce: newRenewalNonce(),
			})).completion,
			reach,
			csrfGuard: { issue: () => {} } as unknown as CsrfGuard,
			logger: spyLogger(),
			storeUnavailable: vi.fn(),
		};
		const unrecordable = createSessionEscalation({ ...options, secondFactorStore: undefined });
		const escalation = createSessionEscalation({
			...options,
			secondFactorStore: storeDouble(async () => recordOf(undefined)).store,
		});
		expect(reach).not.toHaveBeenCalled();
		const call = (over: typeof escalation) =>
			over.escalate(
				"verify",
				{} as Request,
				responseDouble() as unknown as Response,
				SESSION,
				EXPECTED,
				ADDS,
			);
		expect(await call(unrecordable)).toBe<Escalation>("unrecordable_store");
		expect(reach).not.toHaveBeenCalled();
		expect(await call(escalation)).toBe<Escalation>("invalid");
		// The reach registered since is the one the next escalation holds to.
		expect(await call(escalation)).toBe<Escalation>("unbound");
		expect(reach).toHaveBeenCalledTimes(2);
	});

	it("records only once renewed, and issues the CSRF token only once recorded", async () => {
		const renewalNonce = newRenewalNonce();
		let renew: (result: SessionRenewalResult) => void = () => {};
		let record: (answer: unknown) => void = () => {};
		const { completion } = recordingLoginCompletion(
			() =>
				new Promise<SessionRenewalResult>((resolve) => {
					renew = resolve;
				}),
		);
		const double = storeDouble(
			() =>
				new Promise<unknown>((resolve) => {
					record = resolve;
				}),
		);
		const issued: unknown[] = [];
		const escalation = createSessionEscalation({
			secondFactorStore: double.store,
			loginCompletion: completion,
			reach: () => REACH,
			csrfGuard: { issue: (res: Response) => issued.push(res) } as unknown as CsrfGuard,
			logger: spyLogger(),
			storeUnavailable: vi.fn(),
		});
		const res = responseDouble() as unknown as Response;
		const outcome = escalation.escalate("step-up", {} as Request, res, SESSION, EXPECTED, ADDS);
		await new Promise((resolve) => setImmediate(resolve));
		expect(double.recordSecondFactor).not.toHaveBeenCalled();
		renew({ outcome: "renewed", renewalNonce });
		await new Promise((resolve) => setImmediate(resolve));
		expect(double.recordSecondFactor).toHaveBeenCalledTimes(1);
		expect(issued).toEqual([]);
		record(recordOf(renewalNonce));
		expect(await outcome).toBe<Escalation>("escalated");
		expect(issued).toEqual([res]);
	});

	it("ESCALATION_REFUSALS answers every outcome but escalated", () => {
		expect(Object.keys(ESCALATION_REFUSALS).sort()).toEqual([
			"invalid",
			"not_recorded",
			"not_renewed",
			"unavailable",
			"unbound",
			"unrecordable_store",
		]);
	});
});
