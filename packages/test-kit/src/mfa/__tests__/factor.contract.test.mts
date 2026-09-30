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
 * The conformance suite every contributed second factor runs, against core's
 * factor double, with and without a challenge; each way a factor can break
 * the contract fails the case that names it.
 */

import type { MfaFactor } from "@o3co/auth-provider-core";
import {
	createTestMfaFactor,
	type TestMfaFactorOptions,
	testMfaFactorProofs,
} from "@o3co/auth-provider-core/testing";
import { describe, expect, it } from "vitest";
import { type MfaFactorContractInput, mfaFactorContract } from "#/index.mjs";

const RULES = {
	kind: "kind is a hint token: a lowercase letter, then up to 63 lowercase letters, digits, _ or -",
	amrValues:
		"amrValues is a non-empty list of distinct non-empty strings, with no primary's marker and no mfa",
	flags:
		"addsMfa, counting and guessable are true or false, and reusableChallenge true, false or absent",
	enrollable: "enrollable, when present, answers true for an account that can enroll the factor",
	begin: "beginEnrollment answers state that survives a JSON round trip",
	completeMalformed:
		"completeEnrollment answers malformed for a proof it cannot read, and never throws for one",
	complete:
		"completeEnrollment takes the proof of possession, and answers data that survives a JSON round trip, a label that is a string when present, and at least one amr value, each among amrValues",
	describe: "describe answers a hint that is a string, or none, and never the account's address",
	challenge: "challenge, when present, answers state that survives a JSON round trip",
	verifyMalformed: "verify answers malformed for a proof it cannot read, and never throws for one",
	verify:
		"verify takes a valid proof, names a factor the subject holds, and answers next data that survives a JSON round trip",
} as const;

const USER = { id: "u-contract", username: "contract", email: "contract@example.com" };

/** The input that runs the suite over the double built with `options`, changed by `change`. */
const inputFor = (
	options: TestMfaFactorOptions = {},
	change: (factor: MfaFactor) => MfaFactor = (factor) => factor,
): MfaFactorContractInput => ({
	build: () => change(createTestMfaFactor(options)),
	user: USER,
	...testMfaFactorProofs,
});

/** The names of the cases the factors `input` builds fail. */
const failing = async (input: MfaFactorContractInput): Promise<string[]> => {
	const failed: string[] = [];
	for (const { name, run } of mfaFactorContract(input)) {
		try {
			await run();
		} catch {
			failed.push(name);
		}
	}
	return failed;
};

describe("mfaFactorContract", () => {
	it("names every rule it holds a factor to", () => {
		expect(mfaFactorContract(inputFor()).map((c) => c.name)).toEqual(Object.values(RULES));
	});

	it("passes the double, with and without a challenge", async () => {
		expect(await failing(inputFor())).toEqual([]);
		expect(await failing(inputFor({ challenge: true }))).toEqual([]);
		expect(await failing(inputFor({ kind: "test_2", amrValues: ["hwk", "swk"] }))).toEqual([]);
	});

	it("passes a factor that holds every call to the account's id as its subject, enrollment and verification alike", async () => {
		const bound = (factor: MfaFactor): MfaFactor => ({
			...factor,
			beginEnrollment: async (ctx) => {
				if (ctx.subject !== ctx.user.id) throw new Error("the ceremony is not the account's");
				return factor.beginEnrollment(ctx);
			},
			completeEnrollment: async (ctx) => {
				if (ctx.subject !== ctx.user.id) return { ok: false, reason: "invalid" };
				const done = await factor.completeEnrollment(ctx);
				return done.ok ? { ...done, data: { ...done.data, subject: ctx.subject } } : done;
			},
			verify: async (ctx) =>
				ctx.subject === ctx.factor.data.subject
					? factor.verify(ctx)
					: { ok: false, reason: "invalid" },
		});
		expect(await failing(inputFor({}, bound))).toEqual([]);
		expect(await failing(inputFor({ challenge: true }, bound))).toEqual([]);
		expect(await failing({ ...inputFor({}, bound), user: { ...USER, id: "u-another" } })).toEqual(
			[],
		);
	});

	it("passes a factor whose state and data are objects with no prototype, as the coordinator's sealing takes them", async () => {
		const bare = <T extends object>(value: T): T => Object.assign(Object.create(null), value);
		expect(
			await failing(
				inputFor({ challenge: true }, (factor) => ({
					...factor,
					beginEnrollment: async (ctx) => {
						const start = await factor.beginEnrollment(ctx);
						return { ...start, state: bare(start.state) };
					},
					completeEnrollment: async (ctx) => {
						const done = await factor.completeEnrollment(ctx);
						return done.ok ? { ...done, data: bare(done.data) } : done;
					},
					challenge: async (ctx) => {
						const sent = await (factor.challenge as NonNullable<MfaFactor["challenge"]>)(ctx);
						return { ...sent, state: bare(sent.state ?? {}) };
					},
				})),
			),
		).toEqual([]);
	});

	it("fails a kind a hint cannot carry", async () => {
		expect(await failing(inputFor({ kind: "Test" }))).toEqual([RULES.kind]);
	});

	it("fails amrValues that are empty, repeat a value, or name a primary's marker or mfa", async () => {
		for (const amrValues of [[], ["otp", "otp"], ["pwd", "otp"], ["fed"], ["otp", "mfa"], [""]]) {
			expect(await failing(inputFor({ amrValues }))).toContain(RULES.amrValues);
		}
	});

	it("fails a flag that is not true or false", async () => {
		expect(
			await failing(
				inputFor({}, (factor) => ({ ...factor, counting: "yes" as unknown as boolean })),
			),
		).toEqual([RULES.flags]);
		expect(
			await failing(
				inputFor({}, (factor) => ({ ...factor, reusableChallenge: 1 as unknown as boolean })),
			),
		).toEqual([RULES.flags]);
	});

	it("fails a factor that refuses the account it is handed as enrollable", async () => {
		expect(
			await failing(inputFor({}, (factor) => ({ ...factor, enrollable: () => false }))),
		).toEqual([RULES.enrollable]);
	});

	it("fails an enrollment whose state does not survive JSON", async () => {
		expect(
			await failing(
				inputFor({}, (factor) => ({
					...factor,
					beginEnrollment: async (ctx) => {
						const start = await factor.beginEnrollment(ctx);
						return { ...start, state: { ...start.state, at: new Date(ctx.nowMs) } };
					},
				})),
			),
		).toEqual([RULES.begin]);
	});

	it("fails a completion whose data amrFor answers nothing for", async () => {
		expect(await failing(inputFor({}, (factor) => ({ ...factor, amrFor: () => [] })))).toEqual([
			RULES.complete,
		]);
	});

	it("fails a hint that shows the account's address", async () => {
		expect(
			await failing(
				inputFor({}, (factor) => ({ ...factor, describe: () => ({ hint: `for ${USER.email}` }) })),
			),
		).toEqual([RULES.describe]);
	});

	it("fails a completion that throws for a proof it cannot read", async () => {
		expect(
			await failing(
				inputFor({}, (factor) => ({
					...factor,
					completeEnrollment: async (ctx) => {
						if (typeof ctx.proof !== "string") throw new TypeError("proof is not a string");
						return factor.completeEnrollment(ctx);
					},
				})),
			),
		).toEqual([RULES.completeMalformed]);
	});

	it("fails a completion whose data does not survive JSON, or whose amr values are not declared", async () => {
		expect(
			await failing(
				inputFor({}, (factor) => ({
					...factor,
					completeEnrollment: async (ctx) => {
						const done = await factor.completeEnrollment(ctx);
						return done.ok ? { ...done, data: { ...done.data, at: 1n as never } } : done;
					},
				})),
			),
		).toContain(RULES.complete);
		expect(
			await failing(inputFor({}, (factor) => ({ ...factor, amrFor: () => ["otp", "sms"] }))),
		).toEqual([RULES.complete]);
	});

	it("fails a hint that is not a string", async () => {
		expect(
			await failing(
				inputFor({}, (factor) => ({ ...factor, describe: () => ({ hint: 5 as never }) })),
			),
		).toEqual([RULES.describe]);
	});

	it("fails a challenge whose state does not survive JSON", async () => {
		expect(
			await failing(
				inputFor({ challenge: true }, (factor) => ({
					...factor,
					challenge: async (ctx) => {
						const sent = await (factor.challenge as NonNullable<MfaFactor["challenge"]>)(ctx);
						return { ...sent, state: { ...sent.state, sentAt: new Map([["at", ctx.nowMs]]) } };
					},
				})),
			),
		).toEqual([RULES.challenge]);
	});

	it("fails a verification that throws for a proof it cannot read", async () => {
		expect(
			await failing(
				inputFor({}, (factor) => ({
					...factor,
					verify: async (ctx) => {
						if (typeof ctx.proof !== "string") throw new TypeError("proof is not a string");
						return factor.verify(ctx);
					},
				})),
			),
		).toEqual([RULES.verifyMalformed]);
	});

	it("fails a verification that refuses a valid proof, or names a factor the subject does not hold", async () => {
		// Each reads a malformed proof as the double does, so only the valid one breaks the contract.
		expect(
			await failing(
				inputFor({}, (factor) => ({
					...factor,
					verify: async (ctx) =>
						typeof ctx.proof === "string" ? { ok: false, reason: "invalid" } : factor.verify(ctx),
				})),
			),
		).toEqual([RULES.verify]);
		expect(
			await failing(
				inputFor({}, (factor) => ({
					...factor,
					verify: async (ctx) =>
						typeof ctx.proof === "string"
							? { ok: true, factorId: "someone-else's" }
							: factor.verify(ctx),
				})),
			),
		).toEqual([RULES.verify]);
	});
});
