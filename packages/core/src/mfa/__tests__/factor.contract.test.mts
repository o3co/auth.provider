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
 * The conformance suite every contributed second factor runs, the factor
 * double, and the keyed digests a factor's tests hand it. The suite runs
 * against the double, with and without mail; each way a factor can break
 * the contract fails the case that names it.
 */

import { describe, expect, it } from "vitest";
import type { MailMessage } from "#/mail/types.mjs";
import type { MfaFactor } from "#/mfa/factor.mjs";
import {
	createTestMfaDigests,
	createTestMfaFactor,
	type MfaFactorContractInput,
	mfaFactorContract,
	type TestMfaFactorOptions,
	testMfaFactorProofs,
} from "#/testing/index.mjs";

const RULES = {
	kind: "kind is a hint token: a lowercase letter, then up to 63 lowercase letters, digits, _ or -",
	amrValues:
		"amrValues is a non-empty list of distinct non-empty strings, with no primary's marker and no mfa",
	flags:
		"addsMfa, counting and guessable are true or false, and reusableChallenge true, false or absent",
	mailLimits:
		"mailLimits, when declared, allow at least one send, in whole numbers of sends and seconds",
	enrollable: "enrollable, when present, answers true for an account that can enroll the factor",
	begin:
		"beginEnrollment answers state that survives a JSON round trip, and mail only beside mailLimits, as a message with a recipient, a subject and a text, whose code the response does not carry",
	completeMalformed:
		"completeEnrollment answers malformed for a proof it cannot read, and never throws for one",
	complete:
		"completeEnrollment takes the proof of possession, and answers data that survives a JSON round trip, a label that is a string when present, and at least one amr value, each among amrValues",
	describe: "describe answers a hint that is a string, or none, and never the account's address",
	challenge:
		"challenge, when present, answers state that survives a JSON round trip, and mail only beside mailLimits, as a message with a recipient, a subject and a text, to the address the enrollment mailed, whose code the response does not carry",
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

const MAIL = { maxSends: 3, resendAfterSeconds: 30 } as const;

describe("mfaFactorContract", () => {
	it("names every rule it holds a factor to", () => {
		expect(mfaFactorContract(inputFor()).map((c) => c.name)).toEqual(Object.values(RULES));
	});

	it("passes the double, with and without mail", async () => {
		expect(await failing(inputFor())).toEqual([]);
		expect(await failing(inputFor({ mail: MAIL }))).toEqual([]);
		expect(await failing(inputFor({ kind: "test_2", amrValues: ["hwk", "swk"] }))).toEqual([]);
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

	it("fails mail limits that allow no send, or are not whole numbers", async () => {
		for (const mailLimits of [
			{ maxSends: 0, resendAfterSeconds: 30 },
			{ maxSends: 1.5, resendAfterSeconds: 30 },
			{ maxSends: 3, resendAfterSeconds: -1 },
			{ maxSends: 3, resendAfterSeconds: Number.NaN },
		]) {
			expect(
				await failing(inputFor({ mail: MAIL }, (factor) => ({ ...factor, mailLimits }))),
			).toEqual([RULES.mailLimits]);
		}
	});

	it("fails a factor that refuses the account it is handed as enrollable", async () => {
		expect(
			await failing(inputFor({}, (factor) => ({ ...factor, enrollable: () => false }))),
		).toEqual([RULES.enrollable]);
	});

	it("fails an enrollment whose state does not survive JSON, or whose mail comes without limits", async () => {
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
		const { mailLimits: _dropped, ...withoutLimits } = createTestMfaFactor({ mail: MAIL });
		expect(await failing({ ...inputFor(), build: () => withoutLimits })).toEqual(
			expect.arrayContaining([RULES.begin, RULES.challenge]),
		);
		expect(
			await failing(
				inputFor({ mail: MAIL }, (factor) => ({
					...factor,
					beginEnrollment: async (ctx) => {
						const start = await factor.beginEnrollment(ctx);
						return { ...start, mail: { ...(start.mail as object), subject: "" } as never };
					},
				})),
			),
		).toEqual([RULES.begin]);
	});

	it("fails an enrollment or a challenge whose response carries the code its mail sends", async () => {
		const codeOf = (mail: { text: string } | undefined) => mail?.text.split(" ").at(-1);
		expect(
			await failing(
				inputFor({ mail: MAIL }, (factor) => ({
					...factor,
					beginEnrollment: async (ctx) => {
						const start = await factor.beginEnrollment(ctx);
						return { ...start, response: { sent: true, code: codeOf(start.mail) } };
					},
				})),
			),
		).toEqual([RULES.begin]);
		expect(
			await failing(
				inputFor({ mail: MAIL }, (factor) => ({
					...factor,
					challenge: async (ctx) => {
						const sent = await (factor.challenge as NonNullable<MfaFactor["challenge"]>)(ctx);
						return { ...sent, response: { echo: `code ${codeOf(sent.mail)}` } };
					},
				})),
			),
		).toEqual([RULES.challenge]);
	});

	it("fails a challenge that mails another address than the enrollment did", async () => {
		expect(
			await failing(
				inputFor({ mail: MAIL }, (factor) => ({
					...factor,
					challenge: async (ctx) => {
						const sent = await (factor.challenge as NonNullable<MfaFactor["challenge"]>)(ctx);
						return { ...sent, mail: { ...(sent.mail as MailMessage), to: "mallory@example.com" } };
					},
				})),
			),
		).toEqual([RULES.challenge]);
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
				inputFor({ mail: MAIL }, (factor) => ({
					...factor,
					challenge: async (ctx) => {
						const sent = await (factor.challenge as NonNullable<MfaFactor["challenge"]>)(ctx);
						return { ...sent, state: { ...sent.state, undefinedMember: undefined } };
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

describe("createTestMfaFactor", () => {
	it("is a counting, non-guessable factor of kind test adding otp and mfa, with no challenge unless it mails", () => {
		const factor = createTestMfaFactor();
		expect(factor).toMatchObject({
			kind: "test",
			amrValues: ["otp"],
			addsMfa: true,
			counting: true,
			guessable: false,
		});
		expect(factor.challenge).toBeUndefined();
		expect(factor.mailLimits).toBeUndefined();
		const mailing = createTestMfaFactor({ mail: MAIL });
		expect(mailing.mailLimits).toEqual(MAIL);
		expect(typeof mailing.challenge).toBe("function");
	});

	it("mails the enrollment's code to the account's address, and offers itself only to an account that has one", async () => {
		const factor = createTestMfaFactor({ mail: MAIL });
		expect(factor.enrollable?.(USER)).toBe(true);
		expect(factor.enrollable?.({ id: "u-without" })).toBe(false);
		const start = await factor.beginEnrollment({
			subject: USER.id,
			transactionId: "tx",
			nowMs: 0,
			request: {},
			digests: createTestMfaDigests("test"),
			user: USER,
			factors: [],
		});
		expect(start.mail?.to).toBe(USER.email);
		expect(JSON.stringify(start.response)).not.toContain(
			String(testMfaFactorProofs.enrollmentProof(start)),
		);
	});
});

describe("createTestMfaDigests", () => {
	it("matches what it digested, under its kind and parts alone", () => {
		const digests = createTestMfaDigests("email");
		const made = digests.digest(["tx", "f-1", "123456"]);
		expect(digests.matchesDigest(["tx", "f-1", "123456"], made)).toBe("match");
		expect(digests.matchesDigest(["tx", "f-1", "654321"], made)).toBe("mismatch");
		// Length-prefixed: moving a character between two parts is another input.
		expect(digests.matchesDigest(["tx", "f-11", "23456"], made)).toBe("mismatch");
		expect(createTestMfaDigests("recovery_code").matchesDigest(["tx", "f-1", "123456"], made)).toBe(
			"mismatch",
		);
	});

	it("answers key_unavailable for a digest made under a key it does not hold", () => {
		const digests = createTestMfaDigests("email");
		const made = digests.digest(["x"]);
		expect(digests.matchesDigest(["x"], { ...made, keyId: "retired" })).toBe("key_unavailable");
	});
});
