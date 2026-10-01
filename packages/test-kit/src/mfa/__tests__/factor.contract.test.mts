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

import { createHash, randomBytes } from "node:crypto";
import { type MfaFactor, type MfaFactorData, normaliseMailAddress } from "@o3co/auth-provider-core";
import {
	createTestMfaDigests,
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
	beginMail:
		"beginEnrollment, when it asks for a code to be mailed, asks for the enrollment code, non-empty, with an expiry after now when it gives one, and its response carries no form of the code",
	completeMalformed:
		"completeEnrollment answers malformed for a proof it cannot read, and never throws for one",
	complete:
		"completeEnrollment takes the proof of possession, and answers data that survives a JSON round trip, a label that is a string when present, and at least one amr value, each among amrValues",
	describe: "describe answers a hint that is a string, or none, and never the account's address",
	challenge: "challenge, when present, answers state that survives a JSON round trip",
	challengeMail:
		"challenge, when it asks for a code to be mailed, asks for a login code, non-empty, with an expiry after now when it gives one and the keyed digest of the account's address, another at each challenge, and its response carries no form of the code",
	handed:
		"completeEnrollment records exactly the address digest it is handed — of the address its code went to, kept at the send — never one of the address the account answered at the start or answers by the completion",
	unhanded:
		"completeEnrollment, after its code was mailed, completes nothing when it is handed no address digest",
	rotated:
		"verify, handed the address digest under a newer key than the one recorded, keeps it in its next data, and a later challenge mails it",
	unreadable:
		"challenge, over data whose address digest is gone or is no digest, still asks for its login code, with a null address digest, and never throws: the coordinator refuses the factor",
	noAddress:
		"nothing kept, and no challenge's answer, carries the account's address — an enrollment's answer only as the account's username, verbatim — whatever its case or escaping: the pending enrollment's state and answer, the enrolled data and label, a challenge's state and answer, and a verification's next data",
	quietErrors:
		"an error the factor throws — over an account without a username, or a pending state or data it cannot read — quotes neither the account's address nor its username",
	verifyMalformed: "verify answers malformed for a proof it cannot read, and never throws for one",
	verify:
		"verify takes a valid proof, names a factor the subject holds, and answers next data that survives a JSON round trip",
	identity:
		"identity, when present, answers the enrolled data a non-empty string, the same at a second reading, through another JSON round trip, and for the next data a verification answers",
	identityUnreadable:
		"identity, when present, answers a non-empty string or undefined over data it cannot read, never one string for two of them unless it is the enrolled data's own, and never throws",
	identityDistinct:
		"identity, when present and given a second authenticator's enrollment proof, answers the enrolled data of the two authenticators two different non-empty strings: no identity is a duplicate of none, never a distinct authenticator",
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

/**
 * An identity as a factor might answer it: for the double that mails, its
 * address digest, key id and digest; otherwise a digest of its secret. None
 * when the data holds neither. The digest of the secret is a stand-in for
 * these tests alone: a real factor's identity is never derived from a
 * secret, since an unsalted hash of a secret is a verifier for it.
 */
const identityOf = (data: MfaFactorData): string | undefined => {
	const { secret, addressDigest } = data as {
		readonly secret?: unknown;
		readonly addressDigest?: { readonly keyId?: unknown; readonly digest?: unknown } | null;
	};
	if (typeof secret === "string") return createHash("sha256").update(secret).digest("base64url");
	const { keyId, digest } = addressDigest ?? {};
	return typeof keyId === "string" && typeof digest === "string" ? `${keyId}:${digest}` : undefined;
};

/** The double, answering `identity` as {@link identityOf} does. */
const identified = (factor: MfaFactor): MfaFactor => ({ ...factor, identity: identityOf });

/** `input` given a second authenticator: each enrollment of the double makes a new secret. */
const withSecond = (input: MfaFactorContractInput): MfaFactorContractInput => ({
	...input,
	secondEnrollmentProof: testMfaFactorProofs.enrollmentProof,
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

	it("passes the double, with and without a challenge, and with mail", async () => {
		expect(await failing(inputFor())).toEqual([]);
		expect(await failing(inputFor({ challenge: true }))).toEqual([]);
		expect(await failing(inputFor({ mail: true }))).toEqual([]);
		expect(await failing(inputFor({ kind: "test_2", amrValues: ["hwk", "swk"] }))).toEqual([]);
	});

	it("passes the double with an identity of what its data records, with and without a challenge, and with mail", async () => {
		expect(await failing(inputFor({}, identified))).toEqual([]);
		expect(await failing(inputFor({ challenge: true }, identified))).toEqual([]);
		expect(await failing(inputFor({ mail: true }, identified))).toEqual([]);
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

	/** The double with mail, its challenge answer changed by `change`. */
	const challenging = (
		change: (
			sent: Awaited<ReturnType<NonNullable<MfaFactor["challenge"]>>>,
			ctx: Parameters<NonNullable<MfaFactor["challenge"]>>[0],
		) => unknown,
		user: Record<string, unknown> = USER,
	) => ({
		...inputFor({ mail: true }, (factor) => ({
			...factor,
			challenge: async (ctx) => {
				const sent = await (factor.challenge as NonNullable<MfaFactor["challenge"]>)(ctx);
				return change(sent, ctx) as never;
			},
		})),
		user,
	});

	/** The challenge's code set to `code`, kept and mailed alike, so only the response can break the contract. */
	const withCode =
		(code: string, response: (code: string) => unknown): Parameters<typeof challenging>[0] =>
		(sent) => ({
			...sent,
			state: { code },
			mail: { ...sent.mail, code },
			response: response(code),
		});

	it("fails an enrollment or a challenge whose response carries the code it asks to be mailed", async () => {
		expect(
			await failing(
				inputFor({ mail: true }, (factor) => ({
					...factor,
					beginEnrollment: async (ctx) => {
						const start = await factor.beginEnrollment(ctx);
						return { ...start, response: { sent: true, code: start.mail?.code } };
					},
				})),
			),
		).toEqual([RULES.beginMail]);
		expect(
			await failing(
				challenging((sent) => ({ ...sent, response: `sent ${sent.mail?.code} to your mailbox` })),
			),
		).toEqual([RULES.challengeMail]);
	});

	it("fails a response carrying the code escaped, in another case or spacing, as a number or as a key", async () => {
		for (const [code, response] of [
			['ab"cd123', (c: string) => ({ code: c })],
			["ab\\cd123", (c: string) => ({ code: c })],
			["ab12cd34", (c: string) => ({ hint: c.toUpperCase().replace(/(....)/, "$1-") })],
			["482913", (c: string) => ({ code: Number(c) })],
			["482913", (c: string) => ({ codes: { [c]: true } })],
			["482913", (c: string) => [`${c.slice(0, 3)} ${c.slice(3)}`]],
		] as const) {
			expect(await failing(challenging(withCode(code, response))), code).toEqual([
				RULES.challengeMail,
			]);
		}
	});

	it("fails a mail whose purpose is not the call's, or whose code is empty or no string", async () => {
		for (const purpose of [
			"email_factor_enrollment",
			"account_email_proof",
			"security_notice",
			"LOGIN_CODE",
			undefined,
		]) {
			expect(
				await failing(challenging((sent) => ({ ...sent, mail: { ...sent.mail, purpose } }))),
				String(purpose),
			).toEqual([RULES.challengeMail]);
		}
		// A code that is not the one kept is no proof either: verification fails beside it.
		for (const code of ["", 123456, undefined]) {
			expect(
				await failing(challenging((sent) => ({ ...sent, mail: { ...sent.mail, code } }))),
				String(code),
			).toContain(RULES.challengeMail);
		}
		expect(await failing(challenging((sent) => ({ ...sent, mail: sent.mail?.code })))).toContain(
			RULES.challengeMail,
		);
		for (const purpose of ["login_code", "account_email_proof", "notice"]) {
			expect(
				await failing(
					inputFor({ mail: true }, (factor) => ({
						...factor,
						beginEnrollment: async (ctx) => {
							const start = await factor.beginEnrollment(ctx);
							return { ...start, mail: { ...start.mail, purpose } as never };
						},
					})),
				),
				purpose,
			).toEqual([RULES.beginMail]);
		}
	});

	it("fails a mailed code whose expiry is not after now, and a challenge that mails the same code twice", async () => {
		for (const expiry of [
			(now: number) => now,
			(now: number) => now - 1,
			() => Number.NaN,
			() => "soon",
		]) {
			expect(
				await failing(
					challenging((sent, ctx) => ({
						...sent,
						mail: { ...sent.mail, expiresAtMs: expiry(ctx.nowMs) },
					})),
				),
				String(expiry),
			).toEqual([RULES.challengeMail]);
			expect(
				await failing(
					inputFor({ mail: true }, (factor) => ({
						...factor,
						beginEnrollment: async (ctx) => {
							const start = await factor.beginEnrollment(ctx);
							return {
								...start,
								mail: { ...start.mail, expiresAtMs: expiry(ctx.nowMs) } as never,
							};
						},
					})),
				),
				String(expiry),
			).toEqual([RULES.beginMail]);
		}
		expect(await failing(challenging(withCode("482913", () => ({ sent: true }))))).toEqual([
			RULES.challengeMail,
		]);
	});

	it("fails an address kept anywhere, in another case or under JSON escaping", async () => {
		const QUOTED = { ...USER, email: '"probe"@example.com' };
		const answering = (
			change: (factor: MfaFactor) => Partial<MfaFactor>,
			user: Record<string, unknown> = USER,
		) => ({ ...inputFor({ mail: true }, (factor) => ({ ...factor, ...change(factor) })), user });
		const cases = (email: string): [string, (factor: MfaFactor) => Partial<MfaFactor>][] => [
			[
				"the enrolled data",
				(factor) => ({
					completeEnrollment: async (ctx) => {
						const done = await factor.completeEnrollment(ctx);
						return done.ok ? { ...done, data: { ...done.data, to: ctx.user.email } } : done;
					},
				}),
			],
			[
				"the label",
				(factor) => ({
					completeEnrollment: async (ctx) => {
						const done = await factor.completeEnrollment(ctx);
						return done.ok ? { ...done, label: `mail to ${String(ctx.user.email)}` } : done;
					},
				}),
			],
			[
				"the pending enrollment's state and response",
				(factor) => ({
					beginEnrollment: async (ctx) => {
						const start = await factor.beginEnrollment(ctx);
						return {
							...start,
							state: { ...start.state, to: ctx.user.email },
							response: { sentTo: ctx.user.email },
						};
					},
				}),
			],
			[
				"a challenge's state",
				(factor) => ({
					challenge: async (ctx) => {
						const sent = await (factor.challenge as NonNullable<MfaFactor["challenge"]>)(ctx);
						return { ...sent, state: { ...sent.state, to: email.toUpperCase() } };
					},
				}),
			],
		];
		for (const user of [USER, QUOTED]) {
			for (const [where, change] of cases(user.email)) {
				expect(await failing(answering(change, user)), `${where}, ${user.email}`).toEqual([
					RULES.noAddress,
				]);
			}
		}
		expect(
			await failing(
				answering(
					(factor) => ({
						verify: async (ctx) => {
							const verdict = await factor.verify(ctx);
							return verdict.ok
								? {
										...verdict,
										next: { ...(verdict.next ?? ctx.factor.data), lastTo: QUOTED.email },
									}
								: verdict;
						},
					}),
					QUOTED,
				),
			),
		).toEqual([RULES.noAddress]);
	});

	it("fails an address kept percent-encoded in the pending enrollment, as a URI would carry it", async () => {
		const QUOTED = { ...USER, email: '"probe"@example.com' };
		for (const user of [USER, QUOTED]) {
			const encoding = inputFor({ mail: true }, (factor) => ({
				...factor,
				beginEnrollment: async (ctx) => {
					const start = await factor.beginEnrollment(ctx);
					return {
						...start,
						state: {
							...start.state,
							uri: `otpauth://totp/Issuer:${encodeURIComponent(String(ctx.user.email))}`,
						},
					};
				},
			}));
			expect(await failing({ ...encoding, user }), user.email).toEqual([RULES.noAddress]);
		}
	});

	it("fails a factor whose error quotes the account's address or its username, percent-encoded or not — the suite's own canary account", async () => {
		const unreadable = (value: unknown) =>
			typeof value === "object" && value !== null && Object.keys(value).length === 0;
		const quoting: [string, (factor: MfaFactor) => Partial<MfaFactor>][] = [
			[
				"beginEnrollment",
				(factor) => ({
					beginEnrollment: async (ctx) => {
						if (ctx.user.username === undefined) {
							throw new Error(`no username for ${encodeURIComponent(String(ctx.user.email))}`);
						}
						return factor.beginEnrollment(ctx);
					},
				}),
			],
			[
				"completeEnrollment",
				(factor) => ({
					completeEnrollment: async (ctx) => {
						if (unreadable(ctx.state)) {
							throw new Error(`no enrollment of ${String(ctx.user.username)}`);
						}
						return factor.completeEnrollment(ctx);
					},
				}),
			],
		];
		for (const [where, change] of quoting) {
			const input = inputFor({}, (factor) => ({ ...factor, ...change(factor) }));
			expect(await failing(input), where).toEqual([RULES.quietErrors]);
		}
	});

	it("passes a factor whose error says an ordinary word an account's username could be", async () => {
		const plain = inputFor({}, (factor) => ({
			...factor,
			completeEnrollment: async (ctx) => {
				if (Object.keys(ctx.state).length === 0)
					throw new Error("a error in a state it cannot read");
				return factor.completeEnrollment(ctx);
			},
		}));
		for (const username of ["error", "a", "state"]) {
			expect(await failing({ ...plain, user: { ...USER, username } }), username).toEqual([]);
		}
	});

	it("fails a challenge's answer carrying the account's address, as it is or percent-encoded: a login's challenge goes to whoever holds the password", async () => {
		for (const shown of [USER.email, encodeURIComponent(USER.email)]) {
			const naming = inputFor({ challenge: true }, (factor) => ({
				...factor,
				challenge: async (ctx) => {
					const sent = await (factor.challenge as NonNullable<MfaFactor["challenge"]>)(ctx);
					return { ...sent, response: { ...(sent.response as Record<string, unknown>), shown } };
				},
			}));
			expect(await failing(naming), shown).toEqual([RULES.noAddress]);
		}
	});

	it("fails an enrollment's answer carrying the account's address beside a username that is not it, percent-encoded or not", async () => {
		const naming = inputFor({}, (factor) => ({
			...factor,
			beginEnrollment: async (ctx) => {
				const start = await factor.beginEnrollment(ctx);
				return {
					...start,
					response: {
						...(start.response as Record<string, unknown>),
						uri: `otpauth://totp/Issuer:${encodeURIComponent(String(ctx.user.email))}`,
					},
				};
			},
		}));
		expect(await failing(naming)).toEqual([RULES.noAddress]);
	});

	it("passes an enrollment's answer naming the account by its username verbatim, percent-encoded or not, where the username is the address: the answer goes to the account's own browser", async () => {
		const naming = inputFor({}, (factor) => ({
			...factor,
			beginEnrollment: async (ctx) => {
				const start = await factor.beginEnrollment(ctx);
				return {
					...start,
					response: {
						...(start.response as Record<string, unknown>),
						uri: `otpauth://totp/Issuer:${encodeURIComponent(String(ctx.user.username))}`,
						account: ctx.user.username,
					},
				};
			},
		}));
		expect(await failing({ ...naming, user: { ...USER, username: USER.email } })).toEqual([]);
	});

	it("passes text a percent sign cannot decode, searching it as it is", async () => {
		const stray = inputFor({}, (factor) => ({
			...factor,
			beginEnrollment: async (ctx) => {
				const start = await factor.beginEnrollment(ctx);
				return {
					...start,
					response: { ...(start.response as Record<string, unknown>), note: "100% of %E0%A4%A" },
				};
			},
		}));
		expect(await failing(stray)).toEqual([]);
	});

	it("fails a login code mailed with no address digest, one that is no digest, or the digest of another address", async () => {
		for (const addressDigest of [
			undefined,
			"digest",
			{ keyId: "test-key" },
			createTestMfaDigests("test").digest(["someone@example.com"]),
			createTestMfaDigests("another-kind").digest([USER.email]),
		]) {
			expect(
				await failing(challenging((sent) => ({ ...sent, mail: { ...sent.mail, addressDigest } }))),
				JSON.stringify(addressDigest),
			).toEqual([RULES.challengeMail, RULES.rotated]);
		}
		// Null is for data that holds no digest, never for data that does. Each is
		// mailed at every challenge, the one after a rotation too.
		expect(
			await failing(
				challenging((sent) => ({ ...sent, mail: { ...sent.mail, addressDigest: null } })),
			),
		).toEqual([RULES.challengeMail, RULES.rotated]);
	});

	it("fails a factor that records a digest of the account's address as it reads at completion, or at a verification anything but the digest it was handed", async () => {
		const digestOf = (email: unknown) =>
			createTestMfaDigests("test").digest([normaliseMailAddress(email) as string]);
		expect(
			await failing(
				inputFor({ mail: true }, (factor) => ({
					...factor,
					completeEnrollment: async (ctx) => {
						const done = await factor.completeEnrollment(ctx);
						return done.ok ? { ...done, data: { addressDigest: digestOf(ctx.user.email) } } : done;
					},
				})),
			),
		).toEqual([RULES.handed]);
		for (const next of [
			{ addressDigest: digestOf("someone@attacker.example") },
			{ addressDigest: null },
			{},
		]) {
			expect(
				await failing(
					inputFor({ mail: true }, (factor) => ({
						...factor,
						verify: async (ctx) => {
							const verdict = await factor.verify(ctx);
							return verdict.ok && ctx.addressDigest !== undefined ? { ...verdict, next } : verdict;
						},
					})),
				),
				JSON.stringify(next),
			).toEqual([RULES.rotated]);
		}
	});

	it("fails a challenge that, over data holding no readable address digest, throws, asks for no login code, or mails one with a digest that is none", async () => {
		const unreadable = (data: Record<string, unknown>) =>
			typeof data.addressDigest !== "object" ||
			data.addressDigest === null ||
			typeof (data.addressDigest as { digest?: unknown }).digest !== "string";
		for (const change of [
			() => {
				throw new Error("no address digest");
			},
			(sent: Awaited<ReturnType<NonNullable<MfaFactor["challenge"]>>>) => ({
				...sent,
				mail: undefined,
			}),
			(sent: Awaited<ReturnType<NonNullable<MfaFactor["challenge"]>>>) => ({
				...sent,
				mail: { ...sent.mail, addressDigest: undefined },
			}),
			(sent: Awaited<ReturnType<NonNullable<MfaFactor["challenge"]>>>) => ({
				...sent,
				mail: { ...sent.mail, addressDigest: "digest" },
			}),
		]) {
			expect(
				await failing(
					challenging((sent, ctx) =>
						unreadable(ctx.factor.data) ? (change as (s: typeof sent) => unknown)(sent) : sent,
					),
				),
				change.toString(),
			).toEqual([RULES.unreadable]);
		}
	});

	it("passes the double over an account whose address is padded, in another case, internationalised or decomposed, and fails a factor keeping it as normaliseMailAddress spells it", async () => {
		for (const email of [
			" Contract@Example.COM ",
			"contract@b\u00fccher.example",
			"jose\u0301@example.com",
			"Jos\u00e9@B\u00fccher.example",
		]) {
			const user = { ...USER, email };
			expect(await failing({ ...inputFor({ mail: true }), user }), email).toEqual([]);
			expect(
				await failing({
					...inputFor({ mail: true }, (factor) => ({
						...factor,
						completeEnrollment: async (ctx) => {
							const done = await factor.completeEnrollment(ctx);
							return done.ok
								? { ...done, data: { ...done.data, kept: normaliseMailAddress(ctx.user.email) } }
								: done;
						},
					})),
					user,
				}),
				email,
			).toEqual([RULES.noAddress]);
		}
	});

	it("passes a factor that keeps the keyed digest of the address it confirmed, spelled any way, and fails one that keeps the address", async () => {
		expect(
			await failing({
				...inputFor({ mail: true }),
				user: { ...USER, email: " Contract@EXAMPLE.com " },
			}),
		).toEqual([]);
		expect(
			await failing(
				inputFor({ mail: true }, (factor) => ({
					...factor,
					completeEnrollment: async (ctx) => {
						const done = await factor.completeEnrollment(ctx);
						return done.ok ? { ...done, data: { ...done.data, address: ctx.user.email } } : done;
					},
				})),
			),
		).toEqual([RULES.noAddress]);
	});
	it("fails a factor that records a digest it made of the account's address itself: at the start, or when none is handed", async () => {
		const digestOf = (email: unknown) =>
			createTestMfaDigests("test").digest([normaliseMailAddress(email) as string]);
		// Kept from the start, and recorded in place of the one handed.
		const fromTheStart = (factor: MfaFactor): MfaFactor => ({
			...factor,
			beginEnrollment: async (ctx) => {
				const start = await factor.beginEnrollment(ctx);
				return { ...start, state: { ...start.state, mine: digestOf(ctx.user.email) } };
			},
			completeEnrollment: async (ctx) =>
				factor.completeEnrollment({ ...ctx, addressDigest: ctx.state.mine as never }),
		});
		expect(await failing(inputFor({ mail: true }, fromTheStart))).toEqual([
			RULES.handed,
			RULES.unhanded,
		]);
		// Its own, when none is handed.
		const fallingBack = (factor: MfaFactor): MfaFactor => ({
			...factor,
			completeEnrollment: async (ctx) =>
				factor.completeEnrollment({
					...ctx,
					addressDigest: ctx.addressDigest ?? digestOf(ctx.user.email),
				}),
		});
		expect(await failing(inputFor({ mail: true }, fallingBack))).toEqual([RULES.unhanded]);
	});

	it("fails a factor that keeps no digest it is handed under a newer key, or keeps the old one", async () => {
		const rewrapping = (next: (ctx: Parameters<MfaFactor["verify"]>[0]) => unknown) =>
			inputFor({ mail: true }, (factor) => ({
				...factor,
				verify: async (ctx) => {
					const verdict = await factor.verify(ctx);
					if (!verdict.ok) return verdict;
					const { next: _dropped, ...kept } = verdict;
					const changed = next(ctx);
					return changed === undefined ? kept : { ...kept, next: changed as never };
				},
			}));
		// Every rotation write removed.
		expect(await failing(rewrapping(() => undefined))).toEqual([RULES.rotated]);
		// The recorded digest kept, not the one handed.
		expect(await failing(rewrapping((ctx) => ctx.factor.data))).toEqual([RULES.rotated]);
	});
	it("fails an identity that answers no string, or an empty one, for the data its enrollment completes with", async () => {
		expect(
			await failing(inputFor({}, (factor) => ({ ...factor, identity: () => undefined }))),
		).toEqual([RULES.identity]);
		// An empty string is no identity over data it cannot read either.
		expect(await failing(inputFor({}, (factor) => ({ ...factor, identity: () => "" })))).toEqual([
			RULES.identity,
			RULES.identityUnreadable,
		]);
	});

	it("fails an identity that answers another string at each reading of one record's data", async () => {
		expect(
			await failing(
				inputFor({}, (factor) => ({
					...factor,
					identity: () => randomBytes(8).toString("hex"),
				})),
			),
		).toEqual([RULES.identity]);
	});

	it("fails an identity that a verification's next data changes", async () => {
		expect(
			await failing(
				inputFor({}, (factor) => ({
					...factor,
					identity: (data) => JSON.stringify(data),
					verify: async (ctx) => {
						const verdict = await factor.verify(ctx);
						return verdict.ok
							? { ...verdict, next: { ...ctx.factor.data, usedAtMs: ctx.nowMs } }
							: verdict;
					},
				})),
			),
		).toEqual([RULES.identity]);
	});

	it("fails an identity that throws, or answers what is no string, over data it cannot read", async () => {
		const over = (unreadable: (data: MfaFactorData) => string | undefined) =>
			inputFor({}, (factor) => ({
				...factor,
				identity: (data) => (typeof data.secret === "string" ? identityOf(data) : unreadable(data)),
			}));
		expect(
			await failing(
				over(() => {
					throw new TypeError("no secret");
				}),
			),
		).toEqual([RULES.identityUnreadable]);
		expect(await failing(over(() => 7 as never))).toEqual([RULES.identityUnreadable]);
		expect(await failing(over(() => ""))).toEqual([RULES.identityUnreadable]);
	});

	it("fails an identity that answers one string for two data it cannot read", async () => {
		// Read through a member without checking it: a removed digest, or one that
		// is a number or a string, answers "undefined:undefined" alike.
		const careless = (factor: MfaFactor): MfaFactor => ({
			...factor,
			identity: (data) => {
				const digest = data.addressDigest as
					| { readonly keyId?: unknown; readonly digest?: unknown }
					| null
					| undefined;
				return `${String(digest?.keyId)}:${String(digest?.digest)}`;
			},
		});
		expect(await failing(inputFor({ mail: true }, careless))).toEqual([RULES.identityUnreadable]);
	});

	it("passes the double with an identity and a second authenticator, with and without a challenge, and one with no identity", async () => {
		expect(await failing(withSecond(inputFor({}, identified)))).toEqual([]);
		expect(await failing(withSecond(inputFor({ challenge: true }, identified)))).toEqual([]);
		expect(await failing(withSecond(inputFor()))).toEqual([]);
	});

	it("fails an identity that answers one string for two authenticators", async () => {
		const constant = (factor: MfaFactor): MfaFactor => ({ ...factor, identity: () => "one" });
		expect(await failing(withSecond(inputFor({}, constant)))).toEqual([RULES.identityDistinct]);
		// Without a second authenticator the suite cannot tell.
		expect(await failing(inputFor({}, constant))).toEqual([]);
	});

	it("fails an identity that answers none for the second authenticator: none is no distinct authenticator", async () => {
		const secondUnnamed = (factor: MfaFactor): MfaFactor => {
			let completed = 0;
			return {
				...factor,
				completeEnrollment: async (ctx) => {
					const done = await factor.completeEnrollment(ctx);
					if (!done.ok) return done;
					completed += 1;
					return completed === 2 ? { ...done, data: { ...done.data, unnamed: true } } : done;
				},
				identity: (data) => (data.unnamed === true ? undefined : identityOf(data)),
			};
		};
		expect(await failing(withSecond(inputFor({}, secondUnnamed)))).toEqual([
			RULES.identityDistinct,
		]);
	});

	it("fails a second authenticator's proof that completes no enrollment", async () => {
		expect(
			await failing({ ...inputFor({}, identified), secondEnrollmentProof: () => "not-the-secret" }),
		).toEqual([RULES.identityDistinct]);
	});
});
