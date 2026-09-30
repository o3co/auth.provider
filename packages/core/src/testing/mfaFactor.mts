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
 * The conformance suite of a second factor — a value of the `mfaFactors`
 * contribution kind — its double, and the keyed digests a factor's own tests
 * hand it.
 *
 * `mfaFactorContract(input)` holds a factor to what the coordinator relies on
 * whatever the kind: a kind a hint can carry; `amrValues` it can vouch for and
 * `amrFor` within them, never empty; boolean flags; state and data that
 * survive the JSON round trip sealing puts them through, which the suite also
 * hands the factor back after; mail only beside the limits that bound it, a
 * challenge's to the address the enrollment mailed, and the code a message
 * sends never in the page's response; a hint that never shows the account's
 * address; a proof the factor cannot read answered `malformed`, never thrown;
 * and a valid proof that completes an enrollment and verifies the factor it
 * enrolled. The suite
 * enrolls at one instant and verifies an hour later, so a factor that refuses
 * reuse within a time step is not asked to verify at the step it enrolled.
 *
 * `createTestMfaFactor` is a factor with a trivial protocol; `createTestMfaDigests`
 * digests under a fixed test key. Published on `@o3co/auth-provider-core/testing`;
 * moves to the test-kit package with the other contract suites.
 */

import assert from "node:assert/strict";
import { createHmac, randomBytes } from "node:crypto";
import { FEDERATED_AMR, MFA_AMR, OTP_AMR, PASSWORD_AMR } from "../grants/authenticationClaims.mjs";
import type { MailMessage } from "../mail/types.mjs";
import type {
	MfaCeremonyContext,
	MfaChallenge,
	MfaDigestMatch,
	MfaDigests,
	MfaEnrolledFactor,
	MfaEnrollmentStart,
	MfaFactor,
	MfaFactorData,
	MfaKeyedDigest,
	MfaMailLimits,
} from "../mfa/factor.mjs";
import { constantTimeStringEqual } from "../security/timingSafe.mjs";
import { isHintToken } from "../session-admission/requirement.mjs";
import type { ContractCase } from "../session-admission/testing/requirement.contract.mjs";

export interface MfaFactorContractInput {
	/** A fresh factor for each case. */
	readonly build: () => MfaFactor;
	/** An account the factor can enroll, as the Store answers it (a `User`). */
	readonly user: Readonly<Record<string, unknown>>;
	/** The proof of possession that completes the enrollment `start` began, as a request carries it. */
	readonly enrollmentProof: (start: MfaEnrollmentStart, context: MfaCeremonyContext) => unknown;
	/**
	 * A proof that verifies `enrolled` at the context's time — after `challenge`,
	 * which the suite passes, when the factor has one.
	 */
	readonly verificationProof: (
		enrolled: MfaEnrolledFactor,
		challenge: MfaChallenge | undefined,
		context: MfaCeremonyContext,
	) => unknown;
	/** Proofs the factor cannot read. Default: `undefined`, `null`, a number and an empty object. */
	readonly malformedProofs?: readonly unknown[];
}

/** When the suite enrolls, and an hour later, when it verifies. */
const ENROLLED_AT_MS = Date.UTC(2026, 0, 1);
const VERIFIED_AT_MS = ENROLLED_AT_MS + 3_600_000;
const SUBJECT = "contract-subject";
const FACTOR_ID = "contract-factor-1";

const DEFAULT_MALFORMED: readonly unknown[] = [undefined, null, 1234, {}];

/** Whether `value` comes back from JSON as it went in. */
function survivesJson(value: unknown, what: string): void {
	let copy: unknown;
	try {
		copy = JSON.parse(JSON.stringify(value));
	} catch {
		assert.fail(`${what} cannot be written as JSON`);
	}
	assert.deepStrictEqual(copy, value, `${what} does not survive a JSON round trip`);
}

/** `value` as the coordinator hands it back after keeping it: through JSON. */
const reopened = <T,>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

/** Whether `response` carries `proof`, the code a message sends. */
function carries(response: unknown, proof: unknown): boolean {
	if (typeof proof !== "string" || proof.length === 0) return false;
	return (JSON.stringify(response) ?? "").includes(proof);
}

/**
 * A message the coordinator can send — a recipient, a subject and a text —
 * whose code, `proof`, the page's `response` does not carry: the code
 * travels only in the message.
 */
function checkMail(
	mail: unknown,
	factor: MfaFactor,
	what: string,
	response: unknown,
	proof: unknown,
): void {
	if (mail === undefined) return;
	assert.ok(
		factor.mailLimits !== undefined,
		`${what} answered mail, and the factor declares no mailLimits: the coordinator would send it unbounded`,
	);
	const { to, subject, text } = (mail ?? {}) as Partial<MailMessage>;
	for (const [part, value] of [
		["recipient", to],
		["subject", subject],
		["text", text],
	] as const) {
		assert.ok(typeof value === "string" && value.length > 0, `${what}'s mail has no ${part}`);
	}
	assert.ok(
		!carries(response, proof),
		`${what}'s response carries the code its mail sends: the page would hold what only the mailbox should`,
	);
}

/** Every call's context, at `nowMs`, under the transaction `transactionId`. */
const contextAt = (
	factor: MfaFactor,
	nowMs: number,
	transactionId: string,
): MfaCeremonyContext => ({
	subject: SUBJECT,
	transactionId,
	nowMs,
	request: { ip: "192.0.2.1", userAgent: "mfa-factor-contract" },
	digests: createTestMfaDigests(factor.kind),
});

/** The cases of the factor contract over the factors `input` builds. */
export function mfaFactorContract(input: MfaFactorContractInput): readonly ContractCase[] {
	const malformed = input.malformedProofs ?? DEFAULT_MALFORMED;

	const begin = async (factor: MfaFactor) => {
		const context = contextAt(factor, ENROLLED_AT_MS, "contract-enrollment");
		const start = await factor.beginEnrollment({ ...context, user: input.user, factors: [] });
		return { context, start };
	};

	/** The factor enrolled through its own ceremony, its data as the coordinator opens it, and the enrollment's start. */
	const enroll = async (
		factor: MfaFactor,
	): Promise<{ readonly enrolled: MfaEnrolledFactor; readonly start: MfaEnrollmentStart }> => {
		const { context, start } = await begin(factor);
		const done = await factor.completeEnrollment({
			...context,
			user: input.user,
			factors: [],
			state: reopened(start.state),
			proof: await input.enrollmentProof(start, context),
		});
		assert.ok(
			done.ok,
			`the proof of possession did not complete the enrollment: ${JSON.stringify(done)}`,
		);
		return {
			enrolled: {
				id: FACTOR_ID,
				label: done.label,
				createdAt: new Date(ENROLLED_AT_MS),
				lastUsedAt: undefined,
				data: reopened(done.data),
			},
			start,
		};
	};

	/** A challenge of `enrolled`, when the factor has one, an hour after the enrollment. */
	const challenge = async (factor: MfaFactor, enrolled: MfaEnrolledFactor) => {
		const context = contextAt(factor, VERIFIED_AT_MS, "contract-verification");
		const sent =
			factor.challenge === undefined
				? undefined
				: await factor.challenge({ ...context, factor: enrolled, factors: [enrolled] });
		return { context, sent };
	};

	return [
		{
			name: "kind is a hint token: a lowercase letter, then up to 63 lowercase letters, digits, _ or -",
			run: async () => {
				const { kind } = input.build();
				assert.ok(isHintToken(kind), `kind ${JSON.stringify(kind)} is not one a hint can carry`);
			},
		},
		{
			name: "amrValues is a non-empty list of distinct non-empty strings, with no primary's marker and no mfa",
			run: async () => {
				const { amrValues } = input.build();
				assert.ok(Array.isArray(amrValues) && amrValues.length > 0, "amrValues is empty");
				assert.equal(new Set(amrValues).size, amrValues.length, "amrValues repeats a value");
				for (const value of amrValues) {
					assert.ok(
						typeof value === "string" && value.length > 0,
						"amrValues holds an empty value",
					);
					assert.ok(
						![PASSWORD_AMR, FEDERATED_AMR, MFA_AMR].includes(value),
						`amrValues holds ${value}: a second factor never adds a primary's marker, and mfa is addsMfa's`,
					);
				}
			},
		},
		{
			name: "addsMfa, counting and guessable are true or false, and reusableChallenge true, false or absent",
			run: async () => {
				const factor = input.build();
				for (const flag of ["addsMfa", "counting", "guessable"] as const) {
					assert.equal(typeof factor[flag], "boolean", `${flag} is not true or false`);
				}
				assert.ok(
					factor.reusableChallenge === undefined || typeof factor.reusableChallenge === "boolean",
					"reusableChallenge is neither true, false nor absent",
				);
			},
		},
		{
			name: "mailLimits, when declared, allow at least one send, in whole numbers of sends and seconds",
			run: async () => {
				const { mailLimits } = input.build();
				if (mailLimits === undefined) return;
				assert.ok(
					Number.isSafeInteger(mailLimits.maxSends) && mailLimits.maxSends >= 1,
					`mailLimits.maxSends ${String(mailLimits.maxSends)} allows no send`,
				);
				assert.ok(
					Number.isSafeInteger(mailLimits.resendAfterSeconds) && mailLimits.resendAfterSeconds >= 0,
					`mailLimits.resendAfterSeconds ${String(mailLimits.resendAfterSeconds)} is not a whole number of seconds`,
				);
			},
		},
		{
			name: "enrollable, when present, answers true for an account that can enroll the factor",
			run: async () => {
				const factor = input.build();
				if (factor.enrollable === undefined) return;
				assert.equal(factor.enrollable(input.user), true, "enrollable refuses the account");
			},
		},
		{
			name: "beginEnrollment answers state that survives a JSON round trip, and mail only beside mailLimits, as a message with a recipient, a subject and a text, whose code the response does not carry",
			run: async () => {
				const factor = input.build();
				const { context, start } = await begin(factor);
				survivesJson(start.state, "the pending enrollment's state");
				checkMail(
					start.mail,
					factor,
					"beginEnrollment",
					start.response,
					await input.enrollmentProof(start, context),
				);
			},
		},
		{
			name: "completeEnrollment answers malformed for a proof it cannot read, and never throws for one",
			run: async () => {
				const factor = input.build();
				const { context, start } = await begin(factor);
				for (const proof of malformed) {
					const done = await factor.completeEnrollment({
						...context,
						user: input.user,
						factors: [],
						state: reopened(start.state),
						proof,
					});
					assert.deepEqual(done, { ok: false, reason: "malformed" }, `the proof ${String(proof)}`);
				}
			},
		},
		{
			name: "completeEnrollment takes the proof of possession, and answers data that survives a JSON round trip, a label that is a string when present, and at least one amr value, each among amrValues",
			run: async () => {
				const factor = input.build();
				const { context, start } = await begin(factor);
				const done = await factor.completeEnrollment({
					...context,
					user: input.user,
					factors: [],
					state: reopened(start.state),
					proof: await input.enrollmentProof(start, context),
				});
				assert.ok(
					done.ok,
					`the proof of possession did not complete the enrollment: ${JSON.stringify(done)}`,
				);
				survivesJson(done.data, "the enrolled factor's data");
				assert.ok(
					done.label === undefined || typeof done.label === "string",
					"the label is not a string",
				);
				const amr = factor.amrFor(reopened(done.data));
				assert.ok(amr.length > 0, "amrFor answers no value: a verification would add nothing");
				for (const value of amr) {
					assert.ok(
						factor.amrValues.includes(value),
						`amrFor answers ${value}, which amrValues does not declare`,
					);
				}
			},
		},
		{
			name: "describe answers a hint that is a string, or none, and never the account's address",
			run: async () => {
				const factor = input.build();
				const { hint } = factor.describe((await enroll(factor)).enrolled.data);
				assert.ok(hint === undefined || typeof hint === "string", "the hint is not a string");
				const { email } = input.user;
				assert.ok(
					typeof email !== "string" || email === "" || !(hint ?? "").includes(email),
					"the hint shows the account's address, which a page may show to whoever holds the password",
				);
			},
		},
		{
			name: "challenge, when present, answers state that survives a JSON round trip, and mail only beside mailLimits, as a message with a recipient, a subject and a text, to the address the enrollment mailed, whose code the response does not carry",
			run: async () => {
				const factor = input.build();
				if (factor.challenge === undefined) return;
				const { enrolled, start } = await enroll(factor);
				const { context, sent } = await challenge(factor, enrolled);
				if (sent?.state !== undefined) survivesJson(sent.state, "the challenge's state");
				checkMail(
					sent?.mail,
					factor,
					"challenge",
					sent?.response,
					sent === undefined ? undefined : await input.verificationProof(enrolled, sent, context),
				);
				if (sent?.mail !== undefined && start.mail !== undefined) {
					assert.equal(
						sent.mail.to,
						start.mail.to,
						"the challenge mails another address than the one the enrollment proved",
					);
				}
			},
		},
		{
			name: "verify answers malformed for a proof it cannot read, and never throws for one",
			run: async () => {
				const factor = input.build();
				const { enrolled } = await enroll(factor);
				for (const proof of malformed) {
					const { context, sent } = await challenge(factor, enrolled);
					const verdict = await factor.verify({
						...context,
						factor: enrolled,
						factors: [enrolled],
						state: sent?.state === undefined ? undefined : reopened(sent.state),
						proof,
					});
					assert.deepEqual(
						verdict,
						{ ok: false, reason: "malformed" },
						`the proof ${String(proof)}`,
					);
				}
			},
		},
		{
			name: "verify takes a valid proof, names a factor the subject holds, and answers next data that survives a JSON round trip",
			run: async () => {
				const factor = input.build();
				const { enrolled } = await enroll(factor);
				const { context, sent } = await challenge(factor, enrolled);
				const verdict = await factor.verify({
					...context,
					factor: enrolled,
					factors: [enrolled],
					state: sent?.state === undefined ? undefined : reopened(sent.state),
					proof: await input.verificationProof(enrolled, sent, context),
				});
				assert.ok(verdict.ok, `a valid proof was refused: ${JSON.stringify(verdict)}`);
				assert.equal(
					verdict.factorId,
					enrolled.id,
					"the verification names a factor the subject does not hold",
				);
				if (verdict.next !== undefined) survivesJson(verdict.next, "the factor's next data");
			},
		},
	];
}

// ---------------------------------------------------------------------------
// The digests a factor's tests hand it
// ---------------------------------------------------------------------------

/** The one key the test digests are made under, by id. */
const TEST_DIGEST_KEY_ID = "test-key";
const TEST_DIGEST_KEY = Buffer.from("o3co:mfa:test-digests-key:000000", "utf8");

/** `parts` bound to `kind`, each length-prefixed, so no part can move into its neighbour. */
function framed(kind: string, parts: readonly string[]): Buffer {
	return Buffer.concat(
		[kind, ...parts].flatMap((part) => {
			const bytes = Buffer.from(part, "utf8");
			const length = Buffer.alloc(4);
			length.writeUInt32BE(bytes.length);
			return [length, bytes];
		}),
	);
}

/**
 * Keyed digests for a factor of `kind` under one fixed test key, as the
 * coordinator makes them under the ring: HMAC-SHA-256 over the kind and the
 * parts, each length-prefixed, compared in constant time; a digest naming
 * another key is `key_unavailable`. For tests only: the key is public.
 */
export function createTestMfaDigests(kind: string): MfaDigests {
	const digestOf = (parts: readonly string[]): string =>
		createHmac("sha256", TEST_DIGEST_KEY).update(framed(kind, parts)).digest("base64url");
	return {
		digest: (parts): MfaKeyedDigest => ({ keyId: TEST_DIGEST_KEY_ID, digest: digestOf(parts) }),
		matchesDigest: (parts, stored): MfaDigestMatch => {
			if (stored.keyId !== TEST_DIGEST_KEY_ID) return "key_unavailable";
			return constantTimeStringEqual(digestOf(parts), stored.digest) ? "match" : "mismatch";
		},
	};
}

// ---------------------------------------------------------------------------
// The factor double
// ---------------------------------------------------------------------------

export interface TestMfaFactorOptions {
	/** Default `test`. */
	readonly kind?: string;
	/** Default `["otp"]`; `amrFor` answers them all. */
	readonly amrValues?: readonly string[];
	/** Default true. */
	readonly addsMfa?: boolean;
	/** Default true. */
	readonly counting?: boolean;
	/** Default false. */
	readonly guessable?: boolean;
	/**
	 * Mail the enrollment's code to the account's `email`, and a code at each
	 * challenge, under these limits; the factor is then enrollable only by an
	 * account with an address. Absent: the enrollment answers its secret
	 * (as an authenticator app's is shown), and there is no challenge.
	 */
	readonly mail?: MfaMailLimits;
}

/** The code in a message the double sent: its text's last word. */
const codeIn = (mail: MailMessage | undefined): string | undefined => mail?.text.split(" ").at(-1);

/**
 * A second factor with a trivial protocol, for tests: without `mail`, the
 * enrollment answers a random secret and a verification is that secret;
 * with it, the enrollment mails a code the proof of possession must repeat,
 * each challenge mails another, and a verification is the latest one.
 * {@link testMfaFactorProofs} reads the proofs back. A proof that is not a
 * string is `malformed`.
 */
export function createTestMfaFactor(options: TestMfaFactorOptions = {}): MfaFactor {
	const amrValues = Object.freeze([...(options.amrValues ?? [OTP_AMR])]);
	const mailLimits = options.mail === undefined ? undefined : Object.freeze({ ...options.mail });
	const newCode = (): string => randomBytes(8).toString("hex");
	const addressOf = (user: Readonly<Record<string, unknown>>): string | undefined =>
		typeof user.email === "string" && user.email.length > 0 ? user.email : undefined;
	const message = (to: string, code: string): MailMessage => ({
		to,
		subject: "Your test code",
		text: `Your test code is ${code}`,
	});
	const factor: MfaFactor = {
		kind: options.kind ?? "test",
		amrValues,
		amrFor: () => amrValues,
		addsMfa: options.addsMfa ?? true,
		counting: options.counting ?? true,
		guessable: options.guessable ?? false,
		describe: (data: MfaFactorData) =>
			typeof data.address === "string" ? { hint: `${data.address.slice(0, 1)}***` } : {},
		beginEnrollment: async (ctx) => {
			const secret = newCode();
			if (mailLimits === undefined) return { state: { secret }, response: { secret } };
			const address = addressOf(ctx.user);
			if (address === undefined)
				throw new RangeError("createTestMfaFactor: the account has no email");
			return {
				state: { secret, address },
				response: { sent: true },
				mail: message(address, secret),
			};
		},
		completeEnrollment: async (ctx) => {
			if (typeof ctx.proof !== "string") return { ok: false, reason: "malformed" };
			if (ctx.proof !== ctx.state.secret) return { ok: false, reason: "invalid" };
			const { secret, address } = ctx.state;
			return { ok: true, data: address === undefined ? { secret } : { secret, address } };
		},
		verify: async (ctx) => {
			if (typeof ctx.proof !== "string") return { ok: false, reason: "malformed" };
			const expected = mailLimits === undefined ? ctx.factor.data.secret : ctx.state?.code;
			if (expected === undefined) return { ok: false, reason: "expired" };
			return ctx.proof === expected
				? { ok: true, factorId: ctx.factor.id }
				: { ok: false, reason: "invalid" };
		},
		...(mailLimits === undefined
			? {}
			: {
					mailLimits,
					reusableChallenge: true,
					enrollable: (user: Readonly<Record<string, unknown>>) => addressOf(user) !== undefined,
					challenge: async (ctx) => {
						const code = newCode();
						return {
							state: { code },
							response: { sent: true },
							mail: message(String(ctx.factor.data.address), code),
						};
					},
				}),
	};
	return factor;
}

/**
 * The proofs of {@link createTestMfaFactor}: the enrollment's secret, or the
 * code its message carried; a verification's secret, or the code the
 * challenge mailed. An input to {@link mfaFactorContract} beside the double.
 */
export const testMfaFactorProofs: {
	readonly enrollmentProof: (start: MfaEnrollmentStart) => unknown;
	readonly verificationProof: (
		enrolled: MfaEnrolledFactor,
		challenge: MfaChallenge | undefined,
	) => unknown;
} = Object.freeze({
	enrollmentProof: (start: MfaEnrollmentStart) =>
		start.mail === undefined ? (start.response as { secret?: unknown }).secret : codeIn(start.mail),
	verificationProof: (enrolled: MfaEnrolledFactor, challenge: MfaChallenge | undefined) =>
		challenge === undefined ? enrolled.data.secret : codeIn(challenge.mail),
});
