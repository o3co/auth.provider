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
 * The conformance suite of a second factor — a value of core's `mfaFactors`
 * contribution kind.
 *
 * `mfaFactorContract(input)` holds a factor to what the coordinator relies on
 * whatever the kind: a kind a hint can carry; `amrValues` it can vouch for and
 * `amrFor` within them, never empty; boolean flags; state and data that
 * survive the JSON round trip sealing puts them through, which the suite also
 * hands the factor back after; a hint that never shows the account's
 * address; a proof the factor cannot read answered `malformed`, never thrown;
 * and a valid proof that completes an enrollment and verifies the factor it
 * enrolled. The suite enrolls at one instant and verifies an hour later, so a
 * factor that refuses reuse within a time step is not asked to verify at the
 * step it enrolled. Every call is handed core's test digests
 * (`createTestMfaDigests`), made for the factor's kind.
 */

import assert from "node:assert/strict";
import {
	FEDERATED_AMR,
	isHintToken,
	MFA_AMR,
	type MfaCeremonyContext,
	type MfaEnrolledFactor,
	type MfaFactor,
	PASSWORD_AMR,
} from "@o3co/auth-provider-core";
import { type ContractCase, createTestMfaDigests } from "@o3co/auth-provider-core/testing";

/** What the start of an enrollment answers: the state the coordinator keeps, and the page's response. */
export type MfaFactorEnrollmentStart = Awaited<ReturnType<MfaFactor["beginEnrollment"]>>;

/** What a challenge answers: the state the coordinator keeps, if any, and the page's response. */
export type MfaFactorChallenge = Awaited<ReturnType<NonNullable<MfaFactor["challenge"]>>>;

export interface MfaFactorContractInput {
	/** A fresh factor for each case. */
	readonly build: () => MfaFactor;
	/** An account the factor can enroll, as the Store answers it (a `User`). */
	readonly user: Readonly<Record<string, unknown>>;
	/** The proof of possession that completes the enrollment `start` began, as a request carries it. */
	readonly enrollmentProof: (
		start: MfaFactorEnrollmentStart,
		context: MfaCeremonyContext,
	) => unknown;
	/**
	 * A proof that verifies `enrolled` at the context's time — after `challenge`,
	 * which the suite passes, when the factor has one.
	 */
	readonly verificationProof: (
		enrolled: MfaEnrolledFactor,
		challenge: MfaFactorChallenge | undefined,
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

	/** The factor enrolled through its own ceremony, its data as the coordinator opens it. */
	const enroll = async (factor: MfaFactor): Promise<MfaEnrolledFactor> => {
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
			id: FACTOR_ID,
			label: done.label,
			createdAt: new Date(ENROLLED_AT_MS),
			lastUsedAt: undefined,
			data: reopened(done.data),
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
			name: "enrollable, when present, answers true for an account that can enroll the factor",
			run: async () => {
				const factor = input.build();
				if (factor.enrollable === undefined) return;
				assert.equal(factor.enrollable(input.user), true, "enrollable refuses the account");
			},
		},
		{
			name: "beginEnrollment answers state that survives a JSON round trip",
			run: async () => {
				const factor = input.build();
				const { start } = await begin(factor);
				survivesJson(start.state, "the pending enrollment's state");
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
				const { hint } = factor.describe((await enroll(factor)).data);
				assert.ok(hint === undefined || typeof hint === "string", "the hint is not a string");
				const { email } = input.user;
				assert.ok(
					typeof email !== "string" || email === "" || !(hint ?? "").includes(email),
					"the hint shows the account's address, which a page may show to whoever holds the password",
				);
			},
		},
		{
			name: "challenge, when present, answers state that survives a JSON round trip",
			run: async () => {
				const factor = input.build();
				if (factor.challenge === undefined) return;
				const { sent } = await challenge(factor, await enroll(factor));
				if (sent?.state !== undefined) survivesJson(sent.state, "the challenge's state");
			},
		},
		{
			name: "verify answers malformed for a proof it cannot read, and never throws for one",
			run: async () => {
				const factor = input.build();
				const enrolled = await enroll(factor);
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
				const enrolled = await enroll(factor);
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
