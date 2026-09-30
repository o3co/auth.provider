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
 * The doubles a second factor's tests use: the factor with a trivial
 * protocol, the proofs it takes, and keyed digests under a fixed test key.
 */

import { describe, expect, it } from "vitest";
import type { MfaFactor } from "#/mfa/factor.mjs";
import {
	createTestMfaDigests,
	createTestMfaFactor,
	testMfaFactorProofs,
} from "#/testing/index.mjs";

const USER = { id: "u-contract", username: "contract", email: "contract@example.com" };

describe("createTestMfaFactor", () => {
	it("is a counting, non-guessable factor of kind test adding otp and mfa, with a challenge only when asked for one", () => {
		const factor = createTestMfaFactor();
		expect(factor).toMatchObject({
			kind: "test",
			amrValues: ["otp"],
			addsMfa: true,
			counting: true,
			guessable: false,
		});
		expect(factor.challenge).toBeUndefined();
		expect(typeof createTestMfaFactor({ challenge: true }).challenge).toBe("function");
	});

	it("completes an enrollment with the secret it answered, then verifies that secret alone; a proof that is not a string is malformed", async () => {
		const factor = createTestMfaFactor({ amrValues: ["hwk"] });
		const ctx = {
			subject: USER.id,
			transactionId: "tx",
			nowMs: 0,
			request: {},
			digests: createTestMfaDigests("test"),
		};
		const start = await factor.beginEnrollment({ ...ctx, user: USER, factors: [] });
		const complete = (proof: unknown) =>
			factor.completeEnrollment({ ...ctx, user: USER, factors: [], state: start.state, proof });
		expect(await complete(7)).toEqual({ ok: false, reason: "malformed" });
		expect(await complete("not-the-secret")).toEqual({ ok: false, reason: "invalid" });
		const done = await complete(testMfaFactorProofs.enrollmentProof(start));
		if (!done.ok) throw new Error("the enrollment's own secret did not complete it");
		const enrolled = {
			id: "f-1",
			label: undefined,
			createdAt: new Date(0),
			lastUsedAt: undefined,
			data: done.data,
		};
		expect(factor.amrFor(enrolled.data)).toEqual(["hwk"]);
		expect(factor.describe(enrolled.data)).toEqual({});
		const verify = (proof: unknown) =>
			factor.verify({ ...ctx, factor: enrolled, factors: [enrolled], state: undefined, proof });
		expect(await verify(testMfaFactorProofs.verificationProof(enrolled, undefined))).toEqual({
			ok: true,
			factorId: "f-1",
		});
		expect(await verify("not-the-secret")).toEqual({ ok: false, reason: "invalid" });
		expect(await verify(null)).toEqual({ ok: false, reason: "malformed" });
	});

	it("verifies after a challenge only the secret beside the nonce that challenge answered", async () => {
		const factor = createTestMfaFactor({ challenge: true });
		const ctx = {
			subject: USER.id,
			transactionId: "tx",
			nowMs: 0,
			request: {},
			digests: createTestMfaDigests("test"),
		};
		const enrolled = {
			id: "f-1",
			label: undefined,
			createdAt: new Date(0),
			lastUsedAt: undefined,
			data: { secret: "s3cret" },
		};
		const challenge = factor.challenge as NonNullable<MfaFactor["challenge"]>;
		const first = await challenge({ ...ctx, factor: enrolled, factors: [enrolled] });
		const second = await challenge({ ...ctx, factor: enrolled, factors: [enrolled] });
		const verify = (state: unknown, proof: unknown) =>
			factor.verify({
				...ctx,
				factor: enrolled,
				factors: [enrolled],
				state: state as never,
				proof,
			});
		expect(
			await verify(second.state, testMfaFactorProofs.verificationProof(enrolled, second)),
		).toEqual({ ok: true, factorId: "f-1" });
		expect(
			await verify(second.state, testMfaFactorProofs.verificationProof(enrolled, first)),
		).toEqual({ ok: false, reason: "invalid" });
		expect(await verify(undefined, "s3cret:x")).toEqual({ ok: false, reason: "expired" });
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
