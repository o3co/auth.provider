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
import { normaliseMailAddress } from "#/mail/address.mjs";
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

describe("createTestMfaFactor with mail", () => {
	const ctx = {
		subject: USER.id,
		transactionId: "tx",
		nowMs: 0,
		request: {},
		digests: createTestMfaDigests("test"),
	};

	/** The keyed digest of `email` as the coordinator makes it when it mails a code there. */
	const sentTo = (email: string) => ctx.digests.digest([normaliseMailAddress(email) as string]);

	it("is enrollable only by an account whose address normaliseMailAddress reads, and keeps a challenge across attempts", () => {
		const factor = createTestMfaFactor({ mail: true });
		expect(factor.enrollable?.(USER)).toBe(true);
		expect(factor.enrollable?.({ id: "u-2", email: " Contract@Example.COM " })).toBe(true);
		for (const email of [undefined, "", " ", "contract", "@example.com", "contract@", 7]) {
			expect(factor.enrollable?.({ id: "u-2", email }), String(email)).toBe(false);
		}
		expect(factor.reusableChallenge).toBe(true);
	});

	it("records the address digest its completion is handed — of the address its code went to — never one of the account's address as it reads by then, and completes nothing without one", async () => {
		const factor = createTestMfaFactor({ mail: true });
		const start = await factor.beginEnrollment({ ...ctx, user: USER, factors: [] });
		const complete = (extra: object) =>
			factor.completeEnrollment({
				...ctx,
				user: { ...USER, email: "mallory@attacker.example" },
				factors: [],
				state: start.state,
				proof: testMfaFactorProofs.enrollmentProof(start),
				...extra,
			});
		expect(await complete({ addressDigest: sentTo(USER.email) })).toEqual({
			ok: true,
			data: { addressDigest: sentTo(USER.email) },
		});
		for (const addressDigest of [undefined, null, "digest", { keyId: "test-key" }]) {
			expect(await complete({ addressDigest }), JSON.stringify(addressDigest)).toEqual({
				ok: false,
				reason: "expired",
			});
		}
	});

	it("mails a login code with a null address digest when its data holds none it can read, never with a value that is none", async () => {
		const factor = createTestMfaFactor({ mail: true });
		const challenge = factor.challenge as NonNullable<MfaFactor["challenge"]>;
		for (const data of [
			{},
			{ addressDigest: null },
			{ addressDigest: "digest" },
			{ addressDigest: { keyId: "test-key" } },
			{ addressDigest: { keyId: 1, digest: 2 } },
		]) {
			const enrolled = {
				id: "f-1",
				label: undefined,
				createdAt: new Date(0),
				lastUsedAt: undefined,
				data,
			};
			const sent = await challenge({ ...ctx, factor: enrolled, factors: [enrolled] });
			expect(sent.mail?.purpose, JSON.stringify(data)).toBe("login_code");
			expect(sent.mail?.addressDigest, JSON.stringify(data)).toBeNull();
		}
	});

	it("keeps the digest a verification is handed when it was made under another key than the one recorded, and nothing it was not handed", async () => {
		const factor = createTestMfaFactor({ mail: true });
		const enrolled = {
			id: "f-1",
			label: undefined,
			createdAt: new Date(0),
			lastUsedAt: undefined,
			data: { addressDigest: sentTo(USER.email) },
		};
		const challenge = factor.challenge as NonNullable<MfaFactor["challenge"]>;
		const sent = await challenge({ ...ctx, factor: enrolled, factors: [enrolled] });
		const rotated = createTestMfaDigests("test", { rotated: true });
		const handed = rotated.digest([normaliseMailAddress(USER.email) as string]);
		const verify = (addressDigest: unknown) =>
			factor.verify({
				...ctx,
				digests: rotated,
				factor: enrolled,
				factors: [enrolled],
				state: sent.state,
				proof: testMfaFactorProofs.verificationProof(enrolled, sent),
				addressDigest: addressDigest as never,
			});
		expect(await verify(handed)).toEqual({
			ok: true,
			factorId: "f-1",
			next: { addressDigest: handed },
		});
		expect(await verify(sentTo(USER.email))).toEqual({ ok: true, factorId: "f-1" });
		for (const addressDigest of [undefined, null, "digest", { keyId: "test-key-2" }]) {
			expect(await verify(addressDigest), JSON.stringify(addressDigest)).toEqual({
				ok: true,
				factorId: "f-1",
			});
		}
	});

	it("asks for its enrollment code and each challenge's code to be mailed, each with an expiry ten minutes on and a new code at each challenge, a login code with the digest of the address it confirmed, never answering them to the page, and verifies the latest", async () => {
		const factor = createTestMfaFactor({ mail: true });
		const start = await factor.beginEnrollment({ ...ctx, user: USER, factors: [] });
		expect(start.mail).toEqual({
			purpose: "email_factor_enrollment",
			code: expect.any(String),
			expiresAtMs: ctx.nowMs + 600_000,
		});
		expect(JSON.stringify(start.response)).not.toContain(start.mail?.code);
		expect(testMfaFactorProofs.enrollmentProof(start)).toBe(start.mail?.code);
		const done = await factor.completeEnrollment({
			...ctx,
			user: USER,
			factors: [],
			state: start.state,
			proof: testMfaFactorProofs.enrollmentProof(start),
			addressDigest: sentTo(USER.email),
		});
		if (!done.ok) throw new Error("the mailed code did not complete the enrollment");
		// It keeps the keyed digest of the address it confirmed, never the address.
		expect(JSON.stringify(done.data)).not.toContain(USER.email);
		const digests = createTestMfaDigests("test");
		expect(
			digests.matchesDigest(
				[normaliseMailAddress(USER.email) as string],
				done.data.addressDigest as never,
			),
		).toBe("match");
		const enrolled = {
			id: "f-1",
			label: undefined,
			createdAt: new Date(0),
			lastUsedAt: undefined,
			data: done.data,
		};
		const challenge = factor.challenge as NonNullable<MfaFactor["challenge"]>;
		const first = await challenge({ ...ctx, factor: enrolled, factors: [enrolled] });
		const second = await challenge({ ...ctx, factor: enrolled, factors: [enrolled] });
		expect(second.mail).toEqual({
			purpose: "login_code",
			code: expect.any(String),
			expiresAtMs: ctx.nowMs + 600_000,
			addressDigest: done.data.addressDigest,
		});
		expect(second.mail?.code).not.toBe(first.mail?.code);
		expect(JSON.stringify(second.response)).not.toContain(second.mail?.code);
		const verify = (proof: unknown) =>
			factor.verify({
				...ctx,
				factor: enrolled,
				factors: [enrolled],
				state: second.state,
				proof,
			});
		expect(await verify(testMfaFactorProofs.verificationProof(enrolled, second))).toEqual({
			ok: true,
			factorId: "f-1",
		});
		expect(await verify(testMfaFactorProofs.verificationProof(enrolled, first))).toEqual({
			ok: false,
			reason: "invalid",
		});
		expect(await verify(7)).toEqual({ ok: false, reason: "malformed" });
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
		expect(
			digests.matchesDigest(["x"], createTestMfaDigests("email", { rotated: true }).digest(["x"])),
		).toBe("key_unavailable");
	});

	it("rotated, digests under a second test key first, and still matches what the first key made", () => {
		const first = createTestMfaDigests("email");
		const rotated = createTestMfaDigests("email", { rotated: true });
		const made = rotated.digest(["x"]);
		expect(made.keyId).toBe("test-key-2");
		expect(made.digest).not.toBe(first.digest(["x"]).digest);
		expect(rotated.matchesDigest(["x"], made)).toBe("match");
		expect(rotated.matchesDigest(["x"], first.digest(["x"]))).toBe("match");
		expect(rotated.matchesDigest(["y"], first.digest(["x"]))).toBe("mismatch");
		expect(rotated.matchesDigest(["x"], { ...made, keyId: "retired" })).toBe("key_unavailable");
	});
});
