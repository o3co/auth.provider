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
 * The `totp` second factor, as core's `MfaFactor` contract states it. See ADR
 * 2026-09-25-multi-factor-authentication.
 *
 * Its proof is guessable, so the subject lock applies to it. A verification
 * checks the named factor at the steps the window allows, only after the
 * factor's `lastUsedStep`, and answers the step it matched as the factor's
 * next data, which the coordinator writes by compare-and-set: a code used
 * once, or an older one, is `replayed`. The parameters are the factor's own,
 * so a configuration change never breaks an enrollment; the window is the
 * configuration's.
 */

import {
	type MfaDigests,
	type MfaEnrolledFactor,
	type MfaEnrollmentCompletionContext,
	type MfaEnrollmentContext,
	type MfaFactor,
	type MfaFactorData,
	type MfaVerifyContext,
	OTP_AMR,
} from "@o3co/auth-provider-core";
import { mfaFactorContract } from "@o3co/auth-provider-test-kit";
import { describe, expect, it } from "vitest";
import { decodeBase32, encodeBase32 } from "#/totp/base32.mjs";
import { createTotpFactor, type TotpFactorSettings } from "#/totp/factor.mjs";
import { hotp, type TotpAlgorithm, totpStep } from "#/totp/rfc6238.mjs";

const SETTINGS: TotpFactorSettings = {
	algorithm: "SHA1",
	digits: 6,
	period: 30,
	window: 1,
	issuer: "auth.example",
};

const SECRET = Buffer.from("12345678901234567890", "ascii");
const T = 60_000_000;
/** Twelve seconds into step T. */
const NOW_MS = T * 30_000 + 12_000;

/** The factor never digests anything; a call is a failure. */
const digests: MfaDigests = {
	digest: () => {
		throw new Error("the TOTP factor digests nothing");
	},
	matchesDigest: () => {
		throw new Error("the TOTP factor digests nothing");
	},
};

const ceremony = { subject: "u-alice", transactionId: "tx-1", request: {}, digests } as const;

const dataOf = (overrides: Record<string, unknown> = {}): MfaFactorData => ({
	secret: encodeBase32(SECRET),
	algorithm: "SHA1",
	digits: 6,
	period: 30,
	lastUsedStep: T - 5,
	...overrides,
});

const enrolled = (data: MfaFactorData, id = "f-1"): MfaEnrolledFactor => ({
	id,
	label: undefined,
	createdAt: new Date(0),
	lastUsedAt: undefined,
	data,
});

const codeAt = (
	step: number,
	secret: Buffer = SECRET,
	algorithm: TotpAlgorithm = "SHA1",
	digits = 6,
) => hotp(secret, step, { algorithm, digits });

function verifyContext(
	proof: unknown,
	factor: MfaEnrolledFactor = enrolled(dataOf()),
	overrides: Partial<MfaVerifyContext> = {},
): MfaVerifyContext {
	return {
		...ceremony,
		nowMs: NOW_MS,
		factor,
		factors: [factor],
		state: undefined,
		proof,
		...overrides,
	};
}

const USER = { id: "u-alice", username: "alice", email: "alice@example.com" };

function enrollmentContext(user: Record<string, unknown> = USER): MfaEnrollmentContext {
	return { ...ceremony, nowMs: NOW_MS, user, factors: [] };
}

function completionContext(
	state: Record<string, unknown>,
	proof: unknown,
	nowMs = NOW_MS,
): MfaEnrollmentCompletionContext {
	return { ...ceremony, nowMs, user: USER, factors: [], state, proof };
}

describe("the totp factor's declaration", () => {
	const factor: MfaFactor = createTotpFactor(SETTINGS);

	it("is the kind totp, adds otp and mfa, counts as MFA, and is guessable", () => {
		expect(factor.kind).toBe("totp");
		expect(factor.amrValues).toEqual([OTP_AMR]);
		expect(OTP_AMR).toBe("otp");
		expect(factor.addsMfa).toBe(true);
		expect(factor.counting).toBe(true);
		expect(factor.guessable).toBe(true);
	});

	it("needs no challenge, and declares no enrollable check: it is offered to every account", () => {
		expect(factor.challenge).toBeUndefined();
		expect(factor.reusableChallenge).toBeUndefined();
		expect(factor.enrollable).toBeUndefined();
	});

	it("answers from amrFor only values amrValues declares, never mfa", () => {
		for (const data of [dataOf(), dataOf({ algorithm: "SHA512", digits: 8 }), {}]) {
			const values = factor.amrFor(data);
			expect(values.length).toBeGreaterThan(0);
			for (const value of values) expect(factor.amrValues).toContain(value);
			expect(values).not.toContain("mfa");
		}
	});

	it("describes a factor with no hint: nothing about its secret reaches the page", () => {
		expect(factor.describe(dataOf())).toEqual({});
	});
});

describe("verifying a TOTP code", () => {
	const factor = createTotpFactor(SETTINGS);

	it("accepts the current code, naming the factor, and answers the step as the factor's next data", async () => {
		const data = dataOf();
		const result = await factor.verify(verifyContext(codeAt(T), enrolled(data)));
		expect(result).toEqual({ ok: true, factorId: "f-1", next: { ...data, lastUsedStep: T } });
		// The coordinator seals what it is handed as JSON.
		if (result.ok) expect(JSON.parse(JSON.stringify(result.next))).toEqual(result.next);
	});

	it("accepts a code within the window, at its own step", async () => {
		expect(await factor.verify(verifyContext(codeAt(T + 1)))).toMatchObject({
			ok: true,
			next: { lastUsedStep: T + 1 },
		});
		expect(await factor.verify(verifyContext(codeAt(T - 1)))).toMatchObject({
			ok: true,
			next: { lastUsedStep: T - 1 },
		});
	});

	it("refuses the same code a second time, and an older code once a newer one was accepted, as replayed", async () => {
		const first = await factor.verify(verifyContext(codeAt(T)));
		expect(first.ok).toBe(true);
		const after = enrolled((first as { next: MfaFactorData }).next);
		expect(await factor.verify(verifyContext(codeAt(T), after))).toEqual({
			ok: false,
			reason: "replayed",
		});
		expect(await factor.verify(verifyContext(codeAt(T - 1), after))).toEqual({
			ok: false,
			reason: "replayed",
		});
		// The next step is still accepted.
		expect(await factor.verify(verifyContext(codeAt(T + 1), after))).toMatchObject({
			ok: true,
			next: { lastUsedStep: T + 1 },
		});
	});

	it("refuses a code outside the configured window as invalid", async () => {
		const narrow = createTotpFactor({ ...SETTINGS, window: 0 });
		expect(await narrow.verify(verifyContext(codeAt(T - 1)))).toEqual({
			ok: false,
			reason: "invalid",
		});
		expect(await factor.verify(verifyContext(codeAt(T + 2)))).toEqual({
			ok: false,
			reason: "invalid",
		});
	});

	it("verifies under the factor's own parameters, whatever the configuration says now", async () => {
		const secret = Buffer.alloc(32, 7);
		const data = dataOf({
			secret: encodeBase32(secret),
			algorithm: "SHA256",
			digits: 8,
			period: 60,
			// A step of its own period: T - 5 counts 30-second steps.
			lastUsedStep: totpStep(NOW_MS, 60) - 1,
		});
		const step = totpStep(NOW_MS, 60);
		const code = codeAt(step, secret, "SHA256", 8);
		expect(await factor.verify(verifyContext(code, enrolled(data)))).toEqual({
			ok: true,
			factorId: "f-1",
			next: { ...data, lastUsedStep: step },
		});
	});

	it("checks the factor the request named, not another of the subject's", async () => {
		const other = Buffer.alloc(20, 9);
		const named = enrolled(dataOf(), "f-named");
		const sibling = enrolled(dataOf({ secret: encodeBase32(other) }), "f-other");
		expect(
			await factor.verify(verifyContext(codeAt(T, other), named, { factors: [named, sibling] })),
		).toEqual({ ok: false, reason: "invalid" });
	});

	it("refuses a wrong code as invalid", async () => {
		const wrong = String((Number(codeAt(T)) + 1) % 1_000_000).padStart(6, "0");
		expect(await factor.verify(verifyContext(wrong))).toEqual({ ok: false, reason: "invalid" });
	});

	it("refuses a proof it cannot read as malformed", async () => {
		const code = codeAt(T);
		for (const proof of [
			Number(code),
			undefined,
			null,
			{ code },
			[code],
			code.slice(1),
			`${code}0`,
			`${code.slice(1)}a`,
			` ${code}`,
			`${code}\n`,
			`${code.slice(0, 3)}-${code.slice(3)}`,
			"１２３４５６",
		]) {
			expect(await factor.verify(verifyContext(proof)), JSON.stringify(proof)).toEqual({
				ok: false,
				reason: "malformed",
			});
		}
		// The length is the factor's: a 6-digit code is not an 8-digit factor's.
		const eight = enrolled(dataOf({ digits: 8 }));
		expect(await factor.verify(verifyContext(code, eight))).toEqual({
			ok: false,
			reason: "malformed",
		});
	});

	it("throws on data that is not a TOTP record, never quoting the secret — an unreadable factor is not a wrong code", async () => {
		const secret = encodeBase32(SECRET);
		for (const data of [
			{},
			dataOf({ secret: undefined }),
			dataOf({ secret: "not base32!" }),
			dataOf({ secret: secret.toLowerCase() }),
			dataOf({ secret: encodeBase32(Buffer.alloc(15, 1)) }),
			dataOf({ algorithm: "MD5" }),
			dataOf({ digits: 9 }),
			dataOf({ digits: "6" }),
			dataOf({ period: 0 }),
			dataOf({ period: 1.5 }),
			dataOf({ lastUsedStep: undefined }),
			dataOf({ lastUsedStep: -1 }),
			dataOf({ lastUsedStep: 1.5 }),
		]) {
			const attempt = factor.verify(verifyContext(codeAt(T), enrolled(data)));
			await expect(attempt, JSON.stringify(data)).rejects.toThrow(/TOTP/);
			await attempt.catch((error: unknown) => {
				expect(String((error as Error).message)).not.toContain(secret);
			});
		}
	});
});

describe("enrolling a TOTP factor", () => {
	const factor = createTotpFactor(SETTINGS);

	it("hands out a secret of the algorithm's output length, in base32, and its otpauth URI", async () => {
		for (const [algorithm, bytes] of [
			["SHA1", 20],
			["SHA256", 32],
			["SHA512", 64],
		] as const) {
			const begun = await createTotpFactor({ ...SETTINGS, algorithm }).beginEnrollment(
				enrollmentContext(),
			);
			const secret = begun.state.secret as string;
			expect(decodeBase32(secret)?.length, algorithm).toBe(bytes);
			expect(begun.state).toEqual({ secret, algorithm, digits: 6, period: 30 });
			expect(begun.response).toEqual({
				secret,
				otpauth_uri: `otpauth://totp/auth.example:alice?secret=${secret}&issuer=auth.example&algorithm=${algorithm}&digits=6&period=30`,
				algorithm,
				digits: 6,
				period: 30,
			});
		}
	});

	it("labels the factor issuer:account, the account its username, each encoded — never its address", async () => {
		const spaced = createTotpFactor({ ...SETTINGS, issuer: "Example Co" });
		const withEmail = await spaced.beginEnrollment(enrollmentContext());
		const uri = (withEmail.response as { otpauth_uri: string }).otpauth_uri;
		expect(uri).toMatch(/^otpauth:\/\/totp\/Example%20Co:alice\?secret=[A-Z2-7]+&issuer=Example%20Co&/);
		expect(decodeURIComponent(uri)).not.toContain(USER.email);
		const spacedName = await spaced.beginEnrollment(
			enrollmentContext({ id: "u-bob", username: "bob smith", email: "bob@example.com" }),
		);
		expect((spacedName.response as { otpauth_uri: string }).otpauth_uri).toMatch(
			/^otpauth:\/\/totp\/Example%20Co:bob%20smith\?/,
		);
	});

	it("refuses, with a RangeError quoting nothing, an account without a username — whatever its address — a User core's type forbids, so a broken Store answer the coordinator reads as an outage", async () => {
		for (const user of [
			{ id: "u-x" },
			{ id: "u-x", email: "x@example.com" },
			{ id: "u-x", username: "", email: "x@example.com" },
			{ id: "u-x", username: 7, email: "x@example.com" },
		]) {
			const thrown = await factor
				.beginEnrollment(enrollmentContext(user))
				.catch((err: unknown) => err);
			expect(thrown, JSON.stringify(user)).toBeInstanceOf(RangeError);
			expect((thrown as Error).message, JSON.stringify(user)).not.toContain("x@example.com");
		}
	});

	it("refuses, with a RangeError quoting nothing, a username that is not well-formed text, rather than let the URI's encoding throw; an address that is not reads nothing", async () => {
		const thrown = await factor
			.beginEnrollment(enrollmentContext({ id: "u-bob", username: "bob\uDC00" }))
			.catch((err: unknown) => err);
		expect(thrown).toBeInstanceOf(RangeError);
		expect((thrown as Error).message).not.toContain("bob");
		const begun = await factor.beginEnrollment(
			enrollmentContext({ id: "u-alice", username: "alice", email: "alice\uD800@example.com" }),
		);
		expect((begun.response as { otpauth_uri: string }).otpauth_uri).toMatch(
			/^otpauth:\/\/totp\/auth\.example:alice\?/,
		);
	});

	it("hands each enrollment a secret of its own", async () => {
		const a = await factor.beginEnrollment(enrollmentContext());
		const b = await factor.beginEnrollment(enrollmentContext());
		expect(a.state.secret).not.toBe(b.state.secret);
	});

	it("binds the factor at the step its proof matched, with the parameters it was begun under", async () => {
		const begun = await createTotpFactor({
			...SETTINGS,
			algorithm: "SHA256",
			digits: 8,
		}).beginEnrollment(enrollmentContext());
		const secret = decodeBase32(begun.state.secret as string) as Buffer;
		// Completed under a factor configured otherwise since: the state's
		// parameters are the enrollment's.
		const completed = await factor.completeEnrollment(
			completionContext(begun.state, codeAt(T + 1, secret, "SHA256", 8)),
		);
		expect(completed).toEqual({
			ok: true,
			data: {
				secret: begun.state.secret,
				algorithm: "SHA256",
				digits: 8,
				period: 30,
				lastUsedStep: T + 1,
			},
		});
		// The proof's code is spent: the first verification cannot reuse it.
		if (completed.ok) {
			expect(
				await factor.verify(
					verifyContext(codeAt(T + 1, secret, "SHA256", 8), enrolled(completed.data)),
				),
			).toEqual({ ok: false, reason: "replayed" });
		}
	});

	it("refuses a wrong proof as invalid and one it cannot read as malformed", async () => {
		const begun = await factor.beginEnrollment(enrollmentContext());
		const secret = decodeBase32(begun.state.secret as string) as Buffer;
		// The secret is random: a code checked to be none of the window's.
		const window = new Set([T - 1, T, T + 1].map((step) => codeAt(step, secret)));
		const wrong = ["000000", "111111", "222222", "333333"].find((code) => !window.has(code));
		expect(await factor.completeEnrollment(completionContext(begun.state, wrong))).toEqual({
			ok: false,
			reason: "invalid",
		});
		for (const proof of [undefined, 123456, "12345", "abcdef"]) {
			expect(await factor.completeEnrollment(completionContext(begun.state, proof))).toEqual({
				ok: false,
				reason: "malformed",
			});
		}
	});

	it("throws on a pending state that is not a TOTP enrollment's", async () => {
		for (const state of [
			{},
			null as unknown as Record<string, unknown>,
			{ secret: "AAAA", algorithm: "SHA1", digits: 6 },
			{ secret: 1 },
		]) {
			await expect(
				factor.completeEnrollment(completionContext(state, codeAt(T))),
				JSON.stringify(state),
			).rejects.toThrow(/TOTP/);
		}
	});
});

describe("the totp factor under the test kit's factor contract", () => {
	/** The code a TOTP app shows for `state` or `data` at `nowMs`. */
	const codeFor = (parameters: Readonly<Record<string, unknown>>, nowMs: number): string =>
		hotp(
			decodeBase32(String(parameters.secret)) as Buffer,
			totpStep(nowMs, Number(parameters.period)),
			{ algorithm: parameters.algorithm as TotpAlgorithm, digits: Number(parameters.digits) },
		);

	for (const { name, run } of mfaFactorContract({
		build: () => createTotpFactor(SETTINGS),
		user: USER,
		enrollmentProof: (start, context) => codeFor(start.state, context.nowMs),
		verificationProof: (enrolled, _challenge, context) => codeFor(enrolled.data, context.nowMs),
	})) {
		it(name, run);
	}
});
