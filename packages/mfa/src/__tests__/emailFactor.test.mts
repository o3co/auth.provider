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
 * The `email` factor (the MFA ADR's F5, D11, D14, D22): a six-digit login
 * code at each challenge and a long code for its enrollment, each mailed by
 * the coordinator and kept as a keyed digest bound to its transaction. It
 * counts, is guessable, keeps its challenge across attempts, adds `email`
 * and `mfa` only when its section says so, and records nothing of an address
 * but the keyed digest it is handed.
 */

import {
	EMAIL_OTP_AMR,
	type MfaDigests,
	type MfaEnrolledFactor,
	type MfaFactorData,
	type MfaKeyedDigest,
} from "@o3co/auth-provider-core";
import { createTestMfaDigests } from "@o3co/auth-provider-core/testing";
import { mfaFactorContract } from "@o3co/auth-provider-test-kit";
import { describe, expect, it } from "vitest";
import { formatLongCode, readLongCode } from "#/codes.mjs";
import { createEmailFactor, EMAIL_FACTOR_KIND, type EmailFactorSettings } from "#/email/factor.mjs";

const SETTINGS: EmailFactorSettings = { addsMfa: false, codeTtlSeconds: 600 };
const NOW_MS = Date.UTC(2026, 9, 1, 12);
const TX = "tx-email-1";
const FACTOR_ID = "factor-email-1";
const USER = { id: "u-alice", username: "alice", email: "alice@example.com" };

const digests = createTestMfaDigests(EMAIL_FACTOR_KIND);
/** A ring whose first key is another, still holding the first. */
const rotated = createTestMfaDigests(EMAIL_FACTOR_KIND, { rotated: true });

/** The digest of `address` as the coordinator hands it, under `under`. */
const addressDigest = (address: string, under: MfaDigests = digests): MfaKeyedDigest =>
	under.digest([address]);

const enrolled = (data: MfaFactorData, id: string = FACTOR_ID): MfaEnrolledFactor => ({
	id,
	label: undefined,
	createdAt: new Date(NOW_MS - 86_400_000),
	lastUsedAt: undefined,
	data,
});

const ceremony = (under: MfaDigests = digests, transactionId: string = TX) =>
	({ subject: USER.id, transactionId, nowMs: NOW_MS, request: {}, digests: under }) as const;

/** A challenge of `factor`'s record holding `data`: what it answered. */
async function challenged(data: MfaFactorData, under: MfaDigests = digests) {
	const factor = createEmailFactor(SETTINGS);
	const named = enrolled(data);
	const issued = await factor.challenge?.({ ...ceremony(under), factor: named, factors: [named] });
	if (issued === undefined) throw new Error("the email factor answered no challenge");
	return issued;
}

describe("createEmailFactor", () => {
	it("is the email kind: counting, guessable, its challenge kept across attempts, adding email", () => {
		const factor = createEmailFactor(SETTINGS);
		expect(factor.kind).toBe("email");
		expect(EMAIL_FACTOR_KIND).toBe("email");
		expect(factor.amrValues).toEqual([EMAIL_OTP_AMR]);
		expect(factor.amrFor({})).toEqual([EMAIL_OTP_AMR]);
		expect(factor.counting).toBe(true);
		expect(factor.guessable).toBe(true);
		expect(factor.reusableChallenge).toBe(true);
	});

	it("adds mfa only when its section says so", () => {
		expect(createEmailFactor({ ...SETTINGS, addsMfa: false }).addsMfa).toBe(false);
		expect(createEmailFactor({ ...SETTINGS, addsMfa: true }).addsMfa).toBe(true);
	});

	it("describes a record with no hint: it holds no address to mask", () => {
		const factor = createEmailFactor(SETTINGS);
		expect(factor.describe({ addressDigest: addressDigest(USER.email) })).toEqual({});
		expect(factor.describe({})).toEqual({});
	});

	it("is enrollable by an account whose address normaliseMailAddress reads, and by no other", () => {
		const factor = createEmailFactor(SETTINGS);
		expect(factor.enrollable?.(USER)).toBe(true);
		expect(factor.enrollable?.({ ...USER, email: "  Alice@Example.COM " })).toBe(true);
		for (const email of [undefined, null, "", "alice", "a@example.com, b@example.com", 42]) {
			expect(factor.enrollable?.({ ...USER, email }), String(email)).toBe(false);
		}
	});
});

describe("the email factor's challenge", () => {
	it("asks for a six-digit login code to be mailed, living codeTtlSeconds, with the digest the record holds", async () => {
		const recorded = addressDigest(USER.email);
		const issued = await challenged({ addressDigest: recorded });
		expect(issued.mail).toEqual({
			purpose: "login_code",
			code: expect.stringMatching(/^[0-9]{6}$/),
			expiresAtMs: NOW_MS + 600_000,
			addressDigest: recorded,
		});
		expect(issued.response).toEqual({});
	});

	it("keeps the code as a keyed digest bound to the transaction and the factor, never the code", async () => {
		const issued = await challenged({ addressDigest: addressDigest(USER.email) });
		const code = issued.mail?.code as string;
		const kept = issued.state?.code as MfaKeyedDigest;
		expect(Object.keys(issued.state ?? {})).toEqual(["code"]);
		expect(JSON.stringify(issued.state)).not.toContain(code);
		expect(digests.matchesDigest([TX, FACTOR_ID, code], kept)).toBe("match");
		expect(digests.matchesDigest(["tx-other", FACTOR_ID, code], kept)).toBe("mismatch");
		expect(digests.matchesDigest([TX, "factor-other", code], kept)).toBe("mismatch");
	});

	it("mails a copy of the recorded digest holding its key id and digest alone", async () => {
		const recorded = { ...addressDigest(USER.email), note: "kept" };
		const issued = await challenged({ addressDigest: recorded });
		expect(issued.mail?.addressDigest).toEqual(addressDigest(USER.email));
	});

	it("mails a null digest when the record holds none it can read, which the coordinator refuses", async () => {
		for (const unreadable of [undefined, null, "digest", {}, { keyId: "test-key" }, []]) {
			const issued = await challenged({ addressDigest: unreadable });
			expect(issued.mail?.addressDigest, JSON.stringify(unreadable)).toBeNull();
		}
	});

	it("draws a code at each challenge: 20 challenges give more than 15 distinct codes", async () => {
		const data = { addressDigest: addressDigest(USER.email) };
		const codes = new Set<string>();
		for (let n = 0; n < 20; n++) codes.add((await challenged(data)).mail?.code as string);
		expect(codes.size).toBeGreaterThan(15);
	});
});

describe("the email factor's verification", () => {
	/** A challenge, then a verification of `proof` (the code mailed unless given), under `under`. */
	async function verified(
		options: {
			readonly proof?: (code: string) => unknown;
			readonly state?: "none" | "kept";
			readonly recorded?: unknown;
			readonly handed?: MfaKeyedDigest | undefined;
			readonly under?: MfaDigests;
			readonly transactionId?: string;
		} = {},
	) {
		const recorded =
			"recorded" in options ? options.recorded : (addressDigest(USER.email) as unknown);
		const data = { addressDigest: recorded };
		const issued = await challenged(data);
		const code = issued.mail?.code as string;
		const named = enrolled(data);
		const factor = createEmailFactor(SETTINGS);
		return factor.verify({
			...ceremony(options.under ?? digests, options.transactionId),
			factor: named,
			factors: [named],
			state: options.state === "none" ? undefined : issued.state,
			proof: options.proof === undefined ? code : options.proof(code),
			...("handed" in options
				? options.handed === undefined
					? {}
					: { addressDigest: options.handed }
				: { addressDigest: addressDigest(USER.email) }),
		});
	}

	it("verifies the code it mailed, with the whitespace around it, and changes nothing while the handed digest is under the recorded key", async () => {
		expect(await verified()).toEqual({ ok: true, factorId: FACTOR_ID });
		expect(await verified({ proof: (code) => ` ${code}\n` })).toEqual({
			ok: true,
			factorId: FACTOR_ID,
		});
	});

	it("keeps the handed digest, under the ring's first key, when the recorded one names another", async () => {
		const handed = addressDigest(USER.email, rotated);
		expect(await verified({ under: rotated, handed })).toEqual({
			ok: true,
			factorId: FACTOR_ID,
			next: { addressDigest: handed },
		});
	});

	it("refuses a proof that is not six digits as malformed", async () => {
		for (const proof of [undefined, null, 123456, {}, "", "12345", "1234567", "12 345"]) {
			expect(await verified({ proof: () => proof }), JSON.stringify(proof)).toEqual({
				ok: false,
				reason: "malformed",
			});
		}
	});

	it("refuses a code with no pending challenge as expired", async () => {
		expect(await verified({ state: "none" })).toEqual({ ok: false, reason: "expired" });
	});

	it("refuses another code, and the code under another transaction, as invalid", async () => {
		const other = (code: string) => String((Number(code) + 1) % 1_000_000).padStart(6, "0");
		expect(await verified({ proof: other })).toEqual({ ok: false, reason: "invalid" });
		expect(await verified({ transactionId: "tx-other" })).toEqual({
			ok: false,
			reason: "invalid",
		});
	});

	it("answers its recorded digest as its identity: one string for one digest under one key, another under another key or for another address, none for data holding no digest", () => {
		const factor = createEmailFactor(SETTINGS);
		const identity = factor.identity?.({ addressDigest: addressDigest(USER.email) });
		expect(identity).toEqual(expect.any(String));
		expect(identity).not.toContain(USER.email);
		expect(factor.identity?.({ addressDigest: addressDigest(USER.email) })).toBe(identity);
		expect(
			createEmailFactor(SETTINGS).identity?.({ addressDigest: addressDigest(USER.email) }),
		).toBe(identity);
		expect(factor.identity?.({ addressDigest: addressDigest(USER.email, rotated) })).not.toBe(
			identity,
		);
		expect(factor.identity?.({ addressDigest: addressDigest("bob@example.com") })).not.toBe(
			identity,
		);
		for (const data of [{}, { addressDigest: null }, { addressDigest: { keyId: "k" } }]) {
			expect(factor.identity?.(data), JSON.stringify(data)).toBeUndefined();
		}
	});

	it("throws, an outage, when the kept code's key has left the ring, or the state is not a kept code", async () => {
		const factor = createEmailFactor(SETTINGS);
		const named = enrolled({ addressDigest: addressDigest(USER.email) });
		const base = { ...ceremony(), factor: named, factors: [named], proof: "123456" };
		await expect(
			factor.verify({ ...base, state: { code: { keyId: "gone", digest: "x" } } }),
		).rejects.toThrow();
		for (const state of [{}, { code: "123456" }, { code: { keyId: "test-key" } }]) {
			await expect(factor.verify({ ...base, state }), JSON.stringify(state)).rejects.toThrow();
		}
	});
});

describe("the email factor's enrollment", () => {
	async function begun(under: MfaDigests = digests) {
		const factor = createEmailFactor(SETTINGS);
		const start = await factor.beginEnrollment({ ...ceremony(under), user: USER, factors: [] });
		return { factor, start };
	}

	/** An enrollment begun and completed with `proof` (the code mailed unless given). */
	async function completed(
		options: {
			readonly proof?: (code: string) => unknown;
			readonly handed?: MfaKeyedDigest | null;
			readonly factors?: readonly MfaEnrolledFactor[];
			readonly under?: MfaDigests;
		} = {},
	) {
		const under = options.under ?? digests;
		const { factor, start } = await begun(under);
		const code = start.mail?.code as string;
		const handed = options.handed === undefined ? addressDigest(USER.email, under) : options.handed;
		return factor.completeEnrollment({
			...ceremony(under),
			user: USER,
			factors: options.factors ?? [],
			state: start.state,
			proof: options.proof === undefined ? code : options.proof(code),
			...(handed === null ? {} : { addressDigest: handed }),
		});
	}

	it("asks for a long code to be mailed, living codeTtlSeconds, and answers the page nothing of it", async () => {
		const { start } = await begun();
		expect(start.mail).toEqual({
			purpose: "email_factor_enrollment",
			code: expect.any(String),
			expiresAtMs: NOW_MS + 600_000,
		});
		expect(readLongCode(start.mail?.code)).toBe(start.mail?.code);
		expect(start.response).toEqual({});
	});

	it("keeps the code as a keyed digest bound to the transaction, never the code or the address", async () => {
		const { start } = await begun();
		const code = start.mail?.code as string;
		expect(Object.keys(start.state)).toEqual(["code"]);
		const text = JSON.stringify(start.state);
		expect(text).not.toContain(code);
		expect(text).not.toContain(USER.email);
		const kept = start.state.code as MfaKeyedDigest;
		expect(digests.matchesDigest([TX, code], kept)).toBe("match");
		expect(digests.matchesDigest(["tx-other", code], kept)).toBe("mismatch");
	});

	it("completes with the code as mailed or as shown, recording only the digest it is handed", async () => {
		const handed = addressDigest("sent-to@example.org");
		expect(await completed({ handed })).toEqual({ ok: true, data: { addressDigest: handed } });
		expect(
			await completed({ handed, proof: (code) => formatLongCode(code).toLowerCase() }),
		).toEqual({ ok: true, data: { addressDigest: handed } });
	});

	it("records a copy of the handed digest holding its key id and digest alone", async () => {
		const handed = { ...addressDigest(USER.email), note: "dropped" } as MfaKeyedDigest;
		expect(await completed({ handed })).toEqual({
			ok: true,
			data: { addressDigest: addressDigest(USER.email) },
		});
	});

	it("refuses a proof that is not a long code as malformed, and another code as invalid", async () => {
		for (const proof of [undefined, null, 1234, {}, "123456"]) {
			expect(await completed({ proof: () => proof }), JSON.stringify(proof)).toEqual({
				ok: false,
				reason: "malformed",
			});
		}
		expect(await completed({ proof: () => "0000-0000-0000-0000" })).toEqual({
			ok: false,
			reason: "invalid",
		});
	});

	it("completes nothing, as expired, when it is handed no address digest", async () => {
		expect(await completed({ handed: null })).toEqual({ ok: false, reason: "expired" });
	});

	it("refuses a duplicate: a record of the subject holding the same digest under the same key", async () => {
		const held = enrolled({ addressDigest: addressDigest(USER.email) }, "held-1");
		expect(await completed({ factors: [held] })).toEqual({ ok: false, reason: "duplicate" });
		const other = enrolled({ addressDigest: addressDigest("bob@example.com") }, "held-2");
		expect((await completed({ factors: [other] })).ok).toBe(true);
	});

	it("does not see the same address under another key as a duplicate", async () => {
		const held = enrolled({ addressDigest: addressDigest(USER.email) }, "held-1");
		expect((await completed({ factors: [held], under: rotated })).ok).toBe(true);
	});

	it("throws, an outage, when the kept code's key has left the ring, or the state is not a kept code", async () => {
		const factor = createEmailFactor(SETTINGS);
		const base = {
			...ceremony(),
			user: USER,
			factors: [],
			proof: "0000-0000-0000-0000",
			addressDigest: addressDigest(USER.email),
		};
		await expect(
			factor.completeEnrollment({ ...base, state: { code: { keyId: "gone", digest: "x" } } }),
		).rejects.toThrow();
		await expect(factor.completeEnrollment({ ...base, state: {} })).rejects.toThrow();
	});
});

describe("the email factor, held to the factor contract", () => {
	for (const { name, run } of mfaFactorContract({
		build: () => createEmailFactor(SETTINGS),
		user: USER,
		enrollmentProof: (start) => start.mail?.code,
		verificationProof: (_enrolled, challenge) => challenge?.mail?.code,
	})) {
		it(name, run);
	}
});
