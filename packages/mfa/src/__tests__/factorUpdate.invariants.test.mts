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
 * What a bundled factor's own update keeps (`MfaVerification.next`). A
 * record's update keeps the factor set's store generation, so a membership
 * decision made on the set is not fenced against it; it is safe only while
 * the next data keeps what that decision read. Each bundled factor that
 * answers next data keeps it: a usable factor that counts stays usable and
 * is verified again, and a recovery-code set keeps its generation however
 * many codes it spends (it does not count, and may run out). No bundled
 * factor answers an identity; the factor contract holds a contributed one's
 * identity to its next data.
 */

import type {
	MfaDigests,
	MfaEnrolledFactor,
	MfaFactor,
	MfaFactorData,
} from "@o3co/auth-provider-core";
import { createTestMfaDigests } from "@o3co/auth-provider-core/testing";
import { describe, expect, it } from "vitest";
import { createEmailFactor, EMAIL_FACTOR_KIND } from "#/email/factor.mjs";
import {
	createRecoveryCodeFactor,
	generateRecoveryCodes,
	isExhaustedRecoverySet,
	RECOVERY_CODE_FACTOR_KIND,
	recoverySetGeneration,
} from "#/recovery/factor.mjs";
import { totpCodeForTests } from "#/testing/index.mjs";
import { encodeBase32 } from "#/totp/base32.mjs";
import { createTotpFactor } from "#/totp/factor.mjs";

const SUBJECT = "u-alice";
const T = 1_800_000_000_000;

const enrolled = (data: MfaFactorData): MfaEnrolledFactor => ({
	id: "factor-1",
	label: undefined,
	createdAt: new Date(T - 86_400_000),
	lastUsedAt: undefined,
	data,
});

/** `factor` verifying `proof` over `data` at `nowMs`, with `digests` and a challenge's `state`. */
const verifying = (
	factor: MfaFactor,
	data: MfaFactorData,
	options: {
		readonly proof: unknown;
		readonly nowMs?: number;
		readonly digests: MfaDigests;
		readonly state?: MfaFactorData;
		readonly addressDigest?: unknown;
	},
) =>
	factor.verify({
		subject: SUBJECT,
		transactionId: "tx-1",
		nowMs: options.nowMs ?? T,
		request: {},
		digests: options.digests,
		factor: enrolled(data),
		factors: [enrolled(data)],
		state: options.state,
		proof: options.proof,
		...(options.addressDigest === undefined ? {} : { addressDigest: options.addressDigest }),
	} as Parameters<MfaFactor["verify"]>[0]);

describe("a counting factor's next data", () => {
	it("TOTP: the factor stays counting and is verified again by a later code over it", async () => {
		const factor = createTotpFactor({
			algorithm: "SHA1",
			digits: 6,
			period: 30,
			window: 1,
			issuer: "auth.example",
		});
		const secret = Buffer.from("12345678901234567890", "ascii");
		const data = {
			secret: encodeBase32(secret),
			algorithm: "SHA1",
			digits: 6,
			period: 30,
			lastUsedStep: 0,
		};
		const digests = createTestMfaDigests("totp");

		const first = await verifying(factor, data, {
			proof: totpCodeForTests(secret, { atMs: T }),
			digests,
		});
		expect(first.ok).toBe(true);
		if (!first.ok || first.next === undefined) throw new Error("no next data");
		const later = T + 60_000;
		const again = await verifying(factor, first.next, {
			proof: totpCodeForTests(secret, { atMs: later }),
			nowMs: later,
			digests,
		});

		expect(factor.counting).toBe(true);
		expect(again).toMatchObject({ ok: true });
	});

	it("email: a digest rewrapped under a newer key still names the account's address, and the factor is verified again over it", async () => {
		const factor = createEmailFactor({ addsMfa: false, codeTtlSeconds: 600 });
		const older = createTestMfaDigests(EMAIL_FACTOR_KIND);
		const rotated = createTestMfaDigests(EMAIL_FACTOR_KIND, { rotated: true });
		const address = "alice@example.com";
		const data = { addressDigest: older.digest([address]) };
		const issued = await factor.challenge?.({
			subject: SUBJECT,
			transactionId: "tx-1",
			nowMs: T,
			request: {},
			digests: rotated,
			factor: enrolled(data),
			factors: [enrolled(data)],
		});
		const handed = rotated.digest([address]);

		const first = await verifying(factor, data, {
			proof: issued?.mail?.code,
			digests: rotated,
			state: issued?.state,
			addressDigest: handed,
		});
		expect(first.ok).toBe(true);
		if (!first.ok || first.next === undefined) throw new Error("no next data");
		expect(rotated.matchesDigest([address], first.next.addressDigest as never)).toBe("match");
		const reissued = await factor.challenge?.({
			subject: SUBJECT,
			transactionId: "tx-2",
			nowMs: T,
			request: {},
			digests: rotated,
			factor: enrolled(first.next),
			factors: [enrolled(first.next)],
		});
		const again = await factor.verify({
			subject: SUBJECT,
			transactionId: "tx-2",
			nowMs: T,
			request: {},
			digests: rotated,
			factor: enrolled(first.next),
			factors: [enrolled(first.next)],
			state: reissued?.state,
			proof: reissued?.mail?.code,
		} as Parameters<MfaFactor["verify"]>[0]);

		expect(factor.counting).toBe(true);
		expect(again).toMatchObject({ ok: true });
	});
});

describe("a recovery-code set's next data", () => {
	it("keeps the set's generation through every code it spends, down to none left — when it is exhausted, which never counted", async () => {
		const factor = createRecoveryCodeFactor({ count: 3 });
		const digests = createTestMfaDigests(RECOVERY_CODE_FACTOR_KIND);
		const set = generateRecoveryCodes(factor, digests, 7);
		if (set === undefined) throw new Error("no set");
		let data: MfaFactorData = { ...set.data, shown: true };

		for (const code of set.codes) {
			const spent = await verifying(factor, data, { proof: code, digests });
			expect(spent.ok, code).toBe(true);
			if (!spent.ok || spent.next === undefined) throw new Error("no next data");
			expect(recoverySetGeneration(factor, spent.next)).toBe(7);
			data = spent.next;
		}

		expect(isExhaustedRecoverySet(factor, data)).toBe(true);
		expect(factor.counting).toBe(false);
	});
});
