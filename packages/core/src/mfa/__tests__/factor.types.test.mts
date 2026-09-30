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
 * What the `MfaFactor` contract lets a factor do without holding a key, a
 * store or a transaction. The rules are in the MFA ADR, D7's amendment "what
 * the contract hands a factor". In short: the coordinator digests under the
 * key ring for the factor, which never sees the ring; a factor may refuse a
 * sign count that did not increase, opt in to a challenge that stays across
 * attempts, and say a user cannot enroll it without throwing (a throw reads
 * as an outage). A factor that mails a code answers its purpose and the code,
 * never text or a recipient: the coordinator keeps the state, then sends.
 *
 * These are type assertions: the file is in core's typecheck list.
 */

import { describe, expect, expectTypeOf, it } from "vitest";
import type { MailPurpose } from "#/mail/types.mjs";
import type {
	MfaCeremonyContext,
	MfaChallenge,
	MfaChallengeContext,
	MfaDigestMatch,
	MfaDigests,
	MfaEnrollmentContext,
	MfaEnrollmentStart,
	MfaFactor,
	MfaFactorMail,
	MfaFactorState,
	MfaKeyedDigest,
	MfaVerification,
} from "#/mfa/factor.mjs";

describe("the MfaFactor contract", () => {
	it("hands every call the transaction id and keyed digests that carry a key id, not a key", () => {
		expectTypeOf<MfaCeremonyContext["transactionId"]>().toEqualTypeOf<string>();
		expectTypeOf<MfaCeremonyContext["digests"]>().toEqualTypeOf<MfaDigests>();
		expectTypeOf<MfaKeyedDigest>().toEqualTypeOf<{
			readonly keyId: string;
			readonly digest: string;
		}>();
		expectTypeOf<MfaDigests["digest"]>().toEqualTypeOf<
			(parts: readonly string[]) => MfaKeyedDigest
		>();
		// A digest whose key has left the ring is not a wrong code: the MFA
		// ADR's D11 answers an unreadable factor 503, never "invalid".
		expectTypeOf<MfaDigests["matchesDigest"]>().toEqualTypeOf<
			(parts: readonly string[], stored: MfaKeyedDigest) => MfaDigestMatch
		>();
		expectTypeOf<MfaDigestMatch>().toEqualTypeOf<"match" | "mismatch" | "key_unavailable">();
		expect(true).toBe(true);
	});

	it("lets a verification refuse a sign count that did not increase", () => {
		expectTypeOf<Extract<MfaVerification, { ok: false }>["reason"]>().toEqualTypeOf<
			"invalid" | "expired" | "replayed" | "malformed" | "sign_count_regression"
		>();
		expect(true).toBe(true);
	});

	it("lets a factor opt in to a reusable challenge, and offers no single-use flag", () => {
		// Fail closed: a contributed WebAuthn-like factor that forgets the flag
		// gets a challenge that answers one verification. The email factor opts
		// in to a code that stands across attempts.
		expectTypeOf<MfaFactor["reusableChallenge"]>().toEqualTypeOf<boolean | undefined>();
		expectTypeOf<MfaFactor>().not.toHaveProperty("singleUseChallenge");
		expect(true).toBe(true);
	});

	it("names the amr values a verification may add statically, beside amrFor", () => {
		// `amrFor(data)` depends on a record — a WebAuthn credential is `hwk` or
		// `swk` by its backup flag — so the values a factor can ever add are
		// declared once, for the MFA requirement's reach and for the acr drop
		// at boot; `addsMfa` says the rest.
		expectTypeOf<MfaFactor["amrValues"]>().toEqualTypeOf<readonly string[]>();
		expectTypeOf<MfaFactor["addsMfa"]>().toEqualTypeOf<boolean>();
		expect(true).toBe(true);
	});

	it("may say a user cannot enroll one, without throwing", () => {
		expectTypeOf<MfaFactor["enrollable"]>().toEqualTypeOf<
			((user: Readonly<Record<string, unknown>>) => boolean) | undefined
		>();
		expect(true).toBe(true);
	});

	it("lets a challenge or an enrollment ask for a code to be mailed: its purpose and the code, beside the state and the response", () => {
		expectTypeOf<MfaFactorMail>().toEqualTypeOf<{
			readonly purpose: MailPurpose;
			readonly code: string;
		}>();
		expectTypeOf<MfaChallenge>().toEqualTypeOf<{
			readonly state?: MfaFactorState;
			readonly response: unknown;
			readonly mail?: MfaFactorMail;
		}>();
		expectTypeOf<MfaEnrollmentStart>().toEqualTypeOf<{
			readonly state: MfaFactorState;
			readonly response: unknown;
			readonly mail?: MfaFactorMail;
		}>();
		expectTypeOf<NonNullable<MfaFactor["challenge"]>>().toEqualTypeOf<
			(ctx: MfaChallengeContext) => Promise<MfaChallenge>
		>();
		expectTypeOf<MfaFactor["beginEnrollment"]>().toEqualTypeOf<
			(ctx: MfaEnrollmentContext) => Promise<MfaEnrollmentStart>
		>();
		expect(true).toBe(true);
	});

	it("declares no mail limits: a limit on sending is the sender's", () => {
		expectTypeOf<MfaFactor>().not.toHaveProperty("mailLimits");
		expect(true).toBe(true);
	});
});
