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
 * store or a transaction (the MFA ADR's D7, D11, D14, F3, F5, F7). These are
 * type assertions: the file is in core's typecheck list.
 *
 * - D11 digests an email code over (transaction id, factor id, code) and a
 *   recovery code over the normalised code, under the key ring, each digest
 *   kept with its key id. The coordinator does it for the factor: the
 *   ceremony context carries the transaction id and a digest capability, and
 *   the ring never reaches the factor.
 * - A WebAuthn verification refuses a sign count that did not increase (F7),
 *   which D28 audits as `sign_count_regression`.
 * - Only a WebAuthn challenge is taken by the verification that answers it;
 *   an email code stays on the transaction across attempts until a re-send
 *   replaces it (F5, F7). The factor says which.
 * - A factor may say a user cannot enroll one — the email factor needs an
 *   address on the account (F3, F5) — without throwing, which the coordinator
 *   would read as an outage.
 */

import { describe, expect, expectTypeOf, it } from "vitest";
import type {
	MfaCeremonyContext,
	MfaDigests,
	MfaFactor,
	MfaKeyedDigest,
	MfaVerification,
} from "#/mfa/factor.mjs";

describe("the MfaFactor contract", () => {
	it("hands every call the transaction id and keyed digests under the ring, never a key (D11)", () => {
		expectTypeOf<MfaCeremonyContext["transactionId"]>().toEqualTypeOf<string>();
		expectTypeOf<MfaCeremonyContext["digests"]>().toEqualTypeOf<MfaDigests>();
		expectTypeOf<MfaKeyedDigest>().toEqualTypeOf<{
			readonly keyId: string;
			readonly digest: string;
		}>();
		expectTypeOf<MfaDigests["digest"]>().toEqualTypeOf<
			(parts: readonly string[]) => MfaKeyedDigest
		>();
		expectTypeOf<MfaDigests["matchesDigest"]>().toEqualTypeOf<
			(parts: readonly string[], stored: MfaKeyedDigest) => boolean
		>();
		expect(true).toBe(true);
	});

	it("lets a verification refuse a sign count that did not increase (F7, D28)", () => {
		expectTypeOf<Extract<MfaVerification, { ok: false }>["reason"]>().toEqualTypeOf<
			"invalid" | "expired" | "replayed" | "malformed" | "sign_count_regression"
		>();
		expect(true).toBe(true);
	});

	it("says whether a verification takes the pending challenge (F5, F7)", () => {
		expectTypeOf<MfaFactor["singleUseChallenge"]>().toEqualTypeOf<boolean | undefined>();
		expect(true).toBe(true);
	});

	it("may say a user cannot enroll one, without throwing (F3, F5)", () => {
		expectTypeOf<MfaFactor["enrollable"]>().toEqualTypeOf<
			((user: Readonly<Record<string, unknown>>) => boolean) | undefined
		>();
		expect(true).toBe(true);
	});
});
