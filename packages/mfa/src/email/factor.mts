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
 * The `email` factor (the MFA ADR's F5, D11, D14, D22).
 *
 * - It counts, adds `email` — and `mfa` only with `addsMfa` — and is
 *   guessable: its login code is held to the subject lock. Its challenge
 *   stands across attempts until a new one replaces it.
 * - A challenge asks for a six-digit code to be mailed as a login code; an
 *   enrollment, for a long code. Each lives `codeTtlSeconds` and is kept only
 *   as a keyed digest bound to its transaction — a login code to the factor
 *   too — never the code.
 * - Its data is the keyed digest of the address its enrollment code went to,
 *   exactly as the coordinator handed it, and nothing else: it holds no
 *   address, reads none, and shows no hint. A challenge mails that digest, or
 *   `null` when the data holds none it can read, which the coordinator
 *   refuses. A verification handed a digest under another key than the one
 *   recorded keeps the handed one, so the old key can leave the ring.
 * - A completion is refused as a duplicate when one of the records it is
 *   handed holds the same digest under the same key. That is the records as
 *   read before the create: it does not see another completion at once.
 * - A kept code whose key left the ring, or a pending state that is not a
 *   kept code, throws: an outage, never a code refused.
 */

import {
	EMAIL_OTP_AMR,
	type MfaDigests,
	type MfaEnrollmentCompletion,
	type MfaFactor,
	type MfaFactorState,
	type MfaKeyedDigest,
	type MfaVerification,
	normaliseMailAddress,
} from "@o3co/auth-provider-core";
import {
	generateLongCode,
	generateSixDigitCode,
	readLongCode,
	readSixDigitCode,
} from "../codes.mjs";

/** The kind an email factor's records carry, and the key it is contributed under. */
export const EMAIL_FACTOR_KIND = "email";

/** What the factor is built with, from its section. */
export interface EmailFactorSettings {
	/** Whether a verification adds `mfa` beside `email`. */
	readonly addsMfa: boolean;
	/** How long a mailed code is accepted; the coordinator caps it at the transaction's expiry. */
	readonly codeTtlSeconds: number;
}

const AMR: readonly string[] = Object.freeze([EMAIL_OTP_AMR]);

/** `value` as a keyed digest holding its two fields alone; `undefined` when it is not one. */
function keyedDigest(value: unknown): MfaKeyedDigest | undefined {
	if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
	const { keyId, digest } = value as { readonly keyId?: unknown; readonly digest?: unknown };
	return typeof keyId === "string" && keyId !== "" && typeof digest === "string" && digest !== ""
		? { keyId, digest }
		: undefined;
}

/** The kept code a pending state holds; a throw, quoting nothing, when it holds none. */
function keptCode(state: MfaFactorState): MfaKeyedDigest {
	const kept = keyedDigest(state.code);
	if (kept === undefined) throw new TypeError("the pending state is not an email factor's code");
	return kept;
}

/** Whether `parts` digest to `kept`; a throw when its key has left the ring. */
function matches(digests: MfaDigests, parts: readonly string[], kept: MfaKeyedDigest): boolean {
	const found = digests.matchesDigest(parts, kept);
	if (found === "key_unavailable") {
		throw new RangeError("an email factor's code digest names a key the ring no longer holds");
	}
	return found === "match";
}

/** The `email` factor, its codes living `settings.codeTtlSeconds`. */
export function createEmailFactor(settings: EmailFactorSettings): MfaFactor {
	const ttlMs = settings.codeTtlSeconds * 1000;
	const factor: MfaFactor = {
		kind: EMAIL_FACTOR_KIND,
		amrValues: AMR,
		amrFor: () => AMR,
		addsMfa: settings.addsMfa,
		counting: true,
		guessable: true,
		reusableChallenge: true,
		describe: () => ({}),
		enrollable: (user) => normaliseMailAddress(user.email) !== undefined,

		async challenge(ctx) {
			const code = generateSixDigitCode();
			return {
				state: { code: ctx.digests.digest([ctx.transactionId, ctx.factor.id, code]) },
				response: {},
				mail: {
					purpose: "login_code",
					code,
					expiresAtMs: ctx.nowMs + ttlMs,
					addressDigest: keyedDigest(ctx.factor.data.addressDigest) ?? null,
				},
			};
		},

		async verify(ctx): Promise<MfaVerification> {
			const code = readSixDigitCode(ctx.proof);
			if (code === undefined) return { ok: false, reason: "malformed" };
			if (ctx.state === undefined) return { ok: false, reason: "expired" };
			const kept = keptCode(ctx.state);
			if (!matches(ctx.digests, [ctx.transactionId, ctx.factor.id, code], kept)) {
				return { ok: false, reason: "invalid" };
			}
			const handed = keyedDigest(ctx.addressDigest);
			const recorded = keyedDigest(ctx.factor.data.addressDigest);
			return handed !== undefined && handed.keyId !== recorded?.keyId
				? { ok: true, factorId: ctx.factor.id, next: { addressDigest: handed } }
				: { ok: true, factorId: ctx.factor.id };
		},

		async beginEnrollment(ctx) {
			const code = generateLongCode();
			return {
				state: { code: ctx.digests.digest([ctx.transactionId, code]) },
				response: {},
				mail: { purpose: "email_factor_enrollment", code, expiresAtMs: ctx.nowMs + ttlMs },
			};
		},

		async completeEnrollment(ctx): Promise<MfaEnrollmentCompletion> {
			const code = readLongCode(ctx.proof);
			if (code === undefined) return { ok: false, reason: "malformed" };
			const kept = keptCode(ctx.state);
			if (!matches(ctx.digests, [ctx.transactionId, code], kept)) {
				return { ok: false, reason: "invalid" };
			}
			// The address the code went to, as the coordinator kept it at the send.
			const handed = keyedDigest(ctx.addressDigest);
			if (handed === undefined) return { ok: false, reason: "expired" };
			// Among the records handed, read before the create: not another completion at once.
			const held = ctx.factors.some((enrolled) => {
				const recorded = keyedDigest(enrolled.data.addressDigest);
				return recorded?.keyId === handed.keyId && recorded.digest === handed.digest;
			});
			if (held) return { ok: false, reason: "duplicate" };
			return { ok: true, data: { addressDigest: handed } };
		},
	};
	return Object.freeze(factor);
}
