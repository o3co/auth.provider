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
 * HOTP (RFC 4226) and TOTP (RFC 6238) on `node:crypto`, and the step matching
 * a verification makes (the MFA ADR's F6, D22): HMAC-SHA-1, -256 or -512 over
 * the 8-byte big-endian counter, dynamic truncation, the code `digits` long;
 * the time step counted from the epoch (T0 = 0). A code is looked for at every
 * step from `T - window` to `T + window` — each one computed and compared in
 * constant time, so how far into the window a code matched takes no longer to
 * learn than whether it did — and it counts only when its step is after the
 * factor's `lastUsedStep` (RFC 6238 §5.2): the same code again, and an older
 * one never used once a newer one was accepted, are `replayed`. There is no
 * drift resynchronisation (RFC 6238 §6; D22). Pinned by RFC 6238 Appendix B's
 * vectors and RFC 4226 Appendix D's.
 */

import { createHmac } from "node:crypto";
import { constantTimeStringEqual } from "@o3co/auth-provider-core";

/** The HMAC a factor's codes are computed with. */
export type TotpAlgorithm = "SHA1" | "SHA256" | "SHA512";

/** Every {@link TotpAlgorithm}, in the order the ADR names them. */
export const TOTP_ALGORITHMS: readonly TotpAlgorithm[] = Object.freeze([
	"SHA1",
	"SHA256",
	"SHA512",
]);

/**
 * A secret of the algorithm's output length, as RFC 6238's reference seeds
 * are (F6): a shorter one wastes the hash, and a longer one is hashed down to
 * this length by HMAC anyway.
 */
export const TOTP_SECRET_BYTES: Readonly<Record<TotpAlgorithm, number>> = Object.freeze({
	SHA1: 20,
	SHA256: 32,
	SHA512: 64,
});

/** How long a code may be: RFC 4226 asks for at least 6; 8 is what Appendix B's vectors use. */
export const TOTP_DIGITS = Object.freeze({ min: 6, max: 8 });

const HASH: Readonly<Record<TotpAlgorithm, string>> = {
	SHA1: "sha1",
	SHA256: "sha256",
	SHA512: "sha512",
};

/** What a code is computed with, beside the secret and the counter. */
export interface HotpParameters {
	readonly algorithm: TotpAlgorithm;
	readonly digits: number;
}

/**
 * The RFC 4226 value of `secret` at `counter`, `digits` long with leading
 * zeros. A `RangeError` for an input it cannot compute over — an algorithm it
 * does not know, a length outside {@link TOTP_DIGITS}, a counter that is not a
 * safe non-negative integer, an empty secret: each a caller's fault, and none
 * quoted, since the secret is one of them.
 */
export function hotp(
	secret: Buffer,
	counter: number,
	{ algorithm, digits }: HotpParameters,
): string {
	if (typeof algorithm !== "string" || !Object.hasOwn(HASH, algorithm)) {
		throw new RangeError("HOTP algorithm must be SHA1, SHA256 or SHA512");
	}
	if (!Number.isInteger(digits) || digits < TOTP_DIGITS.min || digits > TOTP_DIGITS.max) {
		throw new RangeError(`HOTP digits must be ${TOTP_DIGITS.min} to ${TOTP_DIGITS.max}`);
	}
	if (!Number.isSafeInteger(counter) || counter < 0) {
		throw new RangeError("HOTP counter must be a safe non-negative integer");
	}
	if (!Buffer.isBuffer(secret) || secret.length === 0) {
		throw new RangeError("HOTP secret must be a non-empty Buffer");
	}
	const message = Buffer.alloc(8);
	message.writeBigUInt64BE(BigInt(counter));
	const mac = createHmac(HASH[algorithm], secret).update(message).digest();
	// RFC 4226 §5.3: dynamic truncation — four bytes at the offset the last
	// byte's low nibble names, the top bit masked off.
	const offset = (mac[mac.length - 1] as number) & 0x0f;
	const binary =
		(((mac[offset] as number) & 0x7f) << 24) |
		((mac[offset + 1] as number) << 16) |
		((mac[offset + 2] as number) << 8) |
		(mac[offset + 3] as number);
	return String(binary % 10 ** digits).padStart(digits, "0");
}

/**
 * The RFC 6238 time step `nowMs` falls in: `floor(seconds / period)` from the
 * epoch. A `RangeError` for a time that is not a finite non-negative number,
 * or a period that is not a positive whole number of seconds.
 */
export function totpStep(nowMs: number, period: number): number {
	if (typeof nowMs !== "number" || !Number.isFinite(nowMs) || nowMs < 0) {
		throw new RangeError("TOTP time must be a finite, non-negative number of milliseconds");
	}
	if (!Number.isSafeInteger(period) || period <= 0) {
		throw new RangeError("TOTP period must be a positive whole number of seconds");
	}
	return Math.floor(nowMs / (period * 1000));
}

/** What a code is matched with: the factor's parameters, the window, the time and the step last used. */
export interface TotpMatchParameters extends HotpParameters {
	readonly secret: Buffer;
	/** Seconds per step. */
	readonly period: number;
	/** Steps accepted either side of now. */
	readonly window: number;
	readonly nowMs: number;
	/** The step the factor's last accepted code was at; absent for a factor that has none (an enrollment's proof). */
	readonly lastUsedStep?: number;
}

/**
 * What matching found. `matched`: the code is the one for `step`, the latest
 * such step in the window after `lastUsedStep`. `replayed`: it is a code of
 * the window, but only for a step at or before `lastUsedStep`. `invalid`: no
 * step in the window has it.
 */
export type TotpMatch =
	| { readonly outcome: "matched"; readonly step: number }
	| { readonly outcome: "replayed" }
	| { readonly outcome: "invalid" };

/**
 * Looks for `code` at each step from `T - window` to `T + window` (none
 * before the epoch). A `RangeError` for a window that is not a non-negative
 * whole number, or a `lastUsedStep` that is not a safe integer, beside
 * {@link hotp}'s and {@link totpStep}'s.
 */
export function matchTotpCode(code: string, params: TotpMatchParameters): TotpMatch {
	const { secret, algorithm, digits, period, window, nowMs, lastUsedStep } = params;
	if (!Number.isSafeInteger(window) || window < 0) {
		throw new RangeError("TOTP window must be a non-negative whole number of steps");
	}
	if (lastUsedStep !== undefined && !Number.isSafeInteger(lastUsedStep)) {
		throw new RangeError("TOTP lastUsedStep must be a safe integer");
	}
	const now = totpStep(nowMs, period);
	const matched: number[] = [];
	for (let step = Math.max(0, now - window); step <= now + window; step++) {
		// Every step is computed and compared: none is skipped once one matched.
		if (constantTimeStringEqual(hotp(secret, step, { algorithm, digits }), code)) {
			matched.push(step);
		}
	}
	const fresh = matched.filter((step) => lastUsedStep === undefined || step > lastUsedStep);
	if (fresh.length > 0) return { outcome: "matched", step: Math.max(...fresh) };
	return matched.length > 0 ? { outcome: "replayed" } : { outcome: "invalid" };
}
