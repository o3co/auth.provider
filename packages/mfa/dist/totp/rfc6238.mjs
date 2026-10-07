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
 * HOTP (RFC 4226) and TOTP (RFC 6238) on `node:crypto`, and a verification's
 * step matching. See README, "The TOTP factor".
 *
 * Every step from `T - window` to `T + window` is computed and compared in
 * constant time, so how far into the window a code matched takes no longer to
 * learn than whether it did. A code counts only when its step is after the
 * factor's `lastUsedStep` (RFC 6238 §5.2). No drift resynchronisation
 * (RFC 6238 §6).
 */
import { createHmac } from "node:crypto";
import { constantTimeStringEqual } from "@o3co/auth-provider-core";
/** The HMACs a factor's codes may be computed with, in the order the ADR names them. */
export const TOTP_ALGORITHMS = Object.freeze(["SHA1", "SHA256", "SHA512"]);
/**
 * A secret of the algorithm's output length, as RFC 6238's reference seeds
 * are: a shorter one wastes the hash, and a longer one is hashed down to
 * this length by HMAC anyway.
 */
export const TOTP_SECRET_BYTES = Object.freeze({
    SHA1: 20,
    SHA256: 32,
    SHA512: 64,
});
/** How long a code may be: RFC 4226 asks for at least 6; 8 is what Appendix B's vectors use. */
export const TOTP_DIGITS = Object.freeze({ min: 6, max: 8 });
const HASH = {
    SHA1: "sha1",
    SHA256: "sha256",
    SHA512: "sha512",
};
/**
 * The RFC 4226 value of `secret` at `counter`, `digits` long with leading
 * zeros. A `RangeError` for an input it cannot compute over — an algorithm it
 * does not know, a length outside {@link TOTP_DIGITS}, a counter that is not a
 * safe non-negative integer, an empty secret: each a caller's fault, and none
 * quoted, since the secret is one of them.
 */
export function hotp(secret, counter, { algorithm, digits }) {
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
    const offset = mac[mac.length - 1] & 0x0f;
    const binary = ((mac[offset] & 0x7f) << 24) |
        (mac[offset + 1] << 16) |
        (mac[offset + 2] << 8) |
        mac[offset + 3];
    return String(binary % 10 ** digits).padStart(digits, "0");
}
/**
 * The RFC 6238 time step `nowMs` falls in: `floor(seconds / period)` from the
 * epoch. A `RangeError` for a time that is not a finite non-negative number,
 * or a period that is not a positive whole number of seconds.
 */
export function totpStep(nowMs, period) {
    if (typeof nowMs !== "number" || !Number.isFinite(nowMs) || nowMs < 0) {
        throw new RangeError("TOTP time must be a finite, non-negative number of milliseconds");
    }
    if (!Number.isSafeInteger(period) || period <= 0) {
        throw new RangeError("TOTP period must be a positive whole number of seconds");
    }
    return Math.floor(nowMs / (period * 1000));
}
/**
 * Looks for `code` at each step from `T - window` to `T + window` (none
 * before the epoch). A `RangeError` for a window that is not a non-negative
 * whole number, or a `lastUsedStep` that is not a safe integer, beside
 * {@link hotp}'s and {@link totpStep}'s.
 */
export function matchTotpCode(code, params) {
    const { secret, algorithm, digits, period, window, nowMs, lastUsedStep } = params;
    if (!Number.isSafeInteger(window) || window < 0) {
        throw new RangeError("TOTP window must be a non-negative whole number of steps");
    }
    if (lastUsedStep !== undefined && !Number.isSafeInteger(lastUsedStep)) {
        throw new RangeError("TOTP lastUsedStep must be a safe integer");
    }
    const now = totpStep(nowMs, period);
    const matched = [];
    for (let step = Math.max(0, now - window); step <= now + window; step++) {
        // Every step is computed and compared: none is skipped once one matched.
        if (constantTimeStringEqual(hotp(secret, step, { algorithm, digits }), code)) {
            matched.push(step);
        }
    }
    const fresh = matched.filter((step) => lastUsedStep === undefined || step > lastUsedStep);
    if (fresh.length > 0)
        return { outcome: "matched", step: Math.max(...fresh) };
    return matched.length > 0 ? { outcome: "replayed" } : { outcome: "invalid" };
}
