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
 *   recorded keeps the handed one, so the old key can leave the ring. The
 *   account page's list reads the recorded digest (`enrolledAddressDigest`)
 *   to tell a record whose address changed.
 * - Its identity is the recorded digest with its key id
 *   (`MfaFactor.identity`): the same address under the same key is one
 *   authenticator, under another key another. A completion is refused as a
 *   duplicate when one of the records it is handed answers the identity its
 *   data would. Those are the records as read before the lease; the
 *   coordinator judges again by identity on the records its lease reads.
 * - A kept code whose key left the ring, or a pending state that is not a
 *   kept code, throws: an outage, never a code refused.
 */
import { EMAIL_OTP_AMR, normaliseMailAddress, } from "@o3co/auth-provider-core";
import { generateLongCode, generateSixDigitCode, readLongCode, readSixDigitCode, } from "../codes.mjs";
import { addressDigestOf } from "../mail.mjs";
/** The kind an email factor's records carry, and the key it is contributed under. */
export const EMAIL_FACTOR_KIND = "email";
const AMR = Object.freeze([EMAIL_OTP_AMR]);
/** `value` as a keyed digest holding its two fields alone; `undefined` when it is not one. */
function keyedDigest(value) {
    if (typeof value !== "object" || value === null || Array.isArray(value))
        return undefined;
    const { keyId, digest } = value;
    return typeof keyId === "string" && keyId !== "" && typeof digest === "string" && digest !== ""
        ? { keyId, digest }
        : undefined;
}
/** The kept code a pending state holds; a throw, quoting nothing, when it holds none. */
function keptCode(state) {
    const kept = keyedDigest(state.code);
    if (kept === undefined)
        throw new TypeError("the pending state is not an email factor's code");
    return kept;
}
/** Whether `parts` digest to `kept`; a throw when its key has left the ring. */
function matches(digests, parts, kept) {
    const found = digests.matchesDigest(parts, kept);
    if (found === "key_unavailable") {
        throw new RangeError("an email factor's code digest names a key the ring no longer holds");
    }
    return found === "match";
}
/** The identity of a record holding `recorded`: its key id and digest, both of which it compares; `undefined` for none. */
const identityOf = (recorded) => recorded === undefined ? undefined : JSON.stringify([recorded.keyId, recorded.digest]);
/** The factors this file made. */
const made = new WeakSet();
/**
 * The digest of the address the record `data` of a factor this file made was
 * enrolled with — `null` when it holds none it can read; `undefined` for any
 * other factor.
 */
export function enrolledAddressDigest(factor, data) {
    return made.has(factor) ? (keyedDigest(data.addressDigest) ?? null) : undefined;
}
/**
 * The identity the record of an enrollment of `factor`, a factor this file
 * made, would answer once its code went to `user`'s address — its digest
 * under `digests` as the coordinator keeps it at the send
 * (`addressDigestOf`); `undefined` for an account with no address, and for
 * any other factor, which is answered before anything is digested.
 */
export function enrollmentIdentity(factor, digests, user) {
    if (!made.has(factor))
        return undefined;
    return identityOf(addressDigestOf(digests, user.email));
}
/** The `email` factor, its codes living `settings.codeTtlSeconds`. */
export function createEmailFactor(settings) {
    const ttlMs = settings.codeTtlSeconds * 1000;
    const factor = {
        kind: EMAIL_FACTOR_KIND,
        amrValues: AMR,
        amrFor: () => AMR,
        addsMfa: settings.addsMfa,
        counting: true,
        guessable: true,
        reusableChallenge: true,
        describe: () => ({}),
        enrollable: (user) => normaliseMailAddress(user.email) !== undefined,
        identity: (data) => identityOf(keyedDigest(data.addressDigest)),
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
        async verify(ctx) {
            const code = readSixDigitCode(ctx.proof);
            if (code === undefined)
                return { ok: false, reason: "malformed" };
            if (ctx.state === undefined)
                return { ok: false, reason: "expired" };
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
        async completeEnrollment(ctx) {
            const code = readLongCode(ctx.proof);
            if (code === undefined)
                return { ok: false, reason: "malformed" };
            const kept = keptCode(ctx.state);
            if (!matches(ctx.digests, [ctx.transactionId, code], kept)) {
                return { ok: false, reason: "invalid" };
            }
            // The address the code went to, as the coordinator kept it at the send.
            const handed = keyedDigest(ctx.addressDigest);
            if (handed === undefined)
                return { ok: false, reason: "expired" };
            const own = identityOf(handed);
            if (ctx.factors.some((enrolled) => identityOf(keyedDigest(enrolled.data.addressDigest)) === own)) {
                return { ok: false, reason: "duplicate" };
            }
            return { ok: true, data: { addressDigest: handed } };
        },
    };
    const frozen = Object.freeze(factor);
    made.add(frozen);
    return frozen;
}
