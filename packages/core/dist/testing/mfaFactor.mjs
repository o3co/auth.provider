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
 * The doubles a second factor's tests use: `createTestMfaFactor`, a factor
 * with a trivial protocol, with or without a challenge, or mailing its codes; `testMfaFactorProofs`,
 * the proofs it takes; and `createTestMfaDigests`, keyed digests under a fixed
 * test key, as the coordinator hands a factor under the key ring. The
 * conformance suite a factor runs, `mfaFactorContract`, is
 * `@o3co/auth-provider-test-kit`'s. Published on
 * `@o3co/auth-provider-core/testing`.
 */
import { createHmac, randomBytes } from "node:crypto";
import { OTP_AMR } from "../grants/authenticationClaims.mjs";
import { normaliseMailAddress } from "../mail/address.mjs";
import { constantTimeStringEqual } from "../security/timingSafe.mjs";
// ---------------------------------------------------------------------------
// The digests a factor's tests hand it
// ---------------------------------------------------------------------------
/** The test keys, by id: the first, and the one a rotated ring puts before it. */
const TEST_DIGEST_KEYS = new Map([
    ["test-key", Buffer.from("o3co:mfa:test-digests-key:000000", "utf8")],
    ["test-key-2", Buffer.from("o3co:mfa:test-digests-key:000002", "utf8")],
]);
/** `parts` bound to `kind`, each length-prefixed, so no part can move into its neighbour. */
function framed(kind, parts) {
    return Buffer.concat([kind, ...parts].flatMap((part) => {
        const bytes = Buffer.from(part, "utf8");
        const length = Buffer.alloc(4);
        length.writeUInt32BE(bytes.length);
        return [length, bytes];
    }));
}
/**
 * Keyed digests for a factor of `kind` under a fixed test key, as the
 * coordinator makes them under the ring: HMAC-SHA-256 over the kind and the
 * parts, each length-prefixed, compared in constant time; a digest naming a
 * key the ring does not hold is `key_unavailable`. For tests only: the keys
 * are public.
 */
export function createTestMfaDigests(kind, options = {}) {
    const ring = options.rotated === true ? ["test-key-2", "test-key"] : ["test-key"];
    const first = ring[0];
    const digestOf = (keyId, parts) => createHmac("sha256", TEST_DIGEST_KEYS.get(keyId))
        .update(framed(kind, parts))
        .digest("base64url");
    return {
        digest: (parts) => ({ keyId: first, digest: digestOf(first, parts) }),
        matchesDigest: (parts, stored) => {
            if (!ring.includes(stored.keyId))
                return "key_unavailable";
            return constantTimeStringEqual(digestOf(stored.keyId, parts), stored.digest)
                ? "match"
                : "mismatch";
        },
    };
}
/** Whether `value` is a keyed digest: a key id and a digest, each a non-empty string. */
function isKeyedDigest(value) {
    if (typeof value !== "object" || value === null)
        return false;
    const { keyId, digest } = value;
    return typeof keyId === "string" && keyId !== "" && typeof digest === "string" && digest !== "";
}
/** A copy of `digest` holding its two fields alone. */
const copyOf = (digest) => ({
    keyId: digest.keyId,
    digest: digest.digest,
});
/** How long a code the double mails is accepted. */
const MAILED_CODE_TTL_MS = 600_000;
/**
 * A second factor with a trivial protocol, for tests: the enrollment answers
 * a random secret, and a verification is that secret — with `challenge`, the
 * secret and the nonce the latest challenge answered, as `secret:nonce`;
 * with `mail`, the code the latest challenge asked to be mailed.
 * {@link testMfaFactorProofs} makes the proofs. A proof that is not a string
 * is `malformed`.
 */
export function createTestMfaFactor(options = {}) {
    const amrValues = Object.freeze([...(options.amrValues ?? [OTP_AMR])]);
    const newSecret = () => randomBytes(8).toString("hex");
    const mails = options.mail === true;
    const factor = {
        kind: options.kind ?? "test",
        amrValues,
        amrFor: () => amrValues,
        addsMfa: options.addsMfa ?? true,
        counting: options.counting ?? true,
        guessable: options.guessable ?? false,
        describe: () => ({}),
        beginEnrollment: async (ctx) => {
            const secret = newSecret();
            return mails
                ? {
                    state: { secret },
                    response: { sent: true },
                    mail: {
                        purpose: "email_factor_enrollment",
                        code: secret,
                        expiresAtMs: ctx.nowMs + MAILED_CODE_TTL_MS,
                    },
                }
                : { state: { secret }, response: { secret } };
        },
        completeEnrollment: async (ctx) => {
            if (typeof ctx.proof !== "string")
                return { ok: false, reason: "malformed" };
            if (ctx.proof !== ctx.state.secret)
                return { ok: false, reason: "invalid" };
            if (!mails)
                return { ok: true, data: { secret: ctx.state.secret } };
            // The digest of the address the code went to, as handed: no code went out without one.
            const handed = ctx.addressDigest;
            if (!isKeyedDigest(handed))
                return { ok: false, reason: "expired" };
            return { ok: true, data: { addressDigest: copyOf(handed) } };
        },
        verify: async (ctx) => {
            if (typeof ctx.proof !== "string")
                return { ok: false, reason: "malformed" };
            if (mails) {
                const code = ctx.state?.code;
                if (typeof code !== "string")
                    return { ok: false, reason: "expired" };
                if (ctx.proof !== code)
                    return { ok: false, reason: "invalid" };
                const recorded = ctx.factor.data.addressDigest;
                const handed = ctx.addressDigest;
                // The handed digest, under the ring's first key, replaces one under another.
                return isKeyedDigest(handed) &&
                    (!isKeyedDigest(recorded) || handed.keyId !== recorded.keyId)
                    ? { ok: true, factorId: ctx.factor.id, next: { addressDigest: copyOf(handed) } }
                    : { ok: true, factorId: ctx.factor.id };
            }
            const { secret } = ctx.factor.data;
            if (options.challenge !== true) {
                return ctx.proof === secret
                    ? { ok: true, factorId: ctx.factor.id }
                    : { ok: false, reason: "invalid" };
            }
            const nonce = ctx.state?.nonce;
            if (typeof nonce !== "string")
                return { ok: false, reason: "expired" };
            return ctx.proof === `${String(secret)}:${nonce}`
                ? { ok: true, factorId: ctx.factor.id }
                : { ok: false, reason: "invalid" };
        },
        ...(mails
            ? {
                reusableChallenge: true,
                enrollable: (user) => normaliseMailAddress(user.email) !== undefined,
                challenge: async (ctx) => {
                    const code = newSecret();
                    return {
                        state: { code },
                        response: { sent: true },
                        mail: {
                            purpose: "login_code",
                            code,
                            expiresAtMs: ctx.nowMs + MAILED_CODE_TTL_MS,
                            // None it can read is a mismatch, which the coordinator refuses.
                            addressDigest: isKeyedDigest(ctx.factor.data.addressDigest)
                                ? copyOf(ctx.factor.data.addressDigest)
                                : null,
                        },
                    };
                },
            }
            : options.challenge === true
                ? {
                    challenge: async () => {
                        const nonce = newSecret();
                        return { state: { nonce }, response: { nonce } };
                    },
                }
                : {}),
    };
    return factor;
}
/**
 * The proofs of {@link createTestMfaFactor}: the secret its enrollment
 * answered, or the code it asked to be mailed; for a verification, that
 * secret — and, after a challenge, the nonce it answered, as `secret:nonce`
 * — or the code the challenge asked to be mailed. An input to the test
 * kit's `mfaFactorContract` beside the double.
 */
export const testMfaFactorProofs = Object.freeze({
    enrollmentProof: (start) => start.mail?.code ?? start.response.secret,
    verificationProof: (enrolled, challenge) => {
        if (challenge === undefined)
            return enrolled.data.secret;
        if (challenge.mail !== undefined)
            return challenge.mail.code;
        return `${String(enrolled.data.secret)}:${String(challenge.response.nonce)}`;
    },
});
