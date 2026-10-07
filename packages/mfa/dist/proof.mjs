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
import { UNKNOWN_FACTOR, } from "./ceremony.mjs";
import { generateLongCode, readLongCode } from "./codes.mjs";
import { keptState, mailedAnswer, mailRefusalOf, readKeptState, sendMfaMail } from "./mail.mjs";
/** The `factor_id` that names the proof, and the kind its code is digested and sealed under. */
export const ACCOUNT_EMAIL_FACTOR_ID = "account-email";
/** How long a proof's code is accepted: ten minutes (D22), capped at the transaction's expiry. */
const PROOF_CODE_TTL_MS = 600_000;
/** A keyed digest as the proof's kept state holds it, read once. */
const digestIn = (state) => {
    const code = state?.code;
    if (typeof code !== "object" || code === null)
        return undefined;
    const { keyId, digest } = code;
    return typeof keyId === "string" && typeof digest === "string" ? { keyId, digest } : undefined;
};
/** The account-email proof over the coordinator's `kit` (see this file's header). */
export function createAccountEmailProof(kit) {
    const { sealing } = kit;
    const digests = sealing.digestsFor(ACCOUNT_EMAIL_FACTOR_ID);
    const binding = (tx) => ({
        transactionId: tx.id,
        kind: ACCOUNT_EMAIL_FACTOR_ID,
        use: "challenge",
    });
    const about = (tx) => ({
        subject: tx.subject,
        kind: ACCOUNT_EMAIL_FACTOR_ID,
        purpose: tx.purpose,
    });
    return {
        async challenge(tx, user) {
            if (tx.emailProof !== "required")
                return UNKNOWN_FACTOR;
            const nowMs = kit.now();
            const failed = (cause) => ({
                outcome: "challenge_failed",
                kind: ACCOUNT_EMAIL_FACTOR_ID,
                factorId: ACCOUNT_EMAIL_FACTOR_ID,
                cause,
            });
            const code = generateLongCode();
            const mailed = await sendMfaMail({
                sender: kit.mailSender,
                mail: { purpose: "account_email_proof", code, expiresAtMs: nowMs + PROOF_CODE_TTL_MS },
                purpose: "account_email_proof",
                subject: tx.subject,
                address: user?.email,
                nowMs,
                notAfterMs: tx.expiresAtMs,
                digests,
                keep: async (addressDigest, expiresAtMs) => {
                    let state;
                    try {
                        state = sealing.sealState(binding(tx), keptState({ state: { code: digests.digest([tx.id, code]) }, addressDigest }));
                    }
                    catch (cause) {
                        return { kept: false, refusal: failed(cause) };
                    }
                    const kept = await kit.write(tx, {
                        challenge: {
                            factorId: ACCOUNT_EMAIL_FACTOR_ID,
                            kind: ACCOUNT_EMAIL_FACTOR_ID,
                            state,
                            expiresAtMs,
                        },
                    });
                    if ("outcome" in kept)
                        return { kept: false, refusal: kept };
                    return { kept: true, clear: () => kit.clear(kept.written, "challenge") };
                },
            });
            switch (mailed.outcome) {
                case "sent":
                    return {
                        outcome: "sent",
                        response: mailedAnswer(mailed, nowMs),
                        ...about(tx),
                    };
                case "not_kept":
                    return mailed.refusal;
                case "no_sender":
                case "no_address":
                    return { outcome: "proof_unavailable" };
                case "refused_at_limit":
                case "unavailable":
                    return mailRefusalOf(mailed, "account_email_proof", ACCOUNT_EMAIL_FACTOR_ID);
                case "malformed":
                case "address_mismatch":
                case "key_unavailable":
                    return failed(new TypeError(`the proof's mail answered ${mailed.outcome}`));
                default:
                    return mailed;
            }
        },
        async verify(call, tx) {
            if (tx.emailProof !== "required")
                return UNKNOWN_FACTOR;
            const nowMs = kit.now();
            const refused = (reason, attemptsRemaining) => ({
                outcome: "refused",
                reason,
                attemptsRemaining,
                ...about(tx),
            });
            const unreadable = (extra = {}) => ({
                outcome: "unreadable",
                kind: ACCOUNT_EMAIL_FACTOR_ID,
                factorId: ACCOUNT_EMAIL_FACTOR_ID,
                state: "challenge",
                ...extra,
            });
            const reserved = await kit.reserve(tx);
            if ("outcome" in reserved) {
                return reserved.outcome === "exhausted" ? refused("exhausted", 0) : reserved;
            }
            const { attemptsRemaining } = reserved;
            // Read, not taken: the code stands across attempts until it is replaced.
            const pending = tx.challenge;
            if (pending === undefined ||
                pending.factorId !== ACCOUNT_EMAIL_FACTOR_ID ||
                pending.kind !== ACCOUNT_EMAIL_FACTOR_ID ||
                pending.expiresAtMs <= nowMs) {
                return refused("expired", attemptsRemaining);
            }
            const opened = sealing.openState(binding(tx), pending.state);
            if (opened.state === "key_unavailable")
                return unreadable({ keyId: opened.keyId });
            const stored = opened.state === "ok" ? digestIn(readKeptState(opened.value)?.state) : undefined;
            if (stored === undefined)
                return unreadable();
            const code = readLongCode(call.proof);
            if (code === undefined)
                return refused("malformed", attemptsRemaining);
            let found;
            try {
                found = digests.matchesDigest([tx.id, code], stored);
            }
            catch (cause) {
                return unreadable({ cause });
            }
            if (found === "key_unavailable")
                return unreadable({ keyId: stored.keyId });
            if (found === "mismatch")
                return refused("invalid", attemptsRemaining);
            const written = await kit.write(tx, {
                emailProof: { provedAtMs: nowMs },
                challenge: null,
            });
            if ("outcome" in written) {
                // A resend moved the transaction on: the code this proves was replaced.
                return written.outcome === "unknown_transaction"
                    ? refused("expired", attemptsRemaining)
                    : written;
            }
            if (tx.purpose === "enroll") {
                // The bound read held its sid to the session's; none is refused by the store, an outage.
                const failed = await kit.recordSessionProof(tx.subject, tx.sid ?? "", nowMs);
                if (failed !== undefined)
                    return failed;
            }
            return { outcome: "proved", ...about(tx) };
        },
    };
}
