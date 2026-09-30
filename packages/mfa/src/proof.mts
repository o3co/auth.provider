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
 * The account-email proof at a login's first binding (the MFA ADR's D24,
 * F3 step 2, D21's 80-bit row), named by `factor_id: "account-email"` on
 * the challenge and verify routes of a transaction whose `emailProof` is
 * `required`, and on no other.
 *
 * - The challenge mails a long code (`codes.mts`) through `sendMfaMail` to
 *   the login's address, the continuation's `User` — never a later read.
 *   The code lives ten minutes, capped at the transaction's expiry, and is
 *   kept only as a keyed digest over the transaction id and the code, sealed
 *   on the transaction; a resend replaces it. A proof nobody can give — no
 *   sender, no address — is refused, never skipped.
 * - A verification reserves one of the transaction's attempts, never a
 *   subject's: an 80-bit code is not guessed, and a lock would let a
 *   password holder lock an unenrolled account out. The code stands across
 *   attempts until it is replaced or proved; past the transaction's attempts
 *   the transaction ends. A right code records `emailProof.provedAtMs`.
 */

import type { MfaKeyedDigest, MfaTransaction } from "@o3co/auth-provider-core";
import { generateLongCode, readLongCode } from "./codes.mjs";
import type {
	MfaCeremonyCall,
	MfaCeremonyKit,
	MfaChallengeOutcome,
	MfaFactorUnreadable,
	MfaRefusalReason,
	MfaVerifyOutcome,
} from "./coordinator.mjs";
import { keptState, maskMailAddress, readKeptState, sendMfaMail } from "./mail.mjs";

/** The `factor_id` that names the proof, and the kind its code is digested and sealed under. */
export const ACCOUNT_EMAIL_FACTOR_ID = "account-email";

/** How long a proof's code is accepted: ten minutes (D22), capped at the transaction's expiry. */
const PROOF_CODE_TTL_MS = 600_000;

const UNKNOWN_FACTOR = Object.freeze({ outcome: "unknown_factor" as const });

/** A keyed digest as the proof's kept state holds it, read once. */
const digestIn = (
	state: Readonly<Record<string, unknown>> | undefined,
): MfaKeyedDigest | undefined => {
	const code = state?.code;
	if (typeof code !== "object" || code === null) return undefined;
	const { keyId, digest } = code as Readonly<Record<string, unknown>>;
	return typeof keyId === "string" && typeof digest === "string" ? { keyId, digest } : undefined;
};

/** The account-email proof over the coordinator's `kit` (see this file's header). */
export function createAccountEmailProof(kit: MfaCeremonyKit): {
	challenge(tx: MfaTransaction): Promise<MfaChallengeOutcome>;
	verify(
		call: MfaCeremonyCall & { readonly proof: unknown },
		tx: MfaTransaction,
	): Promise<MfaVerifyOutcome>;
} {
	const { sealing } = kit;
	const digests = sealing.digestsFor(ACCOUNT_EMAIL_FACTOR_ID);
	const binding = (tx: MfaTransaction) => ({
		transactionId: tx.id,
		kind: ACCOUNT_EMAIL_FACTOR_ID,
		use: "challenge" as const,
	});
	const about = (tx: MfaTransaction) => ({
		subject: tx.subject,
		kind: ACCOUNT_EMAIL_FACTOR_ID,
		purpose: tx.purpose,
	});

	return {
		async challenge(tx) {
			if (tx.emailProof !== "required") return UNKNOWN_FACTOR;
			const nowMs = kit.now();
			const failed = (cause: unknown): MfaChallengeOutcome => ({
				outcome: "challenge_failed",
				kind: ACCOUNT_EMAIL_FACTOR_ID,
				factorId: ACCOUNT_EMAIL_FACTOR_ID,
				cause,
			});
			const code = generateLongCode();
			const mailed = await sendMfaMail<MfaChallengeOutcome>({
				sender: kit.mailSender,
				mail: { purpose: "account_email_proof", code, expiresAtMs: nowMs + PROOF_CODE_TTL_MS },
				purpose: "account_email_proof",
				subject: tx.subject,
				address: tx.continuation?.primary.user.email,
				nowMs,
				notAfterMs: tx.expiresAtMs,
				digests,
				keep: async (addressDigest, expiresAtMs) => {
					let state: string;
					try {
						state = sealing.sealState(
							binding(tx),
							keptState({ state: { code: digests.digest([tx.id, code]) }, addressDigest }),
						);
					} catch (cause) {
						return { kept: false, refusal: failed(cause) };
					}
					const refused = await kit.write(tx, {
						challenge: {
							factorId: ACCOUNT_EMAIL_FACTOR_ID,
							kind: ACCOUNT_EMAIL_FACTOR_ID,
							state,
							expiresAtMs,
						},
					});
					if (refused !== undefined) return { kept: false, refusal: refused };
					return {
						kept: true,
						clear: async () => {
							await kit.transactions.update(tx.id, tx.version + 1, { challenge: null });
						},
					};
				},
			});
			switch (mailed.outcome) {
				case "sent":
					return {
						outcome: "sent",
						response: {
							sent_to: maskMailAddress(mailed.to),
							expires_in: Math.max(1, Math.ceil((mailed.expiresAtMs - nowMs) / 1000)),
						},
						...about(tx),
					};
				case "not_kept":
					return mailed.refusal;
				case "no_sender":
				case "no_address":
					return { outcome: "proof_unavailable" };
				case "refused_at_limit":
					return { outcome: "mail_refused_at_limit" };
				case "unavailable":
					return {
						outcome: "mail_unavailable",
						purpose: "account_email_proof",
						kind: ACCOUNT_EMAIL_FACTOR_ID,
						reason: "outage",
						cleared: mailed.cleared,
						cause: mailed.cause,
					};
				default:
					return failed(new TypeError(`the proof's mail answered ${mailed.outcome}`));
			}
		},

		async verify(call, tx) {
			if (tx.emailProof !== "required") return UNKNOWN_FACTOR;
			const nowMs = kit.now();
			const refused = (reason: MfaRefusalReason, attemptsRemaining: number): MfaVerifyOutcome => ({
				outcome: "refused",
				reason,
				attemptsRemaining,
				...about(tx),
			});
			const unreadable = (
				extra: { readonly keyId?: string; readonly cause?: unknown } = {},
			): MfaFactorUnreadable => ({
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
			if (
				pending === undefined ||
				pending.factorId !== ACCOUNT_EMAIL_FACTOR_ID ||
				pending.kind !== ACCOUNT_EMAIL_FACTOR_ID ||
				pending.expiresAtMs <= nowMs
			) {
				return refused("expired", attemptsRemaining);
			}
			const opened = sealing.openState(binding(tx), pending.state);
			if (opened.state === "key_unavailable") return unreadable({ keyId: opened.keyId });
			const stored =
				opened.state === "ok" ? digestIn(readKeptState(opened.value)?.state) : undefined;
			if (stored === undefined) return unreadable();

			const code = readLongCode(call.proof);
			if (code === undefined) return refused("malformed", attemptsRemaining);
			let found: ReturnType<typeof digests.matchesDigest>;
			try {
				found = digests.matchesDigest([tx.id, code], stored);
			} catch (cause) {
				return unreadable({ cause });
			}
			if (found === "key_unavailable") return unreadable({ keyId: stored.keyId });
			if (found === "mismatch") return refused("invalid", attemptsRemaining);

			const written = await kit.write(tx, {
				emailProof: { provedAtMs: nowMs },
				challenge: null,
			});
			// A resend moved the transaction on: the code this proves was replaced.
			if (written?.outcome === "unknown_transaction") return refused("expired", attemptsRemaining);
			if (written !== undefined) return written;
			return { outcome: "proved", ...about(tx) };
		},
	};
}
