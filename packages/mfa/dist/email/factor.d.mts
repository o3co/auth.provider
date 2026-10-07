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
import { type MfaDigests, type MfaFactor, type MfaFactorData, type MfaKeyedDigest } from "@o3co/auth-provider-core";
/** The kind an email factor's records carry, and the key it is contributed under. */
export declare const EMAIL_FACTOR_KIND = "email";
/** What the factor is built with, from its section. */
export interface EmailFactorSettings {
    /** Whether a verification adds `mfa` beside `email`. */
    readonly addsMfa: boolean;
    /** How long a mailed code is accepted; the coordinator caps it at the transaction's expiry. */
    readonly codeTtlSeconds: number;
}
/**
 * The digest of the address the record `data` of a factor this file made was
 * enrolled with — `null` when it holds none it can read; `undefined` for any
 * other factor.
 */
export declare function enrolledAddressDigest(factor: MfaFactor, data: MfaFactorData): MfaKeyedDigest | null | undefined;
/**
 * The identity the record of an enrollment of `factor`, a factor this file
 * made, would answer once its code went to `user`'s address — its digest
 * under `digests` as the coordinator keeps it at the send
 * (`addressDigestOf`); `undefined` for an account with no address, and for
 * any other factor, which is answered before anything is digested.
 */
export declare function enrollmentIdentity(factor: MfaFactor, digests: MfaDigests, user: Readonly<Record<string, unknown>>): string | undefined;
/** The `email` factor, its codes living `settings.codeTtlSeconds`. */
export declare function createEmailFactor(settings: EmailFactorSettings): MfaFactor;
//# sourceMappingURL=factor.d.mts.map