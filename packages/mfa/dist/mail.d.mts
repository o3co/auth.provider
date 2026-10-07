/**
 * MFA mail: the one place a code the provider issued is handed to the mail
 * sender (the MFA ADR's D5, F5, D23), and the masked address a page may show.
 *
 * `sendMfaMail`, in this order, each step writing nothing when it refuses:
 *
 * 1. The mail is one of the call's purpose, with a code, expiring after now.
 * 2. A sender is wired.
 * 3. The recipient is the account's address as `normaliseMailAddress` spells
 *    it. For a login code it must match the digest the factor recorded: a
 *    digest that is `null`, not a keyed digest, or another address's, and an
 *    account with no address, are a mismatch; a digest under a key the ring
 *    no longer holds is that key's outage. Never a throw.
 * 4. `keep` writes the pending state with the keyed digest of that address,
 *    expiring at the mail's expiry, capped at the transaction's.
 * 5. The sender is handed the purpose, the subject, that address, the code
 *    and the expiry; what it answered is read through `mailSendOutcome` alone.
 *    Anything but `delivered` clears the pending state and is never "sent";
 *    `cleared` says whether the clear was written.
 *
 * An outcome never carries the code; `sent` carries the address, for masking
 * only. Neither is ever logged: a sender's failure is logged through
 * `mailFailureOf`, never its text. `mailRefusalOf` is the one reading of a
 * mail every ceremony refuses alike.
 */
import { type MailPurpose, type MailSender, type MfaDigests, type MfaKeyedDigest } from "@o3co/auth-provider-core";
/** What `keep` answers: the state written, with how to clear it — `true` once the clear is written — or why it was not. */
export type MfaMailKept<Refusal> = {
    readonly kept: true;
    readonly clear: () => Promise<boolean>;
} | {
    readonly kept: false;
    readonly refusal: Refusal;
};
export interface SendMfaMailOptions<Refusal> {
    /** The composition's mail sender; without one nothing is kept or sent. */
    readonly sender: MailSender | undefined;
    /** What a factor's challenge or enrollment asked to be mailed, or the account-email proof's code. */
    readonly mail: unknown;
    /** The one purpose this call sends. */
    readonly purpose: MailPurpose;
    /** The account's subject (`User.id`). */
    readonly subject: string;
    /** The account's address as its user record holds it (`User.email`). */
    readonly address: unknown;
    readonly nowMs: number;
    /** The latest the code may be accepted: its transaction's expiry. */
    readonly notAfterMs: number;
    /** Keyed digests of the address, under the ring, bound to the kind the factor records them under. */
    readonly digests: MfaDigests;
    /** Writes the pending state with the address's digest, expiring at `expiresAtMs`. */
    readonly keep: (addressDigest: MfaKeyedDigest, expiresAtMs: number) => Promise<MfaMailKept<Refusal>>;
}
export type MfaMailOutcome<Refusal> = {
    readonly outcome: "sent";
    readonly to: string;
    readonly expiresAtMs: number;
}
/** Not a mail of the call's purpose, with a code, expiring after now: the asker's fault. */
 | {
    readonly outcome: "malformed";
} | {
    readonly outcome: "no_sender";
}
/** A code that stands in for a factor, for an account with no address. */
 | {
    readonly outcome: "no_address";
}
/** A login code whose recorded digest is not the account's address's, or none. */
 | {
    readonly outcome: "address_mismatch";
} | {
    readonly outcome: "key_unavailable";
    readonly keyId: string;
} | {
    readonly outcome: "not_kept";
    readonly refusal: Refusal;
} | {
    readonly outcome: "refused_at_limit";
    readonly cleared: boolean;
} | {
    readonly outcome: "unavailable";
    readonly cause: unknown;
    readonly cleared: boolean;
};
/**
 * The mail a factor's answer asks for, as a plain copy of the fields
 * `sendMfaMail` reads — its address digest's too — each read once; anything
 * that is not an object as it is. A read that throws is thrown: the caller
 * reads the factor's answer inside the catch that makes it the factor's failure.
 */
export declare function copyAskedMail(value: unknown): unknown;
/**
 * Whether `address`, as the account's user record holds it, is the one
 * `recorded` is the digest of — what a login code is held to; `no_address`
 * for an account with no address.
 */
export declare function matchesRecordedAddress(digests: MfaDigests, address: unknown, recorded: unknown): "match" | "mismatch" | "no_address" | {
    readonly keyUnavailable: string;
};
/**
 * The keyed digest of `address`, as the account's user record holds it,
 * that a mail to it keeps; `undefined` for an account with no address.
 */
export declare function addressDigestOf(digests: MfaDigests, address: unknown): MfaKeyedDigest | undefined;
/** Sends `options.mail` in the order this file's header states. */
export declare function sendMfaMail<Refusal>(options: SendMfaMailOptions<Refusal>): Promise<MfaMailOutcome<Refusal>>;
/** A mail the ceremony needed and could not send: no sender wired, or the sender's outage. */
export interface MfaMailUnavailable {
    readonly outcome: "mail_unavailable";
    readonly purpose: MailPurpose;
    readonly kind: string;
    readonly reason: "no_sender" | "outage";
    /** Whether the pending code was cleared, where one was kept. */
    readonly cleared?: boolean;
    readonly cause?: unknown;
}
/** A mail every ceremony refuses alike: `429` at the sender's limit, else `503`. */
export type MfaMailRefusal = MfaMailUnavailable | {
    readonly outcome: "mail_refused_at_limit";
    readonly purpose: MailPurpose;
    readonly kind: string;
    readonly cleared: boolean;
};
/** `mailed`, one of the outcomes every ceremony answers alike, as its refusal for `purpose` and `kind`. */
export declare function mailRefusalOf(mailed: Extract<MfaMailOutcome<unknown>, {
    outcome: "no_sender" | "refused_at_limit" | "unavailable";
}>, purpose: MailPurpose, kind: string): MfaMailRefusal;
/**
 * What of a sender's failure — or a factor's own — may be logged: its `name`
 * and `code` when each is a short token, and its `status` (or
 * `responseCode`, SMTP's) when it is a whole number — never its message,
 * which a relay or a factor may write the address, the username or the code
 * into.
 */
export declare function mailFailureOf(cause: unknown): {
    readonly name?: string;
    readonly code?: string | number;
    readonly status?: number;
};
/**
 * The address a code went to, as a page may show it: the local part's first
 * character, `***`, and the domain, as `normaliseMailAddress` spells the
 * address (`k***@example.com`); `undefined` for a value that is no address.
 */
export declare function maskMailAddress(address: unknown): string | undefined;
/** Where a code went and how long it lives: what a page is answered once a code was sent. */
export interface MfaMailedAnswer {
    /** The address the code went to, masked (`maskMailAddress`). */
    readonly sent_to: string | undefined;
    /** Whole seconds until the code expires, rounded up, at least 1. */
    readonly expires_in: number;
}
/** The answer for a code `sent` at `nowMs`: the one reading every ceremony that mails a code answers with. */
export declare function mailedAnswer(sent: {
    readonly to: string;
    readonly expiresAtMs: number;
}, nowMs: number): MfaMailedAnswer;
/** The kept form of a ceremony's pending state: the factor's state, and the digest of the address its code went to. */
export interface MfaKeptState {
    readonly state: Readonly<Record<string, unknown>> | undefined;
    readonly addressDigest: MfaKeyedDigest | undefined;
}
/**
 * What is sealed for a pending state: `state` and `addressDigest`, each when
 * present. A `RangeError`, quoting nothing, for one {@link readKeptState}
 * would not read back — it is the one rule for both.
 */
export declare function keptState(kept: MfaKeptState): Readonly<Record<string, unknown>>;
/** A pending state as opened, read back; `undefined` when it is not what {@link keptState} seals. */
export declare function readKeptState(opened: Readonly<Record<string, unknown>>): MfaKeptState | undefined;
//# sourceMappingURL=mail.d.mts.map