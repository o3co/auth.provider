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

import {
	type MailPurpose,
	type MailSender,
	type MfaDigests,
	type MfaKeyedDigest,
	mailSendOutcome,
	normaliseMailAddress,
} from "@o3co/auth-provider-core";

/** What `keep` answers: the state written, with how to clear it — `true` once the clear is written — or why it was not. */
export type MfaMailKept<Refusal> =
	| { readonly kept: true; readonly clear: () => Promise<boolean> }
	| { readonly kept: false; readonly refusal: Refusal };

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
	readonly keep: (
		addressDigest: MfaKeyedDigest,
		expiresAtMs: number,
	) => Promise<MfaMailKept<Refusal>>;
}

export type MfaMailOutcome<Refusal> =
	| { readonly outcome: "sent"; readonly to: string; readonly expiresAtMs: number }
	/** Not a mail of the call's purpose, with a code, expiring after now: the asker's fault. */
	| { readonly outcome: "malformed" }
	| { readonly outcome: "no_sender" }
	/** A code that stands in for a factor, for an account with no address. */
	| { readonly outcome: "no_address" }
	/** A login code whose recorded digest is not the account's address's, or none. */
	| { readonly outcome: "address_mismatch" }
	| { readonly outcome: "key_unavailable"; readonly keyId: string }
	| { readonly outcome: "not_kept"; readonly refusal: Refusal }
	| { readonly outcome: "refused_at_limit"; readonly cleared: boolean }
	| { readonly outcome: "unavailable"; readonly cause: unknown; readonly cleared: boolean };

/** What a sender answered outside its port, as the outage's cause. */
const OUTSIDE_CONTRACT = new TypeError("the mail sender answered outside its port's contract");

const isRecord = (value: unknown): value is Readonly<Record<string, unknown>> =>
	typeof value === "object" && value !== null && !Array.isArray(value);

/**
 * The mail a factor's answer asks for, as a plain copy of the fields
 * `sendMfaMail` reads — its address digest's too — each read once; anything
 * that is not an object as it is. A read that throws is thrown: the caller
 * reads the factor's answer inside the catch that makes it the factor's failure.
 */
export function copyAskedMail(value: unknown): unknown {
	if (!isRecord(value)) return value;
	const { purpose, code, expiresAtMs, addressDigest } = value;
	return {
		purpose,
		code,
		expiresAtMs,
		addressDigest: isRecord(addressDigest)
			? { keyId: addressDigest.keyId, digest: addressDigest.digest }
			: addressDigest,
	};
}

/** The mail as asked, read once, or `undefined` when it is not one of `purpose` with a code expiring after `nowMs`. */
function readMail(
	value: unknown,
	purpose: MailPurpose,
	nowMs: number,
):
	| {
			readonly code: string;
			readonly expiresAtMs: number | undefined;
			readonly addressDigest: unknown;
	  }
	| undefined {
	try {
		if (!isRecord(value) || value.purpose !== purpose) return undefined;
		const { code, expiresAtMs, addressDigest } = value;
		if (typeof code !== "string" || code === "") return undefined;
		if (expiresAtMs !== undefined && !(typeof expiresAtMs === "number" && expiresAtMs > nowMs)) {
			return undefined;
		}
		return { code, expiresAtMs, addressDigest };
	} catch {
		return undefined;
	}
}

/**
 * Whether `recorded`, the digest a login code carries, is the digest of
 * `address`: `match`, `mismatch` — for `null`, anything that is not a keyed
 * digest, or another address's — or the key the ring no longer holds.
 */
function compareAddress(
	digests: MfaDigests,
	address: string,
	recorded: unknown,
): "match" | "mismatch" | { readonly keyUnavailable: string } {
	if (!isRecord(recorded)) return "mismatch";
	const { keyId, digest } = recorded;
	if (typeof keyId !== "string" || typeof digest !== "string") return "mismatch";
	try {
		const found = digests.matchesDigest([address], { keyId, digest });
		if (found === "key_unavailable") return { keyUnavailable: keyId };
		return found === "match" ? "match" : "mismatch";
	} catch {
		// A value that is not a digest as the ring makes one.
		return "mismatch";
	}
}

/**
 * Whether `address`, as the account's user record holds it, is the one
 * `recorded` is the digest of — what a login code is held to; `no_address`
 * for an account with no address.
 */
export function matchesRecordedAddress(
	digests: MfaDigests,
	address: unknown,
	recorded: unknown,
): "match" | "mismatch" | "no_address" | { readonly keyUnavailable: string } {
	const to = normaliseMailAddress(address);
	return to === undefined ? "no_address" : compareAddress(digests, to, recorded);
}

/**
 * The keyed digest of `address`, as the account's user record holds it,
 * that a mail to it keeps; `undefined` for an account with no address.
 */
export function addressDigestOf(digests: MfaDigests, address: unknown): MfaKeyedDigest | undefined {
	const to = normaliseMailAddress(address);
	return to === undefined ? undefined : digestOf(digests, to);
}

/** The keyed digest of `to`, an address as `normaliseMailAddress` spells it. */
const digestOf = (digests: MfaDigests, to: string): MfaKeyedDigest => digests.digest([to]);

/** Sends `options.mail` in the order this file's header states. */
export async function sendMfaMail<Refusal>(
	options: SendMfaMailOptions<Refusal>,
): Promise<MfaMailOutcome<Refusal>> {
	const { sender, purpose, digests, nowMs, notAfterMs } = options;
	const mail = readMail(options.mail, purpose, nowMs);
	if (mail === undefined) return { outcome: "malformed" };
	if (sender === undefined) return { outcome: "no_sender" };
	const to = normaliseMailAddress(options.address);
	if (purpose === "login_code") {
		const compared = matchesRecordedAddress(digests, options.address, mail.addressDigest);
		if (compared === "mismatch" || compared === "no_address")
			return { outcome: "address_mismatch" };
		if (compared !== "match") return { outcome: "key_unavailable", keyId: compared.keyUnavailable };
	}
	if (to === undefined) return { outcome: "no_address" };
	const expiresAtMs = Math.min(mail.expiresAtMs ?? notAfterMs, notAfterMs);
	const kept = await options.keep(digestOf(digests, to), expiresAtMs);
	if (!kept.kept) return { outcome: "not_kept", refusal: kept.refusal };

	let answer: "delivered" | "refused_at_limit" | "outage";
	let cause: unknown = OUTSIDE_CONTRACT;
	try {
		answer = mailSendOutcome(
			await sender.send({ purpose, subject: options.subject, to, code: mail.code, expiresAtMs }),
		);
	} catch (err) {
		answer = "outage";
		cause = err;
	}
	if (answer === "delivered") return { outcome: "sent", to, expiresAtMs };
	let cleared: boolean;
	try {
		cleared = (await kept.clear()) === true;
	} catch {
		cleared = false;
	}
	return answer === "refused_at_limit"
		? { outcome: "refused_at_limit", cleared }
		: { outcome: "unavailable", cause, cleared };
}

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
export type MfaMailRefusal =
	| MfaMailUnavailable
	| {
			readonly outcome: "mail_refused_at_limit";
			readonly purpose: MailPurpose;
			readonly kind: string;
			readonly cleared: boolean;
	  };

/** `mailed`, one of the outcomes every ceremony answers alike, as its refusal for `purpose` and `kind`. */
export function mailRefusalOf(
	mailed: Extract<
		MfaMailOutcome<unknown>,
		{ outcome: "no_sender" | "refused_at_limit" | "unavailable" }
	>,
	purpose: MailPurpose,
	kind: string,
): MfaMailRefusal {
	switch (mailed.outcome) {
		case "refused_at_limit":
			return { outcome: "mail_refused_at_limit", purpose, kind, cleared: mailed.cleared };
		case "no_sender":
			return { outcome: "mail_unavailable", purpose, kind, reason: "no_sender" };
		case "unavailable":
			return {
				outcome: "mail_unavailable",
				purpose,
				kind,
				reason: "outage",
				cleared: mailed.cleared,
				cause: mailed.cause,
			};
		default:
			return mailed satisfies never;
	}
}

/** A name or a code a sender's failure may be logged by: a short token, never text. */
const TOKEN = /^[A-Za-z0-9_.-]{1,64}$/;

/**
 * What of a sender's failure — or a factor's own — may be logged: its `name`
 * and `code` when each is a short token, and its `status` (or
 * `responseCode`, SMTP's) when it is a whole number — never its message,
 * which a relay or a factor may write the address, the username or the code
 * into.
 */
export function mailFailureOf(cause: unknown): {
	readonly name?: string;
	readonly code?: string | number;
	readonly status?: number;
} {
	try {
		if (typeof cause !== "object" || cause === null) return {};
		const { name, code, status, responseCode } = cause as Readonly<Record<string, unknown>>;
		const whole = (value: unknown): value is number =>
			typeof value === "number" && Number.isSafeInteger(value);
		const statusOf = whole(status) ? status : whole(responseCode) ? responseCode : undefined;
		return {
			...(typeof name === "string" && TOKEN.test(name) ? { name } : {}),
			...((typeof code === "string" && TOKEN.test(code)) || whole(code) ? { code } : {}),
			...(statusOf === undefined ? {} : { status: statusOf }),
		};
	} catch {
		return {};
	}
}

/**
 * The address a code went to, as a page may show it: the local part's first
 * character, `***`, and the domain, as `normaliseMailAddress` spells the
 * address (`k***@example.com`); `undefined` for a value that is no address.
 */
export function maskMailAddress(address: unknown): string | undefined {
	const normalised = normaliseMailAddress(address);
	if (normalised === undefined) return undefined;
	const at = normalised.lastIndexOf("@");
	const local = normalised.slice(0, at).replace(/^"/, "");
	const [first = ""] = local;
	return `${first}***${normalised.slice(at)}`;
}

/** Where a code went and how long it lives: what a page is answered once a code was sent. */
export interface MfaMailedAnswer {
	/** The address the code went to, masked (`maskMailAddress`). */
	readonly sent_to: string | undefined;
	/** Whole seconds until the code expires, rounded up, at least 1. */
	readonly expires_in: number;
}

/** The answer for a code `sent` at `nowMs`: the one reading every ceremony that mails a code answers with. */
export function mailedAnswer(
	sent: { readonly to: string; readonly expiresAtMs: number },
	nowMs: number,
): MfaMailedAnswer {
	return {
		sent_to: maskMailAddress(sent.to),
		expires_in: Math.max(1, Math.ceil((sent.expiresAtMs - nowMs) / 1000)),
	};
}

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
export function keptState(kept: MfaKeptState): Readonly<Record<string, unknown>> {
	const envelope = {
		...(kept.state === undefined ? {} : { state: kept.state }),
		...(kept.addressDigest === undefined ? {} : { addressDigest: kept.addressDigest }),
	};
	if (readKeptState(envelope) === undefined) {
		throw new RangeError(
			"a pending state is kept only as readKeptState reads it back: a state that is an object and not a list, and an address digest of a key id and a digest, both text",
		);
	}
	return envelope;
}

/** A pending state as opened, read back; `undefined` when it is not what {@link keptState} seals. */
export function readKeptState(opened: Readonly<Record<string, unknown>>): MfaKeptState | undefined {
	if (Object.keys(opened).some((key) => key !== "state" && key !== "addressDigest")) {
		return undefined;
	}
	const { state, addressDigest } = opened;
	if (state !== undefined && !isRecord(state)) return undefined;
	if (addressDigest !== undefined) {
		if (!isRecord(addressDigest)) return undefined;
		const { keyId, digest } = addressDigest;
		if (typeof keyId !== "string" || typeof digest !== "string") return undefined;
		return { state, addressDigest: { keyId, digest } };
	}
	return { state, addressDigest: undefined };
}
