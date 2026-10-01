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
 * How a session was established and what this provider vouches for, read
 * one way by every consumer (session admission through `requirementSession`,
 * `/authorize`, which records it on the code `/token` stamps, and the
 * `session` grant through `vouchedAmr`), beside what each
 * login path records (`passwordSessionAuthentication`,
 * `federatedSessionAuthentication`, `federationTrustsUpstreamAmr`), so the
 * write and the read are one design. See ADR
 * 2026-09-25-multi-factor-authentication.
 *
 * A session carrying `authentication` holds in `amr` only what this
 * provider vouches for. One written before that key is split as it is read:
 * `fed` makes it federated and every other value an upstream IdP's, never
 * vouched for, whatever that federation's trust is now, because the session
 * does not say which federation wrote it; else `pwd` makes it a password
 * login; else its primary cannot be told. It has no second factor on
 * record. A pre-upgrade session is never read as more trusted than it was
 * written.
 */

import { federationsOf } from "../federations/configured.mjs";
import { FEDERATED_AMR, MFA_AMR, PASSWORD_AMR } from "../grants/authenticationClaims.mjs";
import { DEFAULT_CLOCK_SKEW_MS } from "../jwt/verify.mjs";
import type { RequirementSession } from "../session-admission/requirement.mjs";
import { isRenewalNonce } from "./renewalNonce.mjs";
import type { SecondFactorEvent, SessionAuthentication, UserSession } from "./types.mjs";

/** A copy of `authentication` that shares nothing with it: its list and its date are new. */
export function copySessionAuthentication(
	authentication: SessionAuthentication,
): SessionAuthentication {
	return {
		primary: authentication.primary,
		federation: authentication.federation,
		upstreamAmr:
			authentication.upstreamAmr === undefined ? undefined : [...authentication.upstreamAmr],
		mfaAt:
			authentication.mfaAt === undefined ? undefined : new Date(authentication.mfaAt.getTime()),
	};
}

/**
 * How `session` was established, or `undefined` when that cannot be told — a
 * session written before the `authentication` key whose `amr` names neither a
 * federation nor a password. The baseline re-authenticates such a session
 * rather than guess. A copy: nothing done to the answer reaches the
 * session.
 */
export function sessionAuthentication(session: UserSession): SessionAuthentication | undefined {
	if (session.authentication !== undefined) {
		return copySessionAuthentication(session.authentication);
	}
	const amr = session.amr ?? [];
	if (amr.includes(FEDERATED_AMR)) {
		const upstream = amr.filter((value) => value !== FEDERATED_AMR);
		return {
			primary: FEDERATED_AMR,
			federation: undefined,
			upstreamAmr: upstream.length > 0 ? upstream : undefined,
			mfaAt: undefined,
		};
	}
	if (amr.includes(PASSWORD_AMR)) {
		return {
			primary: PASSWORD_AMR,
			federation: undefined,
			upstreamAmr: undefined,
			mfaAt: undefined,
		};
	}
	return undefined;
}

/**
 * The `amr` this provider vouches for in `session`, copied: what `acr` is
 * matched against and a token may carry. A recorded session's `amr`, which
 * holds nothing else; for one written before the `authentication` key, the
 * split: a federated session vouches for `fed` alone.
 */
export function vouchedAmr(session: UserSession): readonly string[] {
	const amr = session.amr ?? [];
	if (session.authentication === undefined && amr.includes(FEDERATED_AMR)) {
		return [FEDERATED_AMR];
	}
	return [...amr];
}

/** What a login path records about how the user authenticated: the `amr` and `authentication` a session is created with. */
export interface RecordedAuthentication {
	readonly amr: readonly string[];
	readonly authentication: SessionAuthentication;
}

/**
 * What `POST /session/login` records: `amr` `["pwd"]` (RFC 8176), primary
 * `pwd`, no second factor verified yet.
 */
export function passwordSessionAuthentication(): RecordedAuthentication {
	return {
		amr: [PASSWORD_AMR],
		authentication: {
			primary: PASSWORD_AMR,
			federation: undefined,
			upstreamAmr: undefined,
			mfaAt: undefined,
		},
	};
}

/**
 * What a federation callback records for the federation named `federation`,
 * whose upstream IdP asserted `upstreamAmr`. When `trusted`
 * (`federationTrustsUpstreamAmr`), the IdP's values sit beside `fed` in
 * `amr`, where tokens carry them and `acr` is matched against them;
 * otherwise `amr` is `fed` alone and the values, if any, are kept in
 * `authentication.upstreamAmr` for the record, where nothing stamps them or
 * reads them for `acr`. The values are copied.
 */
export function federatedSessionAuthentication(login: {
	readonly federation: string;
	readonly upstreamAmr: readonly string[];
	readonly trusted: boolean;
}): RecordedAuthentication {
	const upstream = [...login.upstreamAmr];
	return {
		amr: login.trusted ? [...new Set([...upstream, FEDERATED_AMR])] : [FEDERATED_AMR],
		authentication: {
			primary: FEDERATED_AMR,
			federation: login.federation,
			upstreamAmr: !login.trusted && upstream.length > 0 ? upstream : undefined,
			mfaAt: undefined,
		},
	};
}

/**
 * Whether `ms` is an instant a session may take as when a second factor was
 * verified, on the store's clock `nowMs`: at or after the epoch, and no
 * further ahead than the clock skew tolerated between hosts
 * (`DEFAULT_CLOCK_SKEW_MS`, the JWT verifier's `iat` tolerance). Clocks are
 * NTP-synced; one further ahead is no clock's reading. What is accepted is
 * still recorded no later than `nowMs` (`notAfter`).
 */
const isRecordableVerificationTime = (ms: number, nowMs: number): boolean =>
	Number.isFinite(ms) && ms >= 0 && ms <= nowMs + DEFAULT_CLOCK_SKEW_MS;

/** `ms` as an instant no later than `nowMs`, the store's clock: a new `Date`. */
const notAfter = (ms: number, nowMs: number): Date => new Date(Math.min(ms, nowMs));

/**
 * Refuses, with a `RangeError`, an event that is not a second factor's: no
 * values; a value that is not a non-empty string; a primary's marker (`pwd`,
 * `fed`: a second factor must not change the primary the baseline is
 * decided on); `mfa` alone (it comes beside a factor's own values, and alone
 * names no factor); a time `isRecordableVerificationTime` refuses on
 * `nowMs`, the store's clock. Every bundled store's `recordSecondFactor`
 * runs this, and {@link readRenewalNonces}, before it reads anything. The
 * message quotes nothing but a primary's marker.
 */
export function checkSecondFactorEvent(event: SecondFactorEvent, nowMs: number): void {
	const amr: unknown = event?.amr;
	if (!Array.isArray(amr) || amr.length === 0) {
		throw new RangeError("recordSecondFactor: a second factor adds at least one amr value");
	}
	for (const value of amr) {
		if (typeof value !== "string" || value.length === 0) {
			throw new RangeError("recordSecondFactor: amr values must be non-empty strings");
		}
		if (value === PASSWORD_AMR || value === FEDERATED_AMR) {
			throw new RangeError(
				`recordSecondFactor: "${value}" marks a primary authentication, never a second factor's amr`,
			);
		}
	}
	if (amr.every((value) => value === MFA_AMR)) {
		throw new RangeError(
			`recordSecondFactor: "${MFA_AMR}" comes beside a factor's own amr values, never alone`,
		);
	}
	const at: unknown = event.at;
	const atMs = at instanceof Date ? at.getTime() : Number.NaN;
	if (!isRecordableVerificationTime(atMs, nowMs)) {
		throw new RangeError(
			"recordSecondFactor: at must be a valid date at or after the epoch, and no further ahead than hosts' clocks drift",
		);
	}
}

/** An event's two renewal nonces, as {@link readRenewalNonces} read them. */
export interface RenewalNonces {
	readonly renewalNonce?: string;
	readonly expectedRenewalNonce?: string;
}

/**
 * The event's `renewalNonce` and `expectedRenewalNonce`, each read once and
 * answered as a frozen copy: what a store compares and records is what was
 * checked. Refuses, with a `RangeError`, one that is not a nonce
 * (`isRenewalNonce`).
 */
export function readRenewalNonces(event: SecondFactorEvent): RenewalNonces {
	const renewalNonce: unknown = event?.renewalNonce;
	if (renewalNonce !== undefined && !isRenewalNonce(renewalNonce)) {
		throw new RangeError("recordSecondFactor: renewalNonce must be one newRenewalNonce spells");
	}
	const expectedRenewalNonce: unknown = event?.expectedRenewalNonce;
	if (expectedRenewalNonce !== undefined && !isRenewalNonce(expectedRenewalNonce)) {
		throw new RangeError(
			"recordSecondFactor: expectedRenewalNonce must be one newRenewalNonce spells",
		);
	}
	return Object.freeze({
		...(renewalNonce === undefined ? {} : { renewalNonce }),
		...(expectedRenewalNonce === undefined ? {} : { expectedRenewalNonce }),
	});
}

/**
 * Whether a session holding `held` may record an event whose nonces are
 * `nonces`: its renewal nonce is the one expected, absent matching absent.
 * Every bundled store asks it in the same atomic step as its write.
 */
export function expectsRenewalNonce(held: string | undefined, nonces: RenewalNonces): boolean {
	return held === nonces.expectedRenewalNonce;
}

/**
 * What a store records as a session's `authentication`: the value given,
 * checked, answered as a copy whose `mfaAt` is no later than `nowMs`, the
 * store's clock (a time a little ahead is a clock, but kept as it came it
 * would count as recent for longer than it is). Every bundled store's
 * `create` records this answer, never its own input, so both refuse the
 * same values.
 *
 * `undefined` is a session written as one from before the key; anything
 * else must be what `SessionAuthentication` admits, its `mfaAt` passing
 * `isRecordableVerificationTime`.
 *
 * @throws RangeError naming the session and the field, quoting nothing of
 *   the value.
 */
export function recordableSessionAuthentication(
	sid: string,
	authentication: unknown,
	nowMs: number,
): SessionAuthentication | undefined {
	if (authentication === undefined) return undefined;
	const refuse = (field: string, rule: string): never => {
		throw new RangeError(`UserSession ${sid}: ${field} must be ${rule}`);
	};
	if (
		typeof authentication !== "object" ||
		authentication === null ||
		Array.isArray(authentication)
	) {
		return refuse("authentication", "an object, or undefined");
	}
	const a = authentication as Partial<Record<keyof SessionAuthentication, unknown>>;
	if (typeof a.primary !== "string" || a.primary.length === 0) {
		refuse("authentication.primary", "a non-empty string");
	}
	if (a.federation !== undefined && typeof a.federation !== "string") {
		refuse("authentication.federation", "a string, or undefined");
	}
	if (
		a.upstreamAmr !== undefined &&
		!(Array.isArray(a.upstreamAmr) && a.upstreamAmr.every((value) => typeof value === "string"))
	) {
		refuse("authentication.upstreamAmr", "a list of strings, or undefined");
	}
	if (
		a.mfaAt !== undefined &&
		!(a.mfaAt instanceof Date && isRecordableVerificationTime(a.mfaAt.getTime(), nowMs))
	) {
		refuse(
			"authentication.mfaAt",
			"a valid date at or after the epoch, no further ahead than hosts' clocks drift, or undefined",
		);
	}
	const valid = authentication as SessionAuthentication;
	return {
		...copySessionAuthentication(valid),
		mfaAt: valid.mfaAt === undefined ? undefined : notAfter(valid.mfaAt.getTime(), nowMs),
	};
}

/**
 * What a session records once a second factor was verified in it; both
 * bundled stores' `recordSecondFactor` write this, so they cannot differ.
 * `amr`: `vouchedAmr(session)`, then the event's values, each once, in
 * order. `authentication`: `sessionAuthentication(session)` with `mfaAt`
 * the later of the two, each first capped at `nowMs`, the store's clock, so
 * nothing recorded is still to come and a stored `mfaAt` from a replica
 * whose clock ran ahead is repaired rather than kept.
 *
 * A pre-upgrade session is split first: `["hwk", "fed"]` plus TOTP becomes
 * `amr` `["fed", "otp", "mfa"]` and `upstreamAmr` `["hwk"]`, so an untrusted
 * IdP's `hwk` never meets `phr`. `null` for one whose primary cannot be
 * told. The event is checked first (`checkSecondFactorEvent`).
 */
export function sessionAfterSecondFactor(
	session: UserSession,
	event: SecondFactorEvent,
	nowMs: number,
): RecordedAuthentication | null {
	checkSecondFactorEvent(event, nowMs);
	const authentication = sessionAuthentication(session);
	if (authentication === undefined) return null;
	const atMs = Math.min(event.at.getTime(), nowMs);
	const storedMs =
		authentication.mfaAt === undefined
			? undefined
			: Math.min(authentication.mfaAt.getTime(), nowMs);
	const mfaAt = new Date(storedMs !== undefined && storedMs >= atMs ? storedMs : atMs);
	return {
		amr: [...new Set([...vouchedAmr(session), ...event.amr])],
		authentication: { ...authentication, mfaAt },
	};
}

/**
 * What a session requirement is asked about `session`: how it was
 * established and what it vouches for, through the two readers above, or
 * `null` when there is no session (no `sid`, or no `UserSessionStore`).
 * Admission builds it here and nowhere else, and its `acr` selection reads
 * the `amr` from it: one built from the record's own `amr` would let a
 * value an untrusted IdP asserted in a pre-upgrade session meet an `acr`.
 */
export function requirementSession(session: UserSession | null): RequirementSession | null {
	if (session === null) return null;
	return frozenRequirementSession(sessionAuthentication(session), vouchedAmr(session));
}

/**
 * A requirement's reading, frozen with its `amr` and `upstreamAmr`: each
 * call's own copy (its `mfaAt` a `Date` of its own), so what one holder does
 * to it reaches no other.
 */
const frozenRequirementSession = (
	authentication: SessionAuthentication | undefined,
	amr: readonly string[],
): RequirementSession =>
	Object.freeze({
		authentication:
			authentication === undefined
				? undefined
				: Object.freeze({
						...authentication,
						upstreamAmr:
							authentication.upstreamAmr === undefined
								? undefined
								: Object.freeze([...authentication.upstreamAmr]),
					}),
		amr: Object.freeze([...amr]),
	});

/**
 * What a session requirement is asked about a token that carries no live
 * session: the primary read from the token's `amr` (`fed`, else `pwd`, else
 * unknown, as for an older token that carries no `amr`), no second factor
 * on record, and the `amr` as vouched, since a token is minted from
 * `vouchedAmr` and carries nothing an IdP asserted. A frozen copy.
 */
export function requirementSessionFromAmr(amr: readonly string[] | undefined): RequirementSession {
	const held = amr === undefined ? [] : [...amr];
	const primary = held.includes(FEDERATED_AMR)
		? FEDERATED_AMR
		: held.includes(PASSWORD_AMR)
			? PASSWORD_AMR
			: undefined;
	return frozenRequirementSession(
		primary === undefined
			? undefined
			: { primary, federation: undefined, upstreamAmr: undefined, mfaAt: undefined },
		held,
	);
}

/**
 * Whether federation `name`'s upstream IdP's `amr` counts: only when
 * `core.federations.<name>.trustUpstreamAmr` is `true` beside `enabled: true`,
 * in either section shape. Then the IdP's values sit in the session's `amr`
 * beside `fed`, where tokens carry them and `acr` is matched against them;
 * otherwise they are kept apart, for the record only.
 *
 * A non-boolean value, or the switch inside the nested shape's sub-section,
 * is a `RangeError` naming the key and quoting nothing of the value: read
 * either way, a typo would decide what this provider vouches for. The
 * refusals come first, so a disabled section's bad switch still refuses the
 * composition. Core's schema coerces environment-variable spellings first;
 * a hand-built configuration meets the refusal.
 *
 * The federation callback (which writes the split) and the `acr` drop both
 * read this one function, so they cannot disagree.
 */
export function federationTrustsUpstreamAmr(config: unknown, name: string): boolean {
	const federations = federationsOf(config);
	if (!Object.hasOwn(federations, name)) return false;
	const section = federations[name];
	if (typeof section !== "object" || section === null) return false;
	// The nested shape's sub-section (keyed by `type`, or by the name for a
	// shorthand: session's `extractFederationSection`) holds the adapter's own
	// settings. A switch there would be silently ignored, so it is refused.
	const type =
		typeof (section as { type?: unknown }).type === "string"
			? (section as { type: string }).type
			: name;
	const sub = Object.hasOwn(section, type) ? (section as Record<string, unknown>)[type] : undefined;
	if (typeof sub === "object" && sub !== null && Object.hasOwn(sub, "trustUpstreamAmr")) {
		throw new RangeError(
			`core.federations.${name}.${type}.trustUpstreamAmr belongs beside enabled, as core.federations.${name}.trustUpstreamAmr`,
		);
	}
	const trust = Object.hasOwn(section, "trustUpstreamAmr")
		? (section as { trustUpstreamAmr?: unknown }).trustUpstreamAmr
		: undefined;
	if (trust !== undefined && typeof trust !== "boolean") {
		throw new RangeError(`core.federations.${name}.trustUpstreamAmr must be true or false`);
	}
	const enabled =
		Object.hasOwn(section, "enabled") && (section as { enabled?: unknown }).enabled === true;
	return enabled && trust === true;
}
