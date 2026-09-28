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
 * How a session was established and what this provider vouches for, read the
 * one way every consumer of a session reads them (the MFA ADR's D9): the
 * requirement rule (`../mfa/requirement.mts`), whose input
 * `requirementSession` builds; `/authorize`; `/token` and the `session` grant,
 * which stamp `vouchedAmr`. And what each login path records, so the write
 * and the read are one design: `passwordSessionAuthentication`,
 * `federatedSessionAuthentication`, and whether a federation's upstream IdP's
 * `amr` counts at all (`federationTrustsUpstreamAmr`, D13).
 *
 * A session written since the build order's step 5 says how it was
 * established (`authentication`), and its `amr` holds only what this provider
 * vouches for: the federation callback kept an untrusted IdP's values apart
 * as it wrote the session. One written before carries no such key, and is
 * split as it is read: `fed` makes it federated, and every value beside `fed`
 * is what an upstream IdP asserted — kept for the record, never vouched for,
 * whether or not that federation is trusted now, because the session does not
 * say which federation wrote it; else `pwd` makes it a password login, whose
 * values are all this provider's own; else its primary cannot be told. No
 * such session has a second factor on record. So a pre-upgrade session is
 * never read as more trusted than it was written.
 */

import { FEDERATED_AMR, MFA_AMR, PASSWORD_AMR } from "../grants/authenticationClaims.mjs";
import { DEFAULT_CLOCK_SKEW_MS } from "../jwt/verify.mjs";
import type { MfaRequirementSession } from "../mfa/requirement.mjs";
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
 * rather than guess (D16). A copy: nothing done to the answer reaches the
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
 * What `POST /session/login` records (D9): `amr` `["pwd"]` (RFC 8176), primary
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
 * What a federation callback records (D9, D13), for the federation named
 * `federation` whose upstream IdP asserted `upstreamAmr`:
 *
 * - `trusted` (`federationTrustsUpstreamAmr`): the IdP's values beside `fed`
 *   in `amr`, where tokens carry them and `acr` is matched against them — as
 *   #481 recorded every federation's.
 * - otherwise: `amr` is `fed` alone, and the IdP's values are kept in
 *   `authentication.upstreamAmr` for the record, where nothing stamps them or
 *   reads them for `acr`.
 *
 * `upstreamAmr` is kept apart only when there is something to keep. The
 * values are copied.
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
 * verified, judged on the store's clock `nowMs`: at or after the epoch, and no
 * further ahead than the clock skew tolerated between hosts
 * (`DEFAULT_CLOCK_SKEW_MS`, five minutes — the tolerance the JWT verifier
 * gives an `iat` another host stamped ahead of it). Clocks are NTP-synced
 * (D22); one further ahead is no clock's reading. What is accepted is still
 * recorded no later than `nowMs` (`notAfter`): never a time still to come.
 */
const isRecordableVerificationTime = (ms: number, nowMs: number): boolean =>
	Number.isFinite(ms) && ms >= 0 && ms <= nowMs + DEFAULT_CLOCK_SKEW_MS;

/** `ms` as an instant no later than `nowMs`, the store's clock: a new `Date`. */
const notAfter = (ms: number, nowMs: number): Date => new Date(Math.min(ms, nowMs));

/**
 * Refuse, with a `RangeError`, an event that is not a second factor's (D9):
 * no values, one that is not a non-empty string, a primary's marker (`pwd`,
 * `fed` — a second factor must not change the primary the baseline is decided
 * on, as `composeAmr` holds a factor to), `mfa` with no value of the factor's
 * own beside it (`mfa` comes from a factor that adds it, D14, and alone names
 * no factor that was verified), or a time that is not a valid date at or
 * after the epoch, or further ahead of `nowMs` — the store's clock — than the
 * clock skew tolerated between hosts (`DEFAULT_CLOCK_SKEW_MS`). What
 * `recordSecondFactor` checks before it
 * reads anything, in every bundled store. The message names what is wrong
 * and quotes nothing but a primary's marker.
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
	const atMs = event.at instanceof Date ? event.at.getTime() : Number.NaN;
	if (!isRecordableVerificationTime(atMs, nowMs)) {
		throw new RangeError(
			"recordSecondFactor: at must be a valid date at or after the epoch, and no further ahead than hosts' clocks drift",
		);
	}
}

/**
 * Check an `authentication` a store is asked to record, and answer what to
 * record (D9). Refused, with a `RangeError`, is what `SessionAuthentication`
 * does not admit — so the two bundled stores refuse the same values, rather
 * than one copying a string's characters as a list and the other writing an
 * envelope it then reads as corrupt. `undefined` is a session written as one
 * from before the key; else an object with a non-empty string `primary`, a
 * `federation` that is a string or `undefined`, an `upstreamAmr` that is a
 * list of strings or `undefined`, and an `mfaAt` that is `undefined` or a
 * `Date` at or after the epoch and no further ahead of `nowMs`, the store's
 * clock, than the clock skew tolerated between hosts. The message names the
 * session and the field, and quotes nothing of the value.
 *
 * What it answers is a copy, its `mfaAt` no later than `nowMs`: a time a
 * little ahead is a clock, but recorded as it came it would count as recent
 * for longer than it is. What every bundled store's `create` records.
 */
export function checkSessionAuthentication(
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
 * What a session records once a second factor was verified in it (D9) — the
 * computation both bundled stores' `recordSecondFactor` write, so they cannot
 * differ. `amr`: what the session vouches for (`vouchedAmr`), then the
 * event's values, each once, in insertion order. `authentication`: the
 * session's (`sessionAuthentication`) with `mfaAt` the later of the two —
 * each first brought to no later than `nowMs`, the store's clock, so nothing
 * recorded is still to come, and a stored `mfaAt` a replica whose clock ran
 * ahead wrote is repaired here rather than kept as the later for as long.
 *
 * A session written before `authentication` existed is split here, first: a
 * pre-upgrade `["hwk", "fed"]` plus TOTP becomes `amr` `["fed", "otp", "mfa"]`
 * and `upstreamAmr` `["hwk"]` — never `["hwk", "fed", "otp", "mfa"]`, whose
 * `hwk`, an untrusted IdP's word, would meet `phr`. `null` for one whose
 * primary cannot be told. The event is checked (`checkSecondFactorEvent`)
 * against `nowMs`, the store's clock.
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
 * The requirement rule's input for `session` (the MFA ADR's D16): how it was
 * established and what it vouches for, through the two readers above — or
 * `null` when there is no session (no `sid`, or no `UserSessionStore`). Every
 * consumer builds the rule's input here and nowhere else: one built from the
 * record's own `amr` would let a value an untrusted IdP asserted in a
 * pre-upgrade session meet an `acr`.
 */
export function requirementSession(session: UserSession | null): MfaRequirementSession | null {
	if (session === null) return null;
	return { authentication: sessionAuthentication(session), amr: vouchedAmr(session) };
}

/**
 * Whether federation `name`'s upstream IdP's `amr` counts (the MFA ADR's
 * D13): `federations.<name>.trustUpstreamAmr`, beside `enabled` in both of a
 * section's shapes — the switch written inside the nested shape's
 * sub-section is a `RangeError` saying so. `true` records what the IdP asserted in the session's
 * `amr` beside `fed`, where tokens carry it and `acr` is matched against it;
 * absent or `false` keeps it apart, for the record only. A value that is
 * given but is neither is a `RangeError` naming the key and quoting nothing
 * of the value — read as either answer, a typo would decide what this
 * provider vouches for. Core's schema coerces the spellings an environment
 * variable delivers before this reads it; a hand-built configuration meets
 * this refusal instead.
 *
 * Read at composition by the federation callback, which writes the split,
 * and by the `acr` drop, which counts a trusted federation as able to
 * produce any value — one reading, so the two cannot disagree.
 */
export function federationTrustsUpstreamAmr(config: unknown, name: string): boolean {
	const federations = (config as { federations?: unknown } | null | undefined)?.federations;
	if (typeof federations !== "object" || federations === null) return false;
	if (!Object.hasOwn(federations, name)) return false;
	const section = (federations as Record<string, unknown>)[name];
	if (typeof section !== "object" || section === null) return false;
	// The nested shape's sub-section — keyed by `type`, or by the name when a
	// shorthand has none (session's `extractFederationSection`) — holds the
	// adapter's own settings. The switch there would be ignored, so an
	// operator who wrote it would believe the IdP trusted, or distrusted, when
	// neither holds: refused, saying where it belongs.
	const type =
		typeof (section as { type?: unknown }).type === "string"
			? (section as { type: string }).type
			: name;
	const sub = Object.hasOwn(section, type) ? (section as Record<string, unknown>)[type] : undefined;
	if (typeof sub === "object" && sub !== null && Object.hasOwn(sub, "trustUpstreamAmr")) {
		throw new RangeError(
			`federations.${name}.${type}.trustUpstreamAmr belongs beside enabled, as federations.${name}.trustUpstreamAmr`,
		);
	}
	const trust = Object.hasOwn(section, "trustUpstreamAmr")
		? (section as { trustUpstreamAmr?: unknown }).trustUpstreamAmr
		: undefined;
	if (trust === undefined) return false;
	if (typeof trust === "boolean") return trust;
	throw new RangeError(`federations.${name}.trustUpstreamAmr must be true or false`);
}
