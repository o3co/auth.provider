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

import { FEDERATED_AMR, PASSWORD_AMR } from "../grants/authenticationClaims.mjs";
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
 * Refuse, with a `RangeError`, an event that is not a second factor's (D9):
 * no values, one that is not a non-empty string, a primary's marker (`pwd`,
 * `fed` — a second factor must not change the primary the baseline is decided
 * on, as `composeAmr` holds a factor to), or a time that is not a valid date
 * at or after the epoch. What `recordSecondFactor` checks before it reads
 * anything, in every bundled store.
 */
export function checkSecondFactorEvent(event: SecondFactorEvent): void {
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
	const atMs = event.at instanceof Date ? event.at.getTime() : Number.NaN;
	if (!Number.isFinite(atMs) || atMs < 0) {
		throw new RangeError("recordSecondFactor: at must be a valid date at or after the epoch");
	}
}

/**
 * What a session records once a second factor was verified in it (D9) — the
 * computation both bundled stores' `recordSecondFactor` write, so they cannot
 * differ. `amr`: what the session vouches for (`vouchedAmr`), then the
 * event's values, each once, in insertion order. `authentication`: the
 * session's (`sessionAuthentication`) with `mfaAt` the later of the two.
 *
 * A session written before `authentication` existed is split here, first: a
 * pre-upgrade `["hwk", "fed"]` plus TOTP becomes `amr` `["fed", "otp", "mfa"]`
 * and `upstreamAmr` `["hwk"]` — never `["hwk", "fed", "otp", "mfa"]`, whose
 * `hwk`, an untrusted IdP's word, would meet `phr`. `null` for one whose
 * primary cannot be told. The event is checked (`checkSecondFactorEvent`).
 */
export function sessionAfterSecondFactor(
	session: UserSession,
	event: SecondFactorEvent,
): RecordedAuthentication | null {
	checkSecondFactorEvent(event);
	const authentication = sessionAuthentication(session);
	if (authentication === undefined) return null;
	const atMs = event.at.getTime();
	const mfaAt =
		authentication.mfaAt !== undefined && authentication.mfaAt.getTime() >= atMs
			? authentication.mfaAt
			: new Date(atMs);
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
 * section's shapes. `true` records what the IdP asserted in the session's
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
	const trust = Object.hasOwn(section, "trustUpstreamAmr")
		? (section as { trustUpstreamAmr?: unknown }).trustUpstreamAmr
		: undefined;
	if (trust === undefined) return false;
	if (typeof trust === "boolean") return trust;
	throw new RangeError(`federations.${name}.trustUpstreamAmr must be true or false`);
}
