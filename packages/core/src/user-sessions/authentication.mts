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
 * `requirementSession` builds, and `/authorize` today; `/token` and the
 * `session` grant once the upstream split lands.
 *
 * A session is read from its `amr`, because the record has no
 * `authentication` key yet (the build order's step 5 adds it): `fed` means a
 * federation callback wrote it, else `pwd` a password login, else the primary
 * cannot be told. No second factor is on record for such a session. Every
 * federation is trusted until the same step teaches the reading which are, so
 * every value the session recorded is vouched for — what #481 shipped.
 */

import { FEDERATED_AMR, PASSWORD_AMR } from "../grants/authenticationClaims.mjs";
import type { MfaRequirementSession } from "../mfa/requirement.mjs";
import type { SessionAuthentication, UserSession } from "./types.mjs";

/**
 * How `session` was established, or `undefined` when that cannot be told — a
 * session whose `amr` names neither a federation nor a password. The baseline
 * re-authenticates such a session rather than guess (D16).
 */
export function sessionAuthentication(session: UserSession): SessionAuthentication | undefined {
	const amr = session.amr ?? [];
	const primary = amr.includes(FEDERATED_AMR)
		? FEDERATED_AMR
		: amr.includes(PASSWORD_AMR)
			? PASSWORD_AMR
			: undefined;
	if (primary === undefined) return undefined;
	return { primary, federation: undefined, upstreamAmr: undefined, mfaAt: undefined };
}

/** The `amr` this provider vouches for in `session`, copied: what `acr` is matched against and a token may carry. */
export function vouchedAmr(session: UserSession): readonly string[] {
	return [...(session.amr ?? [])];
}

/**
 * The requirement rule's input for `session` (the MFA ADR's D16): how it was
 * established and what it vouches for, through the two readers above — or
 * `null` when there is no session (no `sid`, or no `UserSessionStore`). Every
 * consumer builds the rule's input here and nowhere else: one built from the
 * record's own `amr` would, once the upstream split lands, let a value an
 * untrusted IdP asserted meet an `acr`.
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
