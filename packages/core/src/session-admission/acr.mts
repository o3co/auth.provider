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
 * The provider's `acr` vocabulary (the MFA ADR's D15; the session-admission
 * ADR's D2 step 6 and D6): `oauth.authorize.acrValues` as it is read
 * (`readAcrTable`), D15's selection of an `acr` over the `amr` a session
 * vouches for (`selectAcr`), what a step-up through the registered
 * requirements can add (`stepUpReach`, the union of every requirement's
 * `reach`), what the composition can produce (`producibleAmr`), and the
 * table less the entries nothing installed can satisfy
 * (`vouchableAcrTable`), which are dropped at boot so no deployment
 * advertises an `acr` it can never meet.
 *
 * `admitSession` (`admit.mts`) is the one caller of `selectAcr` in product
 * code, over the vouched `amr` `requirementSession` builds; the acr table
 * is a core key and its drop is core's, so the `acr_values` step is
 * admission's own, not a requirement's. `SECOND_FACTOR_AMR` — the values a
 * second factor adds (D14) — is what the requirement named `mfa` alone may
 * reach or add (D3).
 */

import {
	EMAIL_OTP_AMR,
	FEDERATED_AMR,
	HARDWARE_KEY_AMR,
	MFA_AMR,
	OTP_AMR,
	PASSWORD_AMR,
	RECOVERY_CODE_AMR,
	SOFTWARE_KEY_AMR,
} from "../grants/authenticationClaims.mjs";

/**
 * What one `acr` requires (D15): any one of these lists, every value of which
 * the session must carry. `"urn:o3co:acr:phr" = [["hwk"], ["swk"]]` is two
 * alternatives; a plain list in the configuration is one. An alternative that
 * requires nothing — which `readAcrTable` never builds, but a table built by
 * hand can hold — is never met: it would vouch for every session.
 */
export type AcrRequirement = readonly (readonly string[])[];

/** `oauth.authorize.acrValues` as it is read: each `acr` and what it requires. */
export type AcrTable = Readonly<Record<string, AcrRequirement>>;

const isNonEmptyStringList = (value: unknown): value is readonly string[] =>
	Array.isArray(value) &&
	value.length > 0 &&
	value.every((entry) => typeof entry === "string" && entry.length > 0);

/**
 * `oauth.authorize.acrValues` as a table: a list of values is one
 * alternative, a list of such lists is several. The schema refuses at boot
 * every other shape, an entry that requires nothing among them; a hand-built
 * configuration that never met the schema has such an entry skipped here, so
 * it cannot vouch for every session. What it reads is copied, and the table
 * has no prototype: the value looked up in it is one an unauthenticated
 * caller writes.
 */
export function readAcrTable(raw: unknown): AcrTable {
	const table: Record<string, AcrRequirement> = Object.create(null);
	if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return table;
	for (const [acr, entry] of Object.entries(raw as Record<string, unknown>)) {
		if (isNonEmptyStringList(entry)) {
			table[acr] = [[...entry]];
		} else if (Array.isArray(entry) && entry.length > 0 && entry.every(isNonEmptyStringList)) {
			table[acr] = entry.map((alternative: readonly string[]) => [...alternative]);
		}
	}
	return table;
}

/** D15's selection of an `acr`: met, reachable by a step-up, or neither. */
export type AcrSelection =
	| { readonly outcome: "met"; readonly acr: string | undefined }
	| { readonly outcome: "step_up"; readonly acrValues: readonly string[] }
	| { readonly outcome: "unmet" };

/**
 * What a step-up through the registered requirements can add to a session
 * (D2 step 6, D3): the union of every requirement's `reach`, in registration
 * order, each value once — nothing with no requirement, and nothing when
 * none reaches anything. A set of its own: nothing done to it reaches a
 * requirement's. D16's "∪ {mfa}" is the requirement's to include: a
 * deployment whose only factor is the email code (O7) cannot reach
 * `urn:o3co:acr:mfa`, and must not be sent to try.
 */
export function stepUpReach(
	requirements: Iterable<{ readonly reach: ReadonlySet<string> }>,
): ReadonlySet<string> {
	const reach = new Set<string>();
	for (const requirement of requirements) {
		for (const value of requirement.reach) reach.add(value);
	}
	return reach;
}

/**
 * D15's selection over the `amr` a session vouches for. Among the requested
 * values, the first one the session meets wins — over stepping up to one
 * listed earlier: an RP that will accept only `phr` asks only for `phr`. An
 * entry is met when one of its alternatives is all held, and is a step-up
 * target when one of its alternatives lacks only what `reach` holds. A value
 * the table does not carry is neither, and neither is an alternative that
 * requires nothing.
 */
export function selectAcr(
	requested: readonly string[],
	amr: readonly string[],
	table: AcrTable,
	reach: ReadonlySet<string>,
): AcrSelection {
	if (requested.length === 0) return { outcome: "met", acr: undefined };
	const held = new Set(amr);
	const entryFor = (acr: string): AcrRequirement | undefined =>
		Object.hasOwn(table, acr) ? table[acr] : undefined;
	for (const acr of requested) {
		if (
			entryFor(acr)?.some(
				(alternative) => alternative.length > 0 && alternative.every((value) => held.has(value)),
			)
		) {
			return { outcome: "met", acr };
		}
	}
	const reachable = requested.filter((acr) =>
		entryFor(acr)?.some(
			(alternative) =>
				alternative.length > 0 && alternative.every((value) => held.has(value) || reach.has(value)),
		),
	);
	return reachable.length > 0 ? { outcome: "step_up", acrValues: reachable } : { outcome: "unmet" };
}

/**
 * The `amr` values D14 assigns to second factors, reserved to the
 * requirement named `mfa` (D3): a requirement of any other name may neither
 * reach nor add one — boot refuses the reach, `resumePrimary` the addition —
 * so a risk score or a re-consent cannot make a session meet
 * `urn:o3co:acr:mfa`. An entry that lacks only these would be met with MFA
 * installed, which decides the drop's boot line (D15).
 */
export const SECOND_FACTOR_AMR: ReadonlySet<string> = new Set([
	OTP_AMR,
	HARDWARE_KEY_AMR,
	SOFTWARE_KEY_AMR,
	EMAIL_OTP_AMR,
	RECOVERY_CODE_AMR,
	MFA_AMR,
]);

/** What something installed can put in a session's `amr` (D15). */
export interface ProducibleAmr {
	/**
	 * A federation whose upstream IdP's `amr` counts is installed: the IdP may
	 * assert any value, recorded beside `fed` (D13), so every entry can be met.
	 */
	readonly anything: boolean;
	/**
	 * Otherwise: `pwd`; `fed` once a federation is installed; and what the
	 * registered requirements reach (`stepUpReach`), `mfa` among it when one
	 * of them reaches it.
	 */
	readonly values: ReadonlySet<string>;
}

/**
 * What the composition can produce (D15).
 *
 * - `reach`: what a step-up through the registered requirements can add —
 *   `stepUpReach` over the resolver — since a requirement's step-up is what
 *   writes a second factor's values into a session.
 * - `federationInstalled`: a federation is installed, so a federation callback
 *   can write `fed`. Without one, nothing records `fed`.
 * - `trustedFederation`: one of them is a federation whose upstream `amr`
 *   counts (`federations.<name>.trustUpstreamAmr`, read by
 *   `federationTrustsUpstreamAmr`, D13). A trusted federation that is not
 *   installed is a `RangeError`.
 */
export function producibleAmr(installed: {
	readonly reach: ReadonlySet<string>;
	readonly federationInstalled: boolean;
	readonly trustedFederation: boolean;
}): ProducibleAmr {
	if (installed.trustedFederation && !installed.federationInstalled) {
		throw new RangeError("producibleAmr: a trusted federation must be an installed one");
	}
	return {
		anything: installed.trustedFederation,
		values: new Set([
			PASSWORD_AMR,
			...(installed.federationInstalled ? [FEDERATED_AMR] : []),
			...installed.reach,
		]),
	};
}

/** An entry `vouchableAcrTable` dropped, and why. */
export interface UnsatisfiableAcrValue {
	readonly acr: string;
	/** The values its alternatives need that nothing installed produces, each once, in the entry's order. */
	readonly unproducible: readonly string[];
	/**
	 * One alternative lacks only values a second factor adds (D14): a
	 * requirement that reaches them would meet it. When no registered
	 * requirement reaches them its boot line is `info`, not `warn` (D6).
	 */
	readonly forWantOfSecondFactor: boolean;
	/**
	 * One of its alternatives requires nothing, and is never met (only a table
	 * built by hand holds one). When no other alternative is left to name
	 * values, this is why `unproducible` is empty.
	 */
	readonly emptyAlternative: boolean;
}

/**
 * The table `/authorize` answers `acr_values` from and discovery advertises
 * (D15): the configured one, less every entry no alternative of which
 * `producible` can meet — an alternative that requires nothing never can. A
 * dropped entry is answered like one never
 * configured — `unmet_authentication_requirements` — and is reported, so the
 * caller can say so once at boot. An entry that stays is kept whole. The
 * table built is new and has no prototype; the configured one is not touched.
 */
export function vouchableAcrTable(
	configured: AcrTable,
	producible: ProducibleAmr,
): { readonly table: AcrTable; readonly dropped: readonly UnsatisfiableAcrValue[] } {
	const table: Record<string, AcrRequirement> = Object.create(null);
	const dropped: UnsatisfiableAcrValue[] = [];
	const missing = (alternative: readonly string[]): readonly string[] =>
		producible.anything ? [] : alternative.filter((value) => !producible.values.has(value));
	for (const [acr, requirement] of Object.entries(configured)) {
		const lacking = requirement.filter((alternative) => alternative.length > 0).map(missing);
		if (lacking.some((values) => values.length === 0)) {
			table[acr] = requirement;
			continue;
		}
		dropped.push({
			acr,
			unproducible: [...new Set(lacking.flat())],
			forWantOfSecondFactor: lacking.some((values) =>
				values.every((value) => SECOND_FACTOR_AMR.has(value)),
			),
			emptyAlternative: requirement.some((alternative) => alternative.length === 0),
		});
	}
	return { table, dropped };
}
