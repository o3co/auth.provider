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
 * The requirement rule (the MFA ADR's D15, D16): whether a session meets the
 * deployment's baseline (`mfa.mode`) and the `acr_values` a relying party
 * asked for — and when it does not, whether a step-up could. One pure
 * function, so every consumer of an authenticated browser session asks the
 * question the same way; what each does with a step-up (a trip to the MFA
 * page, a `step_up` member, a `403`) is its own.
 *
 * It reads a session only through `sessionAuthentication` and `vouchedAmr`
 * (`../user-sessions/authentication.mts`): a consumer builds its input with
 * `requirementSession(session)`, never by hand, so what the provider vouches
 * for is decided in one place, and it holds `acr_values` to the configured table
 * alone: `acr` is vouched for only as the table defines it — less the entries
 * nothing installed can satisfy, which are dropped at boot
 * (`vouchableAcrTable`), so no deployment advertises an `acr` it can never
 * meet.
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
import type { SessionAuthentication } from "../user-sessions/types.mjs";

/**
 * `mfa.mode` (D19): `required` — every password login has a second factor and
 * every consumer enforces it; `optional` — users with factors are challenged,
 * nobody is forced, step-up works; `off` — no MFA.
 */
export type MfaMode = "off" | "optional" | "required";

/**
 * `mfa.mode` as a consumer reads it, off any config-shaped value: the mode
 * when it is one of the three, else `undefined` — absent, or a value core's
 * schema refuses at boot (a hand-built configuration can still hold one).
 * What `undefined` means is the caller's to decide: until the flip, core's
 * schema and reference default it to `"off"` (D19).
 */
export function readMfaMode(config: unknown): MfaMode | undefined {
	const mode = (config as { mfa?: { mode?: unknown } } | undefined)?.mfa?.mode;
	return mode === "off" || mode === "optional" || mode === "required" ? mode : undefined;
}

/**
 * What one `acr` requires (D15): any one of these lists, every value of which
 * the session must carry. `"urn:o3co:acr:phr" = [["hwk"], ["swk"]]` is two
 * alternatives; a plain list in the configuration is one. An alternative that
 * requires nothing — which `readAcrTable` never builds, but a table built by
 * hand can hold — is never met: it would vouch for every session.
 */
export type AcrRequirement = readonly (readonly string[])[];

/** `oauth.authorize.acrValues` as the rule reads it: each `acr` and what it requires. */
export type AcrTable = Readonly<Record<string, AcrRequirement>>;

/**
 * The primaries the baseline applies after (`mfa.requiredAfter`, fixed to
 * `pwd` for now, D13): a federated login is not asked for a second factor,
 * and an IdP it trusts may have asked for one already.
 */
const BASELINE_PRIMARIES: ReadonlySet<string> = new Set([PASSWORD_AMR]);

/**
 * The primaries the baseline can judge: a password and a federation (D9).
 * Any other — a casing (`"PWD"`), an empty string, a login method a later
 * release adds before the rule learns it — is not one it knows, and is
 * re-authenticated like a primary that cannot be told, never met.
 */
const KNOWN_PRIMARIES: ReadonlySet<string> = new Set([PASSWORD_AMR, FEDERATED_AMR]);

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

/**
 * What the rule reads about a live session (D9). Built by
 * `requirementSession(session)` (`../user-sessions/authentication.mts`) and
 * nowhere else in product code.
 */
export interface MfaRequirementSession {
	/** `sessionAuthentication(session)`: `undefined` when its primary cannot be told. */
	readonly authentication: SessionAuthentication | undefined;
	/** `vouchedAmr(session)`: what the provider vouches for, and all `acr` is matched against. */
	readonly amr: readonly string[];
}

export interface MfaRequirementInput {
	/** The live session, or `null`: no `sid`, or no `UserSessionStore` (D16). */
	readonly session: MfaRequirementSession | null;
	/** The `acr_values` the request asked for, in its order; empty when it asked for none. */
	readonly acrValues: readonly string[];
	readonly mode: MfaMode;
	/** The table `/authorize` answers from — the configured one, less what nothing installed can satisfy. */
	readonly table: AcrTable;
	/** `mfaCoordinator.secondFactorMethods`; `undefined` without a coordinator, when nothing can step a session up. */
	readonly secondFactorMethods: ReadonlySet<string> | undefined;
}

/**
 * What the rule decided (D16, D17).
 *
 * - `met` — the baseline and the request are met; `acr` is the value the
 *   session met, when one was requested.
 * - `reauthenticate` — the baseline cannot be judged on this session:
 *   `session: null`, or a primary that cannot be told. A new login can.
 * - `step_up` — a second factor added to this session could meet what is
 *   missing. `acrValues` are the requested values it could meet, in the
 *   request's order — the MFA page's hint; empty when only the baseline is
 *   missing, which any second factor meets. `requirement` says what a
 *   session that comes back still unmet is refused for: `acr` —
 *   `unmet_authentication_requirements`; `baseline` — `login_required`.
 * - `unmet` — nothing this deployment can do meets it.
 */
export type MfaRequirementDecision =
	| { readonly outcome: "met"; readonly acr: string | undefined }
	| { readonly outcome: "reauthenticate" }
	| {
			readonly outcome: "step_up";
			readonly requirement: "acr" | "baseline";
			readonly acrValues: readonly string[];
	  }
	| { readonly outcome: "unmet"; readonly requirement: "acr" | "baseline" };

/** D15's selection of an `acr`: met, reachable by a step-up, or neither. */
export type AcrSelection =
	| { readonly outcome: "met"; readonly acr: string | undefined }
	| { readonly outcome: "step_up"; readonly acrValues: readonly string[] }
	| { readonly outcome: "unmet" };

const NOTHING: ReadonlySet<string> = new Set();

/**
 * What a step-up can add to a session (D16): the coordinator's
 * `secondFactorMethods` — every value an installed factor adds, `mfa` among
 * them when one of the factors adds it (`MfaFactor.addsMfa`); nothing without
 * a coordinator. D16's "∪ {mfa}" is the coordinator's to include: a
 * deployment whose only factor is the email code (O7) cannot reach
 * `urn:o3co:acr:mfa`, and must not be sent to try.
 */
export function stepUpReach(
	secondFactorMethods: ReadonlySet<string> | undefined,
): ReadonlySet<string> {
	return secondFactorMethods ?? NOTHING;
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
 * The requirement rule (D16): the baseline, then `acr_values`, over one live
 * session. Both must be met: a met `acr` does not meet the baseline.
 *
 * - **Baseline**, under `required` only: met when the primary is one the
 *   baseline does not apply after (a federation), or when a second factor was
 *   verified in the session (`mfaAt`). `session: null`, a primary that cannot
 *   be told and a primary it does not know (anything but `pwd` and `fed`) are
 *   re-authenticated — unless no requested value is in the table at all, which
 *   no login can meet: that is unmet first. A password session without a
 *   second factor steps up — or, with nothing to step up with, is unmet.
 * - **`acr_values`**: D15's selection over `vouchedAmr`. A step-up needs a
 *   live session to add to: with `session: null` nothing is within reach.
 *
 * Once the session can be judged, a request no step-up can meet is unmet
 * whatever the baseline needs; otherwise one step-up is asked for both, since
 * any second factor meets the baseline.
 */
export function decideMfaRequirement(input: MfaRequirementInput): MfaRequirementDecision {
	const { session } = input;
	let baselineMissing = false;
	if (input.mode === "required") {
		const primary = session?.authentication?.primary;
		if (session === null || primary === undefined || !KNOWN_PRIMARIES.has(primary)) {
			const noneConfigured =
				input.acrValues.length > 0 &&
				input.acrValues.every((acr) => !Object.hasOwn(input.table, acr));
			return noneConfigured
				? { outcome: "unmet", requirement: "acr" }
				: { outcome: "reauthenticate" };
		}
		baselineMissing =
			BASELINE_PRIMARIES.has(primary) && session.authentication?.mfaAt === undefined;
	}
	const reach = session === null ? NOTHING : stepUpReach(input.secondFactorMethods);
	const selection = selectAcr(input.acrValues, session?.amr ?? [], input.table, reach);
	if (selection.outcome === "unmet") return { outcome: "unmet", requirement: "acr" };
	if (selection.outcome === "step_up") {
		return { outcome: "step_up", requirement: "acr", acrValues: selection.acrValues };
	}
	if (!baselineMissing) return { outcome: "met", acr: selection.acr };
	return input.secondFactorMethods === undefined
		? { outcome: "unmet", requirement: "baseline" }
		: { outcome: "step_up", requirement: "baseline", acrValues: [] };
}

/**
 * The `amr` values D14 assigns to second factors: an entry that lacks only
 * these would be met with MFA installed. Under `mfa.mode = "off"` dropping it
 * is what the operator chose, and the boot line says so at `info`.
 */
const SECOND_FACTOR_AMR: ReadonlySet<string> = new Set([
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
	 * installed factors add (`stepUpReach`), `mfa` among it when one of them
	 * adds it.
	 */
	readonly values: ReadonlySet<string>;
}

/**
 * What the composition can produce (D15).
 *
 * - `federationInstalled`: a federation is installed, so a federation callback
 *   can write `fed`. Without one, nothing records `fed`.
 * - `trustedFederation`: one of them is a federation whose upstream `amr`
 *   counts — every installed federation, until the build order's step 5 gives
 *   each a `trustUpstreamAmr` switch. A trusted federation that is not
 *   installed is a `RangeError`.
 */
export function producibleAmr(installed: {
	readonly secondFactorMethods: ReadonlySet<string> | undefined;
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
			...stepUpReach(installed.secondFactorMethods),
		]),
	};
}

/** An entry `vouchableAcrTable` dropped, and why. */
export interface UnsatisfiableAcrValue {
	readonly acr: string;
	/** The values its alternatives need that nothing installed produces, each once, in the entry's order. */
	readonly unproducible: readonly string[];
	/**
	 * One alternative lacks only values a second factor adds (D14): MFA
	 * installed would meet it. Under `mfa.mode = "off"` its boot line is
	 * `info`, not `warn` (D15).
	 */
	readonly forWantOfSecondFactor: boolean;
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
		});
	}
	return { table, dropped };
}
