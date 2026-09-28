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
 * (`../user-sessions/authentication.mts`), so what the provider vouches for
 * is decided in one place, and it holds `acr_values` to the configured table
 * alone: `acr` is vouched for only as the table defines it.
 */

import { MFA_AMR, PASSWORD_AMR } from "../grants/authenticationClaims.mjs";
import type { SessionAuthentication } from "../user-sessions/types.mjs";

/**
 * `mfa.mode` (D19): `required` — every password login has a second factor and
 * every consumer enforces it; `optional` — users with factors are challenged,
 * nobody is forced, step-up works; `off` — no MFA.
 */
export type MfaMode = "off" | "optional" | "required";

/**
 * What one `acr` requires (D15): any one of these lists, every value of which
 * the session must carry. `"urn:o3co:acr:phr" = [["hwk"], ["swk"]]` is two
 * alternatives; a plain list in the configuration is one.
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

/** What the rule reads about a live session (D9). */
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
 * What a step-up can add to a session (D16): the values the installed
 * factors add, and `mfa`; nothing without a coordinator.
 */
export function stepUpReach(
	secondFactorMethods: ReadonlySet<string> | undefined,
): ReadonlySet<string> {
	if (secondFactorMethods === undefined) return NOTHING;
	return new Set([...secondFactorMethods, MFA_AMR]);
}

/**
 * D15's selection over the `amr` a session vouches for. Among the requested
 * values, the first one the session meets wins — over stepping up to one
 * listed earlier: an RP that will accept only `phr` asks only for `phr`. An
 * entry is met when one of its alternatives is all held, and is a step-up
 * target when one of its alternatives lacks only what `reach` holds. A value
 * the table does not carry is neither.
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
		if (entryFor(acr)?.some((alternative) => alternative.every((value) => held.has(value)))) {
			return { outcome: "met", acr };
		}
	}
	const reachable = requested.filter((acr) =>
		entryFor(acr)?.some((alternative) =>
			alternative.every((value) => held.has(value) || reach.has(value)),
		),
	);
	return reachable.length > 0 ? { outcome: "step_up", acrValues: reachable } : { outcome: "unmet" };
}

/**
 * The requirement rule (D16): the baseline, then `acr_values`, over one live
 * session.
 *
 * - **Baseline**, under `required` only: met when the primary is not one the
 *   baseline applies after (a federation), or when a second factor was
 *   verified in the session (`mfaAt`). `session: null` and a primary that
 *   cannot be told are re-authenticated. A password session without one steps
 *   up — or, with nothing to step up with, is unmet.
 * - **`acr_values`**: D15's selection over `vouchedAmr`. A step-up needs a
 *   live session to add to: with `session: null` nothing is within reach.
 *
 * Both must be met. A request nothing can meet is unmet whatever the baseline
 * needs; otherwise one step-up is asked for both, since any second factor
 * meets the baseline.
 */
export function decideMfaRequirement(input: MfaRequirementInput): MfaRequirementDecision {
	const { session } = input;
	let baselineMissing = false;
	if (input.mode === "required") {
		if (session === null || session.authentication === undefined) {
			return { outcome: "reauthenticate" };
		}
		const { primary, mfaAt } = session.authentication;
		baselineMissing = BASELINE_PRIMARIES.has(primary) && mfaAt === undefined;
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
