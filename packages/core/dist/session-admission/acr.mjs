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
 * The provider's `acr` vocabulary: reading `oauth.authorize.acrValues`,
 * selecting an `acr` over the `amr` a session vouches for, what a step-up and
 * the composition can produce, and dropping at boot the entries nothing
 * installed can satisfy, so no deployment advertises an `acr` it can never
 * meet.
 *
 * `admitSession` (`admit.mts`) is the one product caller of `selectAcr`: the
 * acr table is a core key, so the `acr_values` step is admission's own, not a
 * requirement's. See the MFA ADR (2026-09-25-multi-factor-authentication,
 * D13–D16) and ADR 2026-09-28-session-admission (D2, D3, D6).
 */
import { EMAIL_OTP_AMR, FEDERATED_AMR, HARDWARE_KEY_AMR, MFA_AMR, OTP_AMR, PASSWORD_AMR, RECOVERY_CODE_AMR, SOFTWARE_KEY_AMR, } from "../grants/authenticationClaims.mjs";
const isNonEmptyStringList = (value) => Array.isArray(value) &&
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
export function readAcrTable(raw) {
    const table = Object.create(null);
    if (typeof raw !== "object" || raw === null || Array.isArray(raw))
        return table;
    for (const [acr, entry] of Object.entries(raw)) {
        if (isNonEmptyStringList(entry)) {
            table[acr] = [[...entry]];
        }
        else if (Array.isArray(entry) && entry.length > 0 && entry.every(isNonEmptyStringList)) {
            table[acr] = entry.map((alternative) => [...alternative]);
        }
    }
    return table;
}
/**
 * What a step-up through the registered requirements can add to a session:
 * the union of every requirement's `reach`, in registration order, each value
 * once; nothing with no requirement. A set of its own: nothing done to it
 * reaches a requirement's. Including `mfa` is the requirement's job: a
 * deployment whose only factor is the email code cannot reach
 * `urn:o3co:acr:mfa`, and must not be sent to try.
 */
export function stepUpReach(requirements) {
    const reach = new Set();
    for (const requirement of requirements) {
        for (const value of requirement.reach)
            reach.add(value);
    }
    return reach;
}
/**
 * The selection over the `amr` a session vouches for. Among the requested
 * values, the first one the session meets wins, over stepping up to one
 * listed earlier: an RP that will accept only `phr` asks only for `phr`. An
 * entry is met when one of its alternatives is all held, and is a step-up
 * target when one of its alternatives lacks only what `reach` holds. A value
 * the table does not carry is neither, and neither is an alternative that
 * requires nothing.
 */
export function selectAcr(requested, amr, table, reach) {
    if (requested.length === 0)
        return { outcome: "met", acr: undefined };
    const held = new Set(amr);
    const entryFor = (acr) => Object.hasOwn(table, acr) ? table[acr] : undefined;
    for (const acr of requested) {
        if (entryFor(acr)?.some((alternative) => alternative.length > 0 && alternative.every((value) => held.has(value)))) {
            return { outcome: "met", acr };
        }
    }
    const reachable = requested.filter((acr) => entryFor(acr)?.some((alternative) => alternative.length > 0 && alternative.every((value) => held.has(value) || reach.has(value))));
    return reachable.length > 0 ? { outcome: "step_up", acrValues: reachable } : { outcome: "unmet" };
}
/**
 * The `amr` values second factors add, reserved to the requirement that
 * declares the second-factor authority: no other may reach or add one,
 * whatever its name (boot refuses the reach, `resumePrimary` the addition),
 * so a risk score or a re-consent cannot make a session meet
 * `urn:o3co:acr:mfa`. An entry that lacks only these would be met with MFA
 * installed, which decides the drop's boot line.
 */
export const SECOND_FACTOR_AMR = new Set([
    OTP_AMR,
    HARDWARE_KEY_AMR,
    SOFTWARE_KEY_AMR,
    EMAIL_OTP_AMR,
    RECOVERY_CODE_AMR,
    MFA_AMR,
]);
/**
 * What the composition can produce.
 *
 * - `reach`: `stepUpReach` over the resolver; a requirement's step-up is what
 *   writes a second factor's values into a session.
 * - `federationInstalled`: a federation callback can write `fed`. Without
 *   one, nothing records `fed`.
 * - `trustedFederation`: an installed federation's upstream `amr` counts
 *   (`core.federations.<name>.trustUpstreamAmr`, read by
 *   `federationTrustsUpstreamAmr`); one not installed is a `RangeError`.
 */
export function producibleAmr(installed) {
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
/**
 * The table `/authorize` answers `acr_values` from and discovery advertises:
 * the configured one, less every entry no alternative of which `producible`
 * can meet (an alternative that requires nothing never can). A dropped entry
 * is answered like one never configured, `unmet_authentication_requirements`,
 * and is reported so the caller can say so once at boot. An entry that stays
 * is kept whole. The table built is new and has no prototype; the configured
 * one is not touched.
 */
export function vouchableAcrTable(configured, producible) {
    const table = Object.create(null);
    const dropped = [];
    const missing = (alternative) => producible.anything ? [] : alternative.filter((value) => !producible.values.has(value));
    for (const [acr, requirement] of Object.entries(configured)) {
        const lacking = requirement.filter((alternative) => alternative.length > 0).map(missing);
        if (lacking.some((values) => values.length === 0)) {
            table[acr] = requirement;
            continue;
        }
        dropped.push({
            acr,
            unproducible: [...new Set(lacking.flat())],
            forWantOfSecondFactor: lacking.some((values) => values.every((value) => SECOND_FACTOR_AMR.has(value))),
            emptyAlternative: requirement.some((alternative) => alternative.length === 0),
        });
    }
    return { table, dropped };
}
