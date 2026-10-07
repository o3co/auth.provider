/**
 * What one `acr` requires: any one of these lists, every value of which the
 * session must carry. `"urn:o3co:acr:phr" = [["hwk"], ["swk"]]` is two
 * alternatives; a plain list in the configuration is one. An alternative that
 * requires nothing (which `readAcrTable` never builds, but a hand-built table
 * can hold) is never met: it would vouch for every session.
 */
export type AcrRequirement = readonly (readonly string[])[];
/** `oauth.authorize.acrValues` as it is read: each `acr` and what it requires. */
export type AcrTable = Readonly<Record<string, AcrRequirement>>;
/**
 * `oauth.authorize.acrValues` as a table: a list of values is one
 * alternative, a list of such lists is several. The schema refuses at boot
 * every other shape, an entry that requires nothing among them; a hand-built
 * configuration that never met the schema has such an entry skipped here, so
 * it cannot vouch for every session. What it reads is copied, and the table
 * has no prototype: the value looked up in it is one an unauthenticated
 * caller writes.
 */
export declare function readAcrTable(raw: unknown): AcrTable;
/** The selection of an `acr`: met, reachable by a step-up, or neither. */
export type AcrSelection = {
    readonly outcome: "met";
    readonly acr: string | undefined;
} | {
    readonly outcome: "step_up";
    readonly acrValues: readonly string[];
} | {
    readonly outcome: "unmet";
};
/**
 * What a step-up through the registered requirements can add to a session:
 * the union of every requirement's `reach`, in registration order, each value
 * once; nothing with no requirement. A set of its own: nothing done to it
 * reaches a requirement's. Including `mfa` is the requirement's job: a
 * deployment whose only factor is the email code cannot reach
 * `urn:o3co:acr:mfa`, and must not be sent to try.
 */
export declare function stepUpReach(requirements: Iterable<{
    readonly reach: ReadonlySet<string>;
}>): ReadonlySet<string>;
/**
 * The selection over the `amr` a session vouches for. Among the requested
 * values, the first one the session meets wins, over stepping up to one
 * listed earlier: an RP that will accept only `phr` asks only for `phr`. An
 * entry is met when one of its alternatives is all held, and is a step-up
 * target when one of its alternatives lacks only what `reach` holds. A value
 * the table does not carry is neither, and neither is an alternative that
 * requires nothing.
 */
export declare function selectAcr(requested: readonly string[], amr: readonly string[], table: AcrTable, reach: ReadonlySet<string>): AcrSelection;
/**
 * The `amr` values second factors add, reserved to the requirement that
 * declares the second-factor authority: no other may reach or add one,
 * whatever its name (boot refuses the reach, `resumePrimary` the addition),
 * so a risk score or a re-consent cannot make a session meet
 * `urn:o3co:acr:mfa`. An entry that lacks only these would be met with MFA
 * installed, which decides the drop's boot line.
 */
export declare const SECOND_FACTOR_AMR: ReadonlySet<string>;
/** What something installed can put in a session's `amr`. */
export interface ProducibleAmr {
    /**
     * A federation whose upstream IdP's `amr` counts is installed: the IdP may
     * assert any value, recorded beside `fed`, so every entry can be met.
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
export declare function producibleAmr(installed: {
    readonly reach: ReadonlySet<string>;
    readonly federationInstalled: boolean;
    readonly trustedFederation: boolean;
}): ProducibleAmr;
/** An entry `vouchableAcrTable` dropped, and why. */
export interface UnsatisfiableAcrValue {
    readonly acr: string;
    /** The values its alternatives need that nothing installed produces, each once, in the entry's order. */
    readonly unproducible: readonly string[];
    /**
     * One alternative lacks only values a second factor adds: a requirement that
     * reaches them would meet it. When no registered requirement reaches them its
     * boot line is `info`, not `warn`.
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
 * The table `/authorize` answers `acr_values` from and discovery advertises:
 * the configured one, less every entry no alternative of which `producible`
 * can meet (an alternative that requires nothing never can). A dropped entry
 * is answered like one never configured, `unmet_authentication_requirements`,
 * and is reported so the caller can say so once at boot. An entry that stays
 * is kept whole. The table built is new and has no prototype; the configured
 * one is not touched.
 */
export declare function vouchableAcrTable(configured: AcrTable, producible: ProducibleAmr): {
    readonly table: AcrTable;
    readonly dropped: readonly UnsatisfiableAcrValue[];
};
//# sourceMappingURL=acr.d.mts.map