/**
 * The acr table `/authorize` answers `acr_values` from and discovery
 * advertises as `acr_values_supported`: the configured
 * `oauth.authorize.acrValues` less every entry nothing this composition
 * installs can satisfy (see ADRs 2026-09-25-multi-factor-authentication and
 * 2026-09-28-session-admission). The router and the discovery contribution
 * compute it from the same inputs, so they cannot disagree; the router alone
 * logs at boot what it dropped.
 */
import { type AcrTable, type FederationSettings, type Logger, type UnsatisfiableAcrValue } from "@o3co/auth-provider-core";
/** The event name of the boot line for each dropped entry. */
export declare const ACR_VALUE_UNSATISFIABLE = "acr_value_unsatisfiable";
/**
 * The table this composition vouches for.
 *
 * - `pwd` can always be produced; `fed` once a federation is installed, since
 *   only a federation callback records it.
 * - `reach`, the union of every registered session requirement's reach
 *   (core's `stepUpReach`), is what a step-up can add: the second-factor
 *   values once the MFA requirement is registered, `mfa` among them when an
 *   enabled factor adds it.
 * - An installed federation whose entry in core's `federationSettings` trusts
 *   its upstream IdP's `amr` (`trustsUpstreamAmr`, true only beside `enabled`)
 *   makes every entry satisfiable: the callback records what that IdP asserts
 *   beside `fed`. One that does not, or that the settings hold no entry for,
 *   adds `fed` alone; its IdP's values meet no `acr`.
 *
 * Runs at composition, after every name-keyed contribution has registered.
 * The federation callback reads the same settings, so the two cannot
 * disagree; boot refuses a switch that is given but unusable when it fills
 * them.
 */
export declare const vouchableAcrValues: (configured: AcrTable, federations: ReadonlyMap<string, unknown> | undefined, federationSettings: FederationSettings, reach: ReadonlySet<string>) => {
    readonly table: AcrTable;
    readonly dropped: readonly UnsatisfiableAcrValue[];
};
/**
 * One line per dropped entry, once, at composition: `warn` (an `acr` this
 * deployment can never meet), except `info` for an entry that lacks only a
 * second factor while no registered requirement reaches one, so an MFA-off
 * deployment keeping the template's MFA entries is not warned at every boot.
 * `mfa.mode` is read nowhere here. The entry is operator text, bounded like
 * any logged text.
 */
export declare const logUnsatisfiableAcrValues: (dropped: readonly UnsatisfiableAcrValue[], reach: ReadonlySet<string>, logger: Logger) => void;
//# sourceMappingURL=acrValues.d.mts.map