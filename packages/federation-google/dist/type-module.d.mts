/**
 * The module that handles every `core.federations` entry of type `google`:
 * it contributes the type, and core dispatches each enabled entry of it here —
 * the provider and its redirect policy built from the entry, under the
 * entry's name.
 */
import { type Module } from "@o3co/auth-provider-core";
/** The `type` a `core.federations.<name>` entry names to select this provider. */
export declare const GOOGLE_FEDERATION_TYPE = "google";
export interface GoogleFederationTypeModuleOptions {
    /**
     * The fetch every request to Google of every `google` entry goes through —
     * the token, UserInfo and JWKS requests: a proxy, or a test seam. Default:
     * the global `fetch`.
     */
    readonly fetch?: typeof fetch;
}
/**
 * Contributes `federationTypes.google`. For each enabled entry of type
 * `google` core parses the entry's own keys with the type's strict, flat
 * schema (`entry.mts`) and calls the two factories with the entry's name, its
 * `callbackURL` and the parsed keys: the provider and its redirect policy.
 * The name is the `:name` route segment and the prefix of the identity handed
 * to the Store (`<name>:<sub>`), so two entries are two Google clients side by
 * side. It requires no dependency.
 *
 * Its module name is `federation-google-type`.
 */
export declare function googleFederationTypeModule(options?: GoogleFederationTypeModuleOptions): Module;
//# sourceMappingURL=type-module.d.mts.map