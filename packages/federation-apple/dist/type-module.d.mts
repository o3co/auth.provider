/**
 * The module that handles every `core.federations` entry of type `apple`: it
 * contributes the type, and core dispatches each enabled entry of it here —
 * the provider and its redirect policy built from the entry, under the
 * entry's name.
 */
import { type Module } from "@o3co/auth-provider-core";
/** The `type` a `core.federations.<name>` entry names to select this provider. */
export declare const APPLE_FEDERATION_TYPE = "apple";
export interface AppleFederationTypeModuleOptions {
    /**
     * The fetch every request to Apple of every `apple` entry goes through —
     * the token and JWKS requests: a proxy, or a test seam. Default: the
     * global `fetch`.
     */
    readonly fetch?: typeof fetch;
}
/**
 * Contributes `federationTypes.apple`. For each enabled entry of type `apple`
 * core parses the entry's own keys with the type's strict, flat schema
 * (`entry.mts`) and calls the two factories with the entry's name, its
 * `callbackURL` and the parsed keys: the provider (its return URL checked at
 * boot) and its redirect policy. The name is the `:name` route segment and
 * the prefix of the identity handed to the Store (`<name>:<sub>`), so two
 * entries are two Services IDs side by side. It requires no dependency.
 */
export declare function appleFederationTypeModule(options?: AppleFederationTypeModuleOptions): Module;
//# sourceMappingURL=type-module.d.mts.map