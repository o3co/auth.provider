/**
 * The module that handles every `core.federations` entry of type `oidc`: it
 * contributes the type, and core dispatches each enabled entry of it here —
 * the provider and its redirect policy built from the entry, under the
 * entry's name.
 */
import { type Module } from "@o3co/auth-provider-core";
/** The `type` a `core.federations.<name>` entry names to select this provider. */
export declare const OIDC_FEDERATION_TYPE = "oidc";
export interface OidcFederationTypeModuleOptions {
    /**
     * The fetch every upstream request of every `oidc` entry goes through —
     * discovery, the token, UserInfo and JWKS requests: a proxy, or a test
     * seam. Default: the global `fetch`.
     */
    readonly fetch?: typeof fetch;
}
/**
 * Contributes `federationTypes.oidc`. For each enabled entry of type `oidc`
 * core parses the entry's own keys with the type's strict, flat schema
 * (`entry.mts`) and calls the two factories with the entry's name, its
 * `callbackURL` and the parsed keys: the provider (built at boot, discovery
 * included, so a failure refuses boot) and its redirect policy. The name is
 * the `:name` route segment and the prefix of the identity handed to the
 * Store (`<name>:<sub>`). It requires no dependency.
 */
export declare function oidcFederationTypeModule(options?: OidcFederationTypeModuleOptions): Module;
//# sourceMappingURL=type-module.d.mts.map