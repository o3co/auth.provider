/**
 * The module that handles every `core.federations` entry of type `github`: it
 * contributes the type, and core dispatches each enabled entry of it here —
 * the provider and its redirect policy built from the entry, under the
 * entry's name.
 */
import { type Module } from "@o3co/auth-provider-core";
/** The `type` a `core.federations.<name>` entry names to select this provider. */
export declare const GITHUB_FEDERATION_TYPE = "github";
export interface GithubFederationTypeModuleOptions {
    /**
     * The fetch every request to GitHub of every `github` entry goes through —
     * the token exchange, `/user` and `/user/emails`: a proxy, or a test seam.
     * Default: the global `fetch`.
     */
    readonly fetch?: typeof fetch;
}
/**
 * Contributes `federationTypes.github`. For each enabled entry of type
 * `github` core parses the entry's own keys with the type's strict, flat
 * schema (`entry.mts`) and calls the two factories with the entry's name, its
 * `callbackURL` and the parsed keys: the provider and its redirect policy.
 * The name is the `:name` route segment and the prefix of the identity handed
 * to the Store (`<name>:<id>`), so two entries are two GitHub clients. It
 * requires no dependency.
 */
export declare function githubFederationTypeModule(options?: GithubFederationTypeModuleOptions): Module;
//# sourceMappingURL=type-module.d.mts.map