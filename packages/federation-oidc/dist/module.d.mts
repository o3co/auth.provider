import { type Module } from "@o3co/auth-provider-core";
import { type OidcProviderConfig } from "./oidc.mjs";
declare module "@o3co/auth-provider-core" {
    interface ComponentMap {
        readonly oidcFederationConfigs?: Readonly<Record<string, OidcProviderConfig>>;
    }
}
/** The `type` a `federations.<name>` section names to select this provider. */
export declare const OIDC_FEDERATION_TYPE = "oidc";
/**
 * One module per OIDC instance (#524).
 *
 * Unlike the single-tenant Google/GitHub/Apple modules this is a factory:
 * a deployment brokering login to two issuers lists
 * `oidcFederationModule("okta")` and `oidcFederationModule("keycloak")`,
 * and each contributes `federations.<name>` (the provider, built at boot —
 * discovery included, so a failure refuses boot) and
 * `federationRedirectPolicies.<name>` from its entry in
 * `oidcFederationConfigs`. The name is the `:name` route segment and the
 * prefix of the identity handed to the Store (`<name>:<sub>`).
 */
export declare function oidcFederationModule(name: string): Module;
/** Names of every enabled `federations.<name>` section of type `oidc`, sorted. */
export declare function oidcFederationNames(federations: Record<string, unknown> | undefined): string[];
/**
 * The `oidcFederationConfigs` slot from the `federations` config section:
 * every enabled section whose `type` is `oidc`, flat or nested (the shapes
 * `extractFederationSection` accepts), checked field by field so a typo is a
 * boot refusal naming `federations.<name>.<field>` rather than a provider
 * running with one fewer setting than the operator wrote down. The map has
 * no prototype, and every name is checked before it becomes a key: a
 * section the config parser named `__proto__` is refused by name rather
 * than assigned through the prototype setter.
 */
export declare function readOidcFederationConfigs(federations: Record<string, unknown> | undefined): Readonly<Record<string, OidcProviderConfig>>;
//# sourceMappingURL=module.d.mts.map