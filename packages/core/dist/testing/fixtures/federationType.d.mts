import type { FederationProvider } from "../../federations/types.mjs";
import { type FederationInstance, type FederationRedirectPolicyContribution, type Module } from "../../modules/manifest/index.mjs";
/** One entry of the type as the fixture's callbacks receive it. */
type FederationInstanceForTests = FederationInstance<Readonly<Record<string, unknown>>>;
export interface FederationTypeForTestsOptions {
    /** The provider for one entry; its `name` must be the entry's. */
    readonly provider?: (instance: FederationInstanceForTests) => FederationProvider;
    /**
     * The redirect policy for one entry. Its type is what the
     * `federationRedirectPolicies` kind takes where the package that declares
     * that kind is in the program, and `unknown` where it is not.
     */
    readonly redirectPolicy?: (instance: FederationInstanceForTests) => FederationRedirectPolicyContribution;
}
/**
 * A module named `test-federation-type-<type>` that registers `type` under
 * `federationTypes`, with an entry schema that accepts any entry. For each
 * enabled `core.federations` entry naming `type`, boot registers the provider
 * `options.provider` answers and the redirect policy `options.redirectPolicy`
 * answers under the entry's name. By default the provider is named after the
 * entry, with scope `openid`, an authorization URL on
 * `https://<name>.idp.test` and a code exchange that answers one fixed
 * subject; the policy accepts every redirect and resolves the callback to `/`.
 * `type` is one kebab-case word.
 */
export declare function federationTypeForTests(type: string, options?: FederationTypeForTestsOptions): Module;
export {};
//# sourceMappingURL=federationType.d.mts.map