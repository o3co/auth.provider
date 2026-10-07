import type { FederationGrantPolicy } from "@o3co/auth-provider-core";
import type { ContractCase } from "../contractCase.mjs";
export interface FederationGrantPolicyContractInput {
    /** The policy under test, built afresh for each case: a provider's, over the configuration its test chose. */
    readonly build: () => FederationGrantPolicy;
}
/** The cases of the `federationGrantPolicy` contract over the policy `input` builds. */
export declare function federationGrantPolicyContract(input: FederationGrantPolicyContractInput): readonly ContractCase[];
//# sourceMappingURL=federationGrantPolicy.contract.d.mts.map