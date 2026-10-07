import { type SessionCookiePolicy } from "@o3co/auth-provider-core";
import type { ContractCase } from "../contractCase.mjs";
export interface SessionCookiePolicyContractInput {
    /** The policy under test, built afresh for each case: a provider's, over the configuration its test chose. */
    readonly build: () => SessionCookiePolicy;
}
/** The cases of the `sessionCookiePolicy` contract over the policy `input` builds. */
export declare function sessionCookiePolicyContract(input: SessionCookiePolicyContractInput): readonly ContractCase[];
//# sourceMappingURL=sessionCookiePolicy.contract.d.mts.map