import type { LoginEntry } from "@o3co/auth-provider-core";
import type { ContractCase } from "../contractCase.mjs";
export interface LoginEntryContractInput {
    /** An entry for the login page `url`, as the provider builds one from a configuration naming that page. */
    readonly build: (url: string) => LoginEntry;
}
/** The cases of the `loginEntry` contract over the entries `input` builds. */
export declare function loginEntryContract(input: LoginEntryContractInput): readonly ContractCase[];
//# sourceMappingURL=loginEntry.contract.d.mts.map