import { type HttpSettings } from "@o3co/auth-provider-core";
import type { ContractCase } from "../contractCase.mjs";
export interface HttpSettingsContractInput {
    /** The settings under test, built afresh for each case: a provider's, over the configuration its test chose. */
    readonly build: () => HttpSettings;
}
/** The cases of the `httpSettings` contract over the settings `input` builds. */
export declare function httpSettingsContract(input: HttpSettingsContractInput): readonly ContractCase[];
//# sourceMappingURL=httpSettings.contract.d.mts.map