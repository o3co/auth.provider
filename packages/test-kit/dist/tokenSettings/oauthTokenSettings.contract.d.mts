import { type OAuthTokenSettings } from "@o3co/auth-provider-core";
import type { ContractCase } from "../contractCase.mjs";
export interface OAuthTokenSettingsContractInput {
    /** The settings under test, built afresh for each case: a provider's, over the configuration its test chose. */
    readonly build: () => OAuthTokenSettings;
}
/** The cases of the `oauthTokenSettings` contract over the settings `input` builds. */
export declare function oauthTokenSettingsContract(input: OAuthTokenSettingsContractInput): readonly ContractCase[];
//# sourceMappingURL=oauthTokenSettings.contract.d.mts.map