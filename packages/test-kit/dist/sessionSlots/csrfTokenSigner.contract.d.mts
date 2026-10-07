import { type CsrfTokenSigner } from "@o3co/auth-provider-core";
import type { ContractCase } from "../contractCase.mjs";
export interface CsrfTokenSignerContractInput {
    /** The signer under test, built afresh for each case. */
    readonly build: () => CsrfTokenSigner;
    /** A signer of the same kind built with another key (another session secret): its signatures must not pass. */
    readonly other: () => CsrfTokenSigner;
    /**
     * The session secret `build` derives its key from, when the provider takes
     * one: the signature must not be an HMAC of the payload under the secret
     * itself, and the secret must not show when the signer is printed. Absent,
     * the separation is not checked.
     */
    readonly sessionSecret?: string;
}
/** The cases of the `csrfTokenSigner` contract over the signers `input` builds. */
export declare function csrfTokenSignerContract(input: CsrfTokenSignerContractInput): readonly ContractCase[];
//# sourceMappingURL=csrfTokenSigner.contract.d.mts.map