import { type WebAuthnCredentialStore } from "@o3co/auth-provider-core";
import type { ContractCase } from "../contractCase.mjs";
/** What one case runs over: a fresh, empty store. */
export interface WebAuthnCredentialStoreHarness {
    /** The store under test, holding nothing. */
    readonly store: WebAuthnCredentialStore;
    /** Releases what the store runs on once the case ends. */
    readonly close?: () => Promise<void>;
}
export interface WebAuthnCredentialStoreContractInput {
    /** Builds a fresh harness for each case. */
    readonly build: () => Promise<WebAuthnCredentialStoreHarness>;
}
/** The cases of the WebAuthn credential store's contract over the harnesses `input` builds. */
export declare function webAuthnCredentialStoreContract(input: WebAuthnCredentialStoreContractInput): readonly ContractCase[];
//# sourceMappingURL=credentialStore.contract.d.mts.map