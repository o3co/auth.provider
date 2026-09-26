/**
 * How acquisition's three records are written down and read back (#593, D16,
 * slice 6).
 *
 * **Canonical, field by field.** The text a record encodes to is a function of
 * the record alone: the same intent encodes to the same bytes on every
 * instance and every release, which is what lets the admission script answer
 * `unchanged` for a retried write by comparing the stored text with the
 * incoming one. A spread, or `JSON.stringify` over an object whose key order
 * came from the caller, would make one retry look like a collision.
 *
 * **Nothing here heals a record it cannot read.** A text that does not decode
 * is refused, and the adapter turns that into a thrown error rather than a
 * `null`: reading it as absent would disable a live flow's checks, and
 * deleting it would make a rollback destroy flows a newer release wrote. That
 * is the grant store's treatment of unreadable state, deliberately unlike the
 * pending-consent adapter, which reclaims a corrupt record as it reads it.
 *
 * The values are not secret in the sense the grant credential is — a PKCE
 * verifier and a nonce are worthless once the flow ends, ten minutes at the
 * outside — so they are stored as the login flow's own transaction is: in the
 * clear, in a record with a deadline. What is sealed and why is D16's, and
 * this is the one record it does not seal.
 */
import type { FederationGrantBrowserBinding, FederationGrantConnectTransaction, FederationGrantConsentRecord, FederationGrantIntent } from "@o3co/auth-provider-core";
declare const bindingText: (binding: FederationGrantBrowserBinding) => string;
export { bindingText as federationGrantBindingText };
/** Length-prefixed, for the same reason: the bound is on the pair, not on a concatenation. */
export declare const federationGrantIntentPairText: (clientId: string, subject: string) => string;
export declare function encodeFederationGrantIntent(record: FederationGrantIntent): string;
export declare function decodeFederationGrantIntent(text: string): FederationGrantIntent;
export declare function encodeFederationGrantConsent(record: FederationGrantConsentRecord): string;
export declare function decodeFederationGrantConsent(text: string): FederationGrantConsentRecord;
export declare function encodeFederationGrantTransaction(record: FederationGrantConnectTransaction): string;
export declare function decodeFederationGrantTransaction(text: string): FederationGrantConnectTransaction;
//# sourceMappingURL=federation-grant-intent-codec.d.mts.map