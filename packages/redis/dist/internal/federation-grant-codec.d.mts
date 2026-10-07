import type { FederationGrantAuthorization, FederationGrantCredentials } from "@o3co/auth-provider-core";
/**
 * The text stored under the HASH's `authorization` field, and the last
 * element of {@link credentialAad}.
 */
export declare function canonicalAuthorization(authorization: FederationGrantAuthorization): string;
/**
 * Inverse of {@link canonicalAuthorization}. `undefined` for anything that is
 * not that shape: a HASH whose authorization cannot be read is a record that
 * answers nothing, and guessing at a field would authenticate a credential
 * against something the upstream never granted.
 */
export declare function parseCanonicalAuthorization(text: string): FederationGrantAuthorization | undefined;
export interface FederationGrantCredentialBinding {
    /** The complete Redis key the ciphertext is stored under. */
    readonly credentialKey: string;
    readonly id: string;
    readonly subject: string;
    readonly clientId: string;
    readonly connection: string;
    /** Exactly the bytes the HASH holds — never re-serialized from a parsed record. */
    readonly authorization: string;
}
/**
 * The authenticated data a credential is sealed under: the key it lives at,
 * the record's identity, and every field of the authorization (D1).
 *
 * The key name is in there because the session-bound store binds a ciphertext
 * to its key (#293) and a credential copied to another grant's key must not
 * read as that grant's. The authorization is in there because here the binding
 * is a plaintext HASH: someone able to write to Redis, or a mismatched
 * restore, could re-point `clientId`, extend `expiresAt`, move `consent.at`
 * past a revocation watermark, or rewrite `authorizationRevision` to skip a
 * renewed consent — without touching the ciphertext. A tampered field then
 * fails authentication and the record reads as unreadable.
 *
 * The usage fields are deliberately outside it: `lastUsedAt`, the
 * ineligibility marker and the stamp of a failed refresh change while the
 * grant is in use, and none of them decides what the grant allows.
 */
export declare function credentialAad(binding: FederationGrantCredentialBinding): Buffer;
/** The plaintext inside the envelope. An array, for the reasons {@link canonicalAuthorization} is one. */
export declare function encodeCredentials(credentials: FederationGrantCredentials): string;
/** Inverse of {@link encodeCredentials}; `undefined` for anything else, which reads as an unreadable credential. */
export declare function decodeCredentials(text: string): FederationGrantCredentials | undefined;
//# sourceMappingURL=federation-grant-codec.d.mts.map