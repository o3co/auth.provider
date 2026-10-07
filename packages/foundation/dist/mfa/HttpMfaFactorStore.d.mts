/**
 * `MfaFactorStore` kept by the Store, over its four MFA factor endpoints
 * (README, "The Store's MFA endpoints"), on the user repository's transport.
 *
 * Guarantees: every answer the contract does not give an operation throws —
 * a list is never answered as fewer records, an update never as written; a
 * list is read whole or refused (a record the provider cannot read, one of
 * another subject, an id twice); an update's answer must be the record named,
 * with the changes sent, at the expected version plus one; what is thrown is
 * built from an allowlist (`storeFailure.mts`, `storeErrors.mts`) and carries
 * nothing the Store sent; the sealed `data` it is handed is sent as it is,
 * and nothing is sent that the wire codec would not read back.
 *
 * A record is created or removed only conditionally: every create and every
 * single-record removal it sends carries `expectedGeneration`, and only the
 * whole set's reset (`removeAllForSubject`) is sent without one.
 *
 * The factor set's members (`listVersioned`, `createIf`, `removeIf`) read
 * every answer through core's codec alone, once: a status the operation does
 * not give is `unexpected_status`, read before any body, and whatever the
 * codec refuses — a `404` or `409` without its outcome body among them — is
 * `malformed_answer`. A conditional write states its deadline on the wire
 * (`deadlineMs`, the request timeout from just before it is sent), at or
 * before the moment the transport gives up, whose timer starts after it: a
 * write past it is never applied after the adapter stopped waiting. A Store
 * that reads it as passed answers `408`, which is `unexpected_status`. A conditional write that is sent and then fails,
 * its deadline included, is unknown: it may have committed.
 *
 * Its write lifetime W is the timeout plus `DEFAULT_CLOCK_SKEW_MS`, and the
 * factor-set writer issues a conditional write up to `MFA_SUBJECT_LEASE_MAX_MS`
 * after its read; a `timeout` that would take the two past
 * `BUNDLED_STORE_WRITE_LIFETIME_MS` is a `RangeError` at construction.
 */
import { type ConditionalCreateAnswer, type ConditionalSetRemoveAnswer, type MfaFactorRecord, type MfaFactorRecordUpdate, type MfaFactorStore, type StoreGeneration, type VersionedSet } from "@o3co/auth-provider-core";
export interface HttpMfaFactorStoreOptions {
    /** The Store's four MFA factor endpoints, each https or loopback http. */
    readonly listUrl: string;
    readonly createUrl: string;
    readonly updateUrl: string;
    readonly deleteUrl: string;
    /** The user repository's credential: sent as `Authorization: Bearer <token>`. */
    readonly bearerToken?: string;
    /** The whole exchange's deadline, in milliseconds: at most 85 500 000 (see the file header). */
    readonly timeout: number;
    /** The most bytes of an answer read. Default `DEFAULT_MAX_RESPONSE_BYTES`. */
    readonly maxResponseBytes?: number;
}
export declare class HttpMfaFactorStore implements MfaFactorStore {
    #private;
    readonly kind = "store";
    constructor({ listUrl, createUrl, updateUrl, deleteUrl, bearerToken, timeout, maxResponseBytes, }: HttpMfaFactorStoreOptions);
    list(subject: string): Promise<readonly MfaFactorRecord[]>;
    listVersioned(subject: string): Promise<VersionedSet<MfaFactorRecord>>;
    createIf(record: MfaFactorRecord, expected: StoreGeneration | null): Promise<ConditionalCreateAnswer>;
    removeIf(subject: string, id: string, expected: StoreGeneration): Promise<ConditionalSetRemoveAnswer>;
    update(subject: string, id: string, expectedVersion: number, next: MfaFactorRecordUpdate): Promise<MfaFactorRecord | null>;
    /** The subject's whole set reset: done on a `2xx` or a `404`. */
    removeAllForSubject(subject: string): Promise<void>;
}
//# sourceMappingURL=HttpMfaFactorStore.d.mts.map