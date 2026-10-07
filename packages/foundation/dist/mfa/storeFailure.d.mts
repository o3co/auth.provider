import type { StoreRequestMessages } from "../storeTransport.mjs";
/** The Store's MFA endpoints, by what the provider asks of each. */
export type MfaStoreOperation = "list" | "create" | "update" | "delete" | "markMfaEnrolled";
/** Why an answer is not one the contract gives the operation. */
export type MfaStoreFailure = 
/** A status the contract does not give the operation. */
"unexpected_status"
/** `markMfaEnrolled` answered `404`: the Store holds no such subject. */
 | "unknown_subject"
/** A `2xx` whose body is not the contract's. */
 | "malformed_answer"
/** A list holding a record the provider cannot read: the list is refused, never read as none. */
 | "unreadable_record"
/** An update answered a version other than the expected one plus one. */
 | "version_skipped";
/** An MFA endpoint answered outside the contract. `name`, `reason`, `operation` and `storeStatus` are part of the contract. */
export declare class MfaStoreError extends Error {
    readonly reason: MfaStoreFailure;
    readonly operation: MfaStoreOperation;
    /** The Store's status, for a status the contract does not give the operation. */
    readonly storeStatus: number | undefined;
    constructor(message: string, reason: MfaStoreFailure, operation: MfaStoreOperation, storeStatus?: number);
}
/**
 * What a transport failure of `operation` at `url` says, for the client
 * `owner` that sends it: one wording for every client of these endpoints,
 * naming the endpoint by origin and path.
 */
export declare function mfaStoreRequestMessages(owner: string, operation: MfaStoreOperation, url: string): StoreRequestMessages;
/**
 * `response`'s status as an error, when the contract does not give it to
 * `operation`: `unknown_subject` for `markMfaEnrolled`'s `404`,
 * `unexpected_status` for any other. Reads the status alone and releases the
 * body without awaiting it, which a Store could otherwise hold open.
 */
export declare function mfaStoreStatusError(operation: MfaStoreOperation, url: string, response: Response): MfaStoreError;
/** A `2xx` from `operation` whose body is not the contract's. */
export declare function mfaStoreMalformedAnswer(operation: MfaStoreOperation, url: string): MfaStoreError;
/** A list holding a record the provider cannot read. */
export declare function mfaStoreUnreadableRecord(url: string): MfaStoreError;
/**
 * An update of `(subject, id)` at `expectedVersion` answered another version
 * than `expectedVersion + 1`. The subject and the factor id lead the
 * message, so a log line that cuts it (`loggableError`, 256 characters) still
 * names both.
 */
export declare function mfaStoreVersionSkipped(url: string, update: {
    readonly subject: string;
    readonly id: string;
    readonly expectedVersion: number;
}): MfaStoreError;
//# sourceMappingURL=storeFailure.d.mts.map