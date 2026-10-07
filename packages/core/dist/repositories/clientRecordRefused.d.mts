/** The rejection of a lookup whose record a client-record boundary refused. */
export declare class ClientRecordRefusedError extends Error {
    /** The cause, as a code: what a log line's error projection keeps. */
    readonly reason = "client_record_refused";
    constructor();
}
/**
 * Whether `value` is a client-record refusal: an object carrying the brand
 * on itself, whichever constructor built it. Never throws: a value whose
 * read throws is not a refusal.
 */
export declare function isClientRecordRefused(value: unknown): boolean;
//# sourceMappingURL=clientRecordRefused.d.mts.map