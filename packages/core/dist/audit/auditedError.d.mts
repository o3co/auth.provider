/**
 * An error as an audit event's `details.cause` carries it: the name and the
 * code `loggableError` reads, each sanitised and capped as
 * {@link auditErrorText} does, one level of its cause the same way, and never
 * a message.
 *
 * Every field keeps one type in every event — a numeric code is written as a
 * string — because a sink that fixes a field's type the first time it sees it
 * (Elasticsearch dynamic mapping, a BigQuery schema, a Datadog facet) drops
 * the events that disagree.
 */
export interface AuditedError {
    /** The error's `name`; `"NonError"` for a thrown value that is not an Error. */
    readonly name: string;
    /** A library's or a store's code, e.g. `ECONNREFUSED` or `OAUTH_RESPONSE_BODY_ERROR`. */
    readonly code?: string;
    /**
     * The error's own cause, one level: undici's `fetch failed` is a
     * `TypeError` whose cause holds the `ECONNREFUSED`.
     */
    readonly cause?: AuditedErrorCause;
}
/** An {@link AuditedError}'s cause: the name and code, and no further cause. */
export interface AuditedErrorCause {
    readonly name: string;
    readonly code?: string;
}
/**
 * The {@link AuditedError} of `err`, for an audit event's `details.cause`:
 * what kind of error it was and what caused it, bounded, and nothing a peer
 * wrote into either.
 */
export declare function auditedError(err: unknown): AuditedError;
//# sourceMappingURL=auditedError.d.mts.map