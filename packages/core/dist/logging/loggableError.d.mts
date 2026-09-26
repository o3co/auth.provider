/**
 * The fields of an error a log line carries, and its Error causes the same
 * way: a plain object, with no `message`, so that no serializer takes it for
 * an Error and rewrites it — the line carries exactly these fields.
 */
export interface LoggableError {
    /** The error's `name`; `"NonError"` for a thrown value that is not an Error. */
    readonly name: string;
    /**
     * The error's message, on one line (see {@link lineSafeText}). Absent for a
     * SyntaxError or a YAMLException, which quote their input; a Redis reply's
     * echoed arguments are cut. Not `message`, which would make a serializer
     * take the projection for an Error.
     */
    readonly detail?: string;
    /** A SyntaxError's `position N`, read out of its message. */
    readonly position?: number;
    /** A library's error code, e.g. openid-client's `OAUTH_INVALID_RESPONSE`. */
    readonly code?: string | number;
    /** The HTTP status the error records, e.g. an OAuth refusal's or body-parser's. */
    readonly status?: number;
    /** A string `type`, e.g. body-parser's `entity.too.large`. */
    readonly type?: string;
    /** The upstream's OAuth `error` code (RFC 6749 §5.2), e.g. `invalid_grant`. */
    readonly error?: string;
    /**
     * The upstream's `error_description`: its first line, when that line is
     * within RFC 6749 §5.2's character set, cut at the start of the word that
     * holds its first run of twenty token characters, and trimmed. The one
     * peer-written string kept on purpose.
     */
    readonly error_description?: string;
    /** A Response the library put on the error — its cause, or its own `response`. */
    readonly response?: {
        readonly status: number;
        readonly contentType?: string;
    };
    /**
     * The stack's frames and nothing of its header: at most
     * {@link LOGGED_STACK_MAX_FRAMES} `    at …` lines, joined by `\n` and cut
     * at {@link LOGGED_STACK_MAX_LENGTH} characters. Absent when there are
     * none, when `stack` cannot be read, or when it does not start with the
     * header V8 writes for the error's name, code and message.
     */
    readonly stack?: string;
    readonly cause?: LoggableError;
    /**
     * `true` when the error has an Error cause the projection left out: past
     * the depth limit, or past {@link LOGGED_MAX_PROJECTIONS}.
     */
    readonly causeOmitted?: true;
    /**
     * An own `reason` that is a code — lowercase words joined by `_` or `-`,
     * at most 64 characters — e.g. a Store transport failure's `unreachable`.
     */
    readonly reason?: string;
    /**
     * The command a store's error answered, by name alone — ioredis's
     * `command.name` (`set`, `evalsha`, `hello`) when it is a bounded token —
     * never its `args`.
     */
    readonly command?: {
        readonly name: string;
    };
    /**
     * An AggregateError's members: of its first
     * {@link LOGGED_AGGREGATE_MAX_ERRORS}, the Errors, projected the same way.
     */
    readonly aggregateErrors?: readonly LoggableError[];
    /**
     * How many of the members are not in `aggregateErrors`: past the first
     * five, not an Error, past the depth limit, or left out by
     * {@link LOGGED_MAX_PROJECTIONS}.
     */
    readonly aggregateErrorsOmitted?: number;
    /** For a thrown value that is not an Error: its `typeof`, and nothing of its content. */
    readonly thrown?: string;
    /**
     * An own `<word>Status` field holding an HTTP status (100–599), at most
     * four: an upstream's answer an error records beside its own `status`,
     * e.g. a Store refusal's `storeStatus`.
     */
    readonly [statusField: `${string}Status`]: number | undefined;
}
/** The longest string any field keeps. */
export declare const LOGGED_STRING_MAX_LENGTH = 256;
/** The most AggregateError members the projection looks at, at each level. */
export declare const LOGGED_AGGREGATE_MAX_ERRORS = 5;
/**
 * How many levels deep `util.inspect` prints a projection: past the deepest
 * it nests — three levels of causes or AggregateError members (a member is
 * two, the array and its element) and a `response` or `command` in the last.
 */
export declare const LOGGED_PRINT_DEPTH = 8;
/**
 * The most projections one line holds: the error, its causes and its
 * members, all levels together. Each is capped — every string at 256
 * characters, the stack at 2048 — so a line stays under about 64 KB.
 */
export declare const LOGGED_MAX_PROJECTIONS = 16;
/**
 * Whether `value` is a `reason` a log line may carry: a code — lowercase
 * words joined by `_` or `-`, at most 64 characters. The projection's own
 * rule, for a line that reads a `reason` off something other than an error.
 */
export declare const isLoggableReason: (value: unknown) => value is string;
/**
 * Text a peer wrote, as a log line carries it: on one line — every character
 * that breaks a line or reorders it on screen (C0, DEL, C1, U+2028/U+2029,
 * the directional marks, the bidi embedding, override and isolate controls)
 * replaced by `?` — and cut at `maxLength` characters (256 by default), the
 * cut marked with `...` and never falling inside a surrogate pair. A
 * `maxLength` that is not an integer of at least 4 — room for one character
 * and the mark — is a RangeError.
 * The filter `loggableError` applies to a message, for a package that logs
 * peer text that is not an error's: a certificate's subject, a URL a
 * certificate names, a responder's Content-Type. Not RFC 6749's set
 * (`auditErrorText`): a non-ASCII name, `"` and `\` stay legible. A value
 * that is not a string answers `undefined`.
 */
export declare function lineSafeText(text: string, maxLength?: number): string;
export declare function lineSafeText(text: unknown, maxLength?: number): string | undefined;
/** The most stack frames the projection keeps. */
export declare const LOGGED_STACK_MAX_FRAMES = 10;
/** The longest `stack` the projection keeps, frames joined; the cut may fall mid-frame. */
export declare const LOGGED_STACK_MAX_LENGTH = 2048;
/**
 * `target[key]`, read so that the read cannot throw: `{ value }`, or `null`
 * when it threw — a getter, a Proxy's trap. The projection is handed
 * whatever was thrown, and must not throw while asking about it.
 */
export declare const guardedRead: (target: object, key: string) => {
    readonly value: unknown;
} | null;
/**
 * The text `detail` is cut from: `err`'s message by the projection's rules —
 * nothing for a SyntaxError or a YAMLException, a message that is not a
 * string or a value that is not an Error; a Redis reply's echoed arguments
 * cut; on one line ({@link lineSafeText}'s filter) — without the
 * 256-character cap. For a message read once and whole rather than a log
 * field: a boot failure's, whose advice often runs past 256 characters
 * (`boot/failure-summary.mts`).
 */
export declare function uncappedDetail(err: unknown): string | undefined;
/**
 * Project an error onto the fields a log line may carry — the rules are the
 * file header's.
 *
 * A logger that prints the whole error writes what its peer said to the
 * log. Before this projection both shipped paths did so for a store error:
 * pino's err serializer copies every enumerable property of an error —
 * ioredis's `command.args` included — and `consoleLogger` hands the error to
 * `console.*`, whose inspection prints them. A deployment chooses its logger,
 * so a call site that logs a library's or a store's error hands the logger
 * this instead of the error, and every logger writes it as it is. It never
 * throws.
 */
export declare function loggableError(err: unknown): LoggableError;
//# sourceMappingURL=loggableError.d.mts.map