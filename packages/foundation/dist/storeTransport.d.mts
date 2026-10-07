/**
 * Default ceiling on an upstream response body, in bytes.
 *
 * A `User` record is a few hundred bytes; 1 MiB is generous for one carrying
 * custom claims and small enough that a hostile or broken Store cannot walk the
 * process out of memory one login at a time.
 */
export declare const DEFAULT_MAX_RESPONSE_BYTES: number;
/**
 * The credential presented to the Store, checked when `owner` is built (so
 * an unusable one fails at boot) and turned into the `Authorization` value;
 * `undefined` when none is configured, which sends no `Authorization` header.
 *
 * The shape is refused here, not left to `fetch`, which QUOTES a header value
 * it refuses in the `TypeError` it throws, where the session routes log it.
 * The strength is core's shared-secret floor (`MIN_SECRET_ENTROPY_BYTES`, on
 * the decoded length): whoever holds this token speaks to the Store as
 * auth.provider. No message quotes the value.
 */
export declare function bearerAuthorization(value: unknown, owner: string): string | undefined;
/** `timeout`, the whole exchange's deadline in milliseconds, or an error naming it for `owner`. */
export declare function checkStoreTimeout(timeout: unknown, owner: string): number;
/** `maxResponseBytes`, the response cap, or an error naming it for `owner`. */
export declare function checkStoreResponseCap(maxResponseBytes: unknown, owner: string): number;
/**
 * The transport settings of a Store client's configuration block — the user
 * repository's `http` block — as a client is built from them: `timeout` and
 * `maxResponseBytes` read from text too and defaulted only when absent, and
 * `bearerToken` forwarded whenever set, whatever it holds. The client's
 * constructor refuses what the transport cannot honour.
 */
export declare function readStoreTransportConfig(block: Readonly<Record<string, unknown>>): {
    readonly bearerToken?: string;
    readonly timeout: number;
    readonly maxResponseBytes: number;
};
/**
 * Releases a response body we are not going to read. Left unconsumed, undici
 * holds the socket until the response is garbage collected instead of
 * returning it to the keep-alive pool: a slow leak on the failure path.
 *
 * Deliberately not awaited: that would hand a hostile Store a second way to
 * stall the caller, the one the request deadline exists to close, and some
 * interceptors never settle it at all.
 */
export declare function discardBody(res: Response): void;
/**
 * Reads at most `limit` bytes of `res` as text, throwing once it is passed.
 * `Content-Length` refuses an honest oversized response before a byte is read,
 * but the streaming count is the load-bearing half: a hostile Store omits the
 * header or lies, and chunked encoding has none. Everything it throws is the
 * adapter's own (the cap, the deadline's rejection, what `unreadable` makes of
 * a transport error mid-read), never the transport's error as it is.
 */
export declare function readBodyCapped(res: Response, limit: number, endpoint: string, deadline: Promise<never>, unreadable: (err: unknown) => Error, owner: string): Promise<string>;
/**
 * Whether `err` is the abort our own deadline raised on the `fetch` itself,
 * where the response headers never arrive. Deliberately shallow: an aborted
 * `fetch` rejects with the `AbortError` directly. A runtime that wrapped one
 * would still fail the request, as a `StoreTransportError` rather than a
 * `TimeoutError`: misnamed, not missed. A stalled *body* is the deadline race
 * in `readBodyCapped`.
 */
export declare function isAbortError(err: unknown): boolean;
/** What a request to the Store is sent with. */
export interface StoreRequestSettings {
    /** `Bearer <token>`, or `undefined` to send no `Authorization` header. */
    readonly authorization: string | undefined;
    /** The whole exchange's deadline, in milliseconds. */
    readonly timeout: number;
    /** The most bytes of a body read. */
    readonly maxResponseBytes: number;
}
/** What a failure of the exchange says, each naming the endpoint. */
export interface StoreRequestMessages {
    /** Who is asking, leading every message. */
    readonly owner: string;
    readonly unreachable: string;
    readonly closed: string;
    readonly malformed: string;
    readonly unreadable: string;
}
/** An answer: the response, whose body is released, and the body as text when it was read. */
export interface StoreAnswer {
    readonly response: Response;
    readonly text: string | undefined;
}
/**
 * `POST`s `body` as JSON to `url` and answers what came back, the body read
 * (up to the cap, within the deadline) only when `readsBody` says so for the
 * status, and released otherwise. A `401` or `403` with a `Bearer` challenge
 * to a request that carried the credential throws
 * `StoreCredentialRefusedError`; a deadline passed throws an error named
 * `TimeoutError`; a transport failure throws a `StoreTransportError`.
 */
export declare function postToStore(url: string, body: unknown, settings: StoreRequestSettings, messages: StoreRequestMessages, readsBody: (status: number) => boolean): Promise<StoreAnswer>;
//# sourceMappingURL=storeTransport.d.mts.map