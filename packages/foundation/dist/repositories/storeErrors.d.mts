/**
 * The Store refused the credential this deployment presented: a `401` or a
 * `403` carrying a `Bearer` challenge (RFC 6750 §3 — `invalid_token`,
 * `insufficient_scope`) to a request that sent `bearerToken`. An outage, not
 * an answer about the user: thrown, so every caller answers it as it answers
 * any Store failure.
 *
 * `name` is part of the contract. A caller that does not depend on this
 * package recognises the refusal by it — an operator reading the
 * federation-grants callback's `federation_grant_callback_unavailable` line
 * finds it as the projected error's `name`. The message names the endpoint —
 * its origin and path, never a query or fragment, however it is handed one —
 * the status and the option to check; never the token, and nothing the Store
 * wrote.
 *
 * The Store's status is `storeStatus`, never `status` or `statusCode`: those
 * are what Express's finalhandler, http-errors and the standalone's terminal
 * handler read as the status to ANSWER with, and a 4xx there is taken for a
 * client error — the Store's 401 would reach the browser as its own, and go
 * unlogged.
 */
export declare class StoreCredentialRefusedError extends Error {
    readonly storeStatus: 401 | 403;
    constructor(url: string, status: 401 | 403);
}
/** What went wrong with the exchange, when it was not the Store's answer. */
export type StoreTransportFailure = 
/**
 * No connection to exchange on: refused, DNS, TLS, a route or host the
 * network cannot reach. The network path, or TLS to the Store.
 */
"unreachable"
/**
 * A connection that closed — or was reset — before a complete response
 * arrived: before any byte, after an interim `1xx`, mid-head, or a pooled
 * keep-alive connection the Store, a proxy or an idle timeout closed
 * between two requests. The transport cannot tell which, so this says no
 * more than that; it is not the network path, and not a malformed answer.
 */
 | "connection_closed"
/**
 * The Store (or whatever answers at the URL) sent a response head the
 * transport cannot take: the parser refused the status line or a header,
 * or the head outgrew the size limit. The Store's answer, or a proxy's.
 */
 | "malformed_response"
/** An HTTP answer arrived, and its body broke before it was read. */
 | "unreadable";
/**
 * The Store could not be reached, or what it answered could not be read — a
 * transport failure rather than an answer. Thrown so every caller answers it
 * as it answers any Store failure; `name` is part of the contract (the
 * federation-grants callback's outage line carries it as the projected
 * error's `name`), as are `reason` and `code`.
 *
 * Built only from what an operator can act on: a fixed message naming the
 * endpoint and the failure, and `code` — a transport code from the allowlist
 * below, when there is one. Never a `cause`: the transport's own error may
 * quote what was sent or received. And no `status` (see
 * {@link StoreCredentialRefusedError}).
 */
export declare class StoreTransportError extends Error {
    readonly reason: StoreTransportFailure;
    readonly code: string | undefined;
    constructor(message: string, reason: StoreTransportFailure, code?: string);
}
/** The first allowlisted `code` on `err` or its causes. */
export declare function transportCode(err: unknown): string | undefined;
/**
 * A request that failed before a response could be taken, as its reason's
 * message — `unreachable`, `closed` or `malformed` — with the code, when
 * there is one. Only `unreachable` points an operator at the network.
 */
export declare function requestFailure(err: unknown, messages: {
    readonly unreachable: string;
    readonly closed: string;
    readonly malformed: string;
}): StoreTransportError;
/** An answer whose body broke before it was read. */
export declare function readFailure(err: unknown, message: string): StoreTransportError;
//# sourceMappingURL=storeErrors.d.mts.map