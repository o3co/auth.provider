/** Why a send failed, as an operator acts on it. */
export type MailTransportFailure = 
/**
 * No connection the sender may deliver over: the name did not resolve;
 * the connection was refused, reset or closed, or the relay turned it
 * away; or it could not be secured as `secure` requires — STARTTLS
 * refused, the TLS handshake or the relay's certificate refused, or,
 * under `none`, the connected address not loopback.
 */
"unreachable"
/** The relay refused the account's credentials. */
 | "auth_failed"
/**
 * The relay refused the sender, the recipient or the message, or put it
 * off with a reply that is not a limit; or the recipient is one the
 * transport cannot send to as written.
 */
 | "rejected"
/** No connection, greeting or answer within its time, or the whole send not within its own. */
 | "timeout";
/** A relay's reply as the error keeps it: its codes, never its text. */
interface ReplyCodes {
    readonly code: number;
    readonly enhanced: string | undefined;
}
/** What a `MailTransportError` keeps of the failure beside its reason. */
interface FailureDetails {
    readonly reply?: ReplyCodes | undefined;
    readonly code?: string | undefined;
}
/**
 * A send the SMTP sender could not make. `name`, `reason`, `replyCode`,
 * `enhancedCode` and `code` are part of the contract; the message names the
 * stage, the reply's codes and the transport's code, and nothing the relay
 * or the transport wrote.
 */
export declare class MailTransportError extends Error {
    readonly reason: MailTransportFailure;
    /** The relay's reply code (RFC 5321 §4.2), when the failure was a reply. */
    readonly replyCode: number | undefined;
    /** The reply's enhanced status code (RFC 3463), when it carried one. */
    readonly enhancedCode: string | undefined;
    /** The connection's failure, when it is one of `TRANSPORT_CODES` (`ECONNREFUSED`, …). */
    readonly code: string | undefined;
    constructor(what: string, reason: MailTransportFailure, details?: FailureDetails);
}
/**
 * The transport code of `failure`, when it is one of `TRANSPORT_CODES`: its
 * `code`, or the system error its `errno` names (the transport replaces a
 * socket error's `code` with its own).
 */
export declare function transportCodeOf(failure: unknown): string | undefined;
/**
 * `failure`, what the SMTP exchange failed with, as the sender answers it:
 * `refused_at_limit`, or the `MailTransportError` it rejects with. `securing`
 * says the connection was being secured when it failed.
 */
export declare function readSendFailure(failure: unknown, securing?: boolean): "refused_at_limit" | MailTransportError;
export {};
//# sourceMappingURL=failure.d.mts.map