/**
 * What the federation routes log when a store, the composition or a cleanup
 * step fails: the store and step vocabulary those lines name, and the lines.
 * A line carries the error's projection, never the error.
 */
import { type Logger } from "@o3co/auth-provider-core";
/**
 * The stores the federation routes read or write, as their log lines name
 * them. `cookie_session` is the express-session store behind `req.session`;
 * `federation_transaction` is a `form_post` federation's transaction record,
 * kept in that same store under a key of its own; `session_lifecycle` is
 * core's session lifecycle, which a federation joins a session through.
 */
export type FederationStore = "user_repository" | "user_session" | "federation_token" | "subject_session_index" | "federation_transaction" | "cookie_session" | "session_lifecycle";
/** The operation on a {@link FederationStore} that failed, as a log line names it. */
export type FederationStoreStep = "get" | "set" | "delete" | "save" | "regenerate" | "destroy" | "create" | "authenticate_by_token" | "link" | "attach" | "remove_sid" | "join" | "federations";
/** Which leg of a federation a store outage stopped. */
type FederationOutageEvent = "federation_start_store_unavailable" | "federation_callback_store_unavailable" | "federation_link_store_unavailable";
/**
 * A store a federation route cannot do without could not answer: the
 * server's outage, never a verdict on the user or the IdP. One error line
 * named for the leg, with `store`, `step` and the error's projection — never
 * the error, which can carry a token record. The caller answers `503`.
 */
export declare const logStoreUnavailable: (log: Logger, event: FederationOutageEvent, store: FederationStore, step: FederationStoreStep, cause: unknown, context?: Readonly<Record<string, unknown>>) => void;
/** A composition fault a federation route can meet, as its log line names it. */
type FederationMisconfiguration = "no_callback_url" | "no_redirect_policy" | "no_session_store";
/**
 * A federation route met a composition fault — a provider with no callback URL
 * or no redirect policy, or a `form_post` federation with no express-session
 * store on its requests. No client causes it and no retry fixes it: one line at error level,
 * `federation_misconfigured`, with the `reason`; the caller answers `500`.
 */
export declare const logMisconfigured: (log: Logger, reason: FederationMisconfiguration, context?: Readonly<Record<string, unknown>>) => void;
/**
 * The warn line a best-effort step that failed is logged as,
 * `federation_cleanup_failed`: `store`, `step` and the error's projection.
 * {@link cleanUp} emits it for a step that throws; the caller of a step that
 * returns its error (the callback's discard of a refused transaction) calls
 * it directly; the login tail's reporter emits it for the steps
 * `establishSession` runs.
 */
export declare const logCleanupFailed: (log: Logger, store: FederationStore, step: FederationStoreStep, cause: unknown, context?: Readonly<Record<string, unknown>>) => void;
/**
 * Run one best-effort cleanup step that throws when it fails, such as a
 * rollback after a failed link. A step that fails is one
 * {@link logCleanupFailed} line; the request's own answer stands either way.
 */
export declare const cleanUp: (log: Logger, store: FederationStore, step: FederationStoreStep, run: () => Promise<unknown>, context?: Readonly<Record<string, unknown>>) => Promise<void>;
export {};
//# sourceMappingURL=FederationLog.d.mts.map