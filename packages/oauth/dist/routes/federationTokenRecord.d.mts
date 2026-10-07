/**
 * The route's one hold on the stored record: it reads the record with its
 * store generation, writes only at the generation it read, and answers a
 * record that changed under a refresh. A logout, an unlink or a relink that
 * lands while a request is in flight is therefore never undone or
 * overwritten. A token held across the session's liveness read is handed on
 * only once the record is confirmed, after that read, at the generation it
 * was held from (`serveHeld`). No other stage calls the store's conditional
 * members or sees a generation. The route never removes a link from the
 * session's index: a link with no record is answered `404`, and the link ends
 * with the session.
 */
import { type FederationTokens, type Versioned } from "@o3co/auth-provider-core";
import type { Response } from "express";
import type { FederationTokenCaller, FederationTokenContext } from "./federationTokenContext.mjs";
/** The record as one read found it; a write against it lands only if nothing wrote the record since. */
export type StoredRecord = Versioned<FederationTokens>;
/**
 * Reads the record. Returns it, or `null` once answered: `404` when there is
 * none, `503` when the store cannot answer or answers outside its contract.
 */
export declare const readRecord: (ctx: FederationTokenContext, caller: FederationTokenCaller, step: "get" | "get_after_lock" | "get_after_conflict") => Promise<StoredRecord | null>;
/**
 * Confirms the record is still as `read` found it, before a token held from
 * `read` is handed on with no write that confirmed it. Returns `null` when it
 * is; otherwise answers as a dropped refresh is answered, or `503` when the
 * store cannot answer, and returns that response.
 */
export declare const answerIfChanged: (ctx: FederationTokenContext, caller: FederationTokenCaller, read: StoredRecord) => Promise<Response | null>;
/**
 * Hands on what `serve` answers from `held` only if the caller's session was
 * live at its liveness read and the record was still at `held`'s generation
 * at the confirming read that follows it. A close that commits between the
 * two reads is not seen here; the close removes the stored tokens itself. A
 * record gone by the confirming read is answered as removed (`404`), one
 * rewritten as a conflict, each logged once as `federation_token_serve_discarded`.
 */
export declare const serveHeld: (ctx: FederationTokenContext, caller: FederationTokenCaller, held: StoredRecord, serve: () => Promise<Response>) => Promise<Response>;
/**
 * Hands on the stored token of a record that is not due for refresh. A
 * record with no usable access token is removed as it was read, best effort,
 * and answered as none; its usability is judged only here, where a token
 * would be handed on, so a due one is still refreshed from its refresh token.
 */
export declare const serveStored: (ctx: FederationTokenContext, caller: FederationTokenCaller, read: StoredRecord) => Promise<Response>;
/**
 * Replaces the record only while it is still as `read` found it: `updated`
 * with the record as written. Rejects when the store cannot answer or answers
 * outside its contract: the write's fate is then unknown.
 */
export declare const replaceRecord: (ctx: FederationTokenContext, caller: FederationTokenCaller, read: StoredRecord, next: FederationTokens) => Promise<{
    readonly outcome: "updated";
    readonly written: StoredRecord;
} | {
    readonly outcome: "missing" | "conflict";
}>;
/** Removes the record only while it is still as `read` found it. Rejects as `replaceRecord` does. */
export declare const removeRecord: (ctx: FederationTokenContext, caller: FederationTokenCaller, read: StoredRecord) => Promise<"removed" | "missing" | "conflict">;
/**
 * The answer once a refresh's own result is dropped because the record is no
 * longer the one it was made from, logged once as
 * `federation_token_refresh_discarded`, then answered as
 * {@link answerChangedRecord} answers.
 */
export declare const answerDiscardedRefresh: (ctx: FederationTokenContext, caller: FederationTokenCaller, outcome: "missing" | "conflict") => Promise<Response>;
//# sourceMappingURL=federationTokenRecord.d.mts.map