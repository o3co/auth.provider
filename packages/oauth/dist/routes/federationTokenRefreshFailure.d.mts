import type { Response } from "express";
import type { FederationTokenCaller, FederationTokenContext } from "./federationTokenContext.mjs";
import { type StoredRecord } from "./federationTokenRecord.mjs";
/**
 * Stamps the refresh of `current` as answered `500 refresh_failed`, so the
 * router's back-off holds it.
 */
export declare const stampRefreshFailed: (ctx: FederationTokenContext, caller: FederationTokenCaller, current: StoredRecord) => void;
/**
 * The answer when the provider's refresh of `current` threw. On
 * `invalid_grant` under the refresh lock (`holdsLock`), that record is
 * removed, best effort, before the `410`; the session's index is left as it
 * is. A record removed or rewritten since (a logout, a relink, or another
 * refresh) is not this refresh's to end, and is answered as a refresh that
 * could not write is. Without the lock the record is kept: a sibling refresh
 * may have spent the refresh token this one presented, and its rotation is
 * still to land on the record.
 */
export declare const answerRefreshFailure: (ctx: FederationTokenContext, caller: FederationTokenCaller, current: StoredRecord, holdsLock: boolean, error: unknown) => Promise<Response>;
//# sourceMappingURL=federationTokenRefreshFailure.d.mts.map