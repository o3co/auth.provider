import type { Response } from "express";
import type { FederationTokenCaller, FederationTokenContext } from "./federationTokenContext.mjs";
import { type StoredRecord } from "./federationTokenRecord.mjs";
import { type RefreshReading } from "./federationTokenRefreshAnswer.mjs";
/**
 * The refusals of an answer, then steps 11f and 11h. `current` is the record
 * the refresh was made from.
 */
export declare const recordRefresh: (ctx: FederationTokenContext, caller: FederationTokenCaller, current: StoredRecord, reading: RefreshReading) => Promise<Response>;
//# sourceMappingURL=federationTokenRefreshRecord.d.mts.map