import type { Response } from "express";
import type { FederationTokenCaller, FederationTokenContext } from "./federationTokenContext.mjs";
import { type StoredRecord } from "./federationTokenRecord.mjs";
/** Step 11. `read` is the record as read before the lock. */
export declare const refreshStoredTokens: (ctx: FederationTokenContext, caller: FederationTokenCaller, read: StoredRecord) => Promise<Response>;
//# sourceMappingURL=federationTokenRefresh.d.mts.map