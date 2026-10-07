/**
 * The consent stores' clients over one ioredis connection: each indivisible operation one
 * script, and `revoke` one `DEL`.
 */
import type { Redis } from "ioredis";
import type { ConsentStoreClient, PendingConsentStoreClient } from "../../clients.mjs";
export declare function makeIoredisConsentStoreClient(io: Redis): ConsentStoreClient;
export declare function makeIoredisPendingConsentStoreClient(io: Redis): PendingConsentStoreClient;
//# sourceMappingURL=consent.d.mts.map