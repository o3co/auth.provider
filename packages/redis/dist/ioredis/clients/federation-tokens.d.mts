/**
 * The federation token store's client over one ioredis connection. The index's add and its
 * expiry are one MULTI/EXEC whose reply is checked, the lock is released only by the
 * compare-and-delete script, and the attach and each conditional member are one script whose
 * reply is held to its declared answers.
 */
import type { Redis } from "ioredis";
import type { FederationTokenStoreClient } from "../../clients.mjs";
import { type IoredisDurabilityOptions } from "../durability.mjs";
export declare function makeIoredisFederationTokenStoreClient(io: Redis, options?: IoredisDurabilityOptions): FederationTokenStoreClient;
//# sourceMappingURL=federation-tokens.d.mts.map