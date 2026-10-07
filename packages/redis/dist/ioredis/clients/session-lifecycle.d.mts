/**
 * The session lifecycle store's client over one ioredis connection. Every
 * member is one script, so it runs on the primary even where reads are
 * routed to replicas, and its reply is held to its declared answers; a reply
 * of any other shape throws, as a script this client did not run.
 */
import type { Redis } from "ioredis";
import type { SessionLifecycleStoreClient } from "../../clients.mjs";
import { type IoredisDurabilityOptions } from "../durability.mjs";
export declare function makeIoredisSessionLifecycleStoreClient(io: Redis, options?: IoredisDurabilityOptions): SessionLifecycleStoreClient;
//# sourceMappingURL=session-lifecycle.d.mts.map