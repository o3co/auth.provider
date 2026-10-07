/**
 * The attempt counter's client over one ioredis connection: one script per attempt, and the
 * durability report its module's boot check reads. A reply the script does not document is an
 * error, never a count.
 */
import type { Redis } from "ioredis";
import type { AttemptCounterClient } from "../../clients.mjs";
import { type IoredisDurabilityOptions } from "../durability.mjs";
export declare function makeIoredisAttemptCounterClient(io: Redis, options?: IoredisDurabilityOptions): AttemptCounterClient;
//# sourceMappingURL=attempt-counter.d.mts.map