/**
 * The refresh-token family store's client over one ioredis connection. Its `duplicate()` opens
 * a connection of its own that never carries a command across a reconnect, logs that
 * connection's errors by their projection only, and closes it on disposal without ever
 * rejecting.
 */
import { type EventLogger } from "@o3co/auth-provider-core";
import type { Redis } from "ioredis";
import type { RefreshTokenFamilyClient } from "../../clients.mjs";
import { type IoredisDurabilityOptions } from "../durability.mjs";
export declare function makeIoredisRefreshTokenFamilyClient(io: Redis, logger: EventLogger, options?: IoredisDurabilityOptions): RefreshTokenFamilyClient;
//# sourceMappingURL=refresh-token-family.d.mts.map