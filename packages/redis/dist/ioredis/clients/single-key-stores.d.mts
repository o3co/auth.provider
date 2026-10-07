/**
 * The single-key stores' clients over one ioredis connection: each operation one command on
 * one key.
 */
import type { Redis } from "ioredis";
import type { AccessTokenDenylistClient, ChallengeStoreClient, CodeRepositoryClient, ReplaySeenSetClient } from "../../clients.mjs";
import { type IoredisDurabilityOptions } from "../durability.mjs";
export declare function makeIoredisChallengeStoreClient(io: Redis): ChallengeStoreClient;
export declare function makeIoredisAccessTokenDenylistClient(io: Redis, options?: IoredisDurabilityOptions): AccessTokenDenylistClient;
export declare function makeIoredisReplaySeenSetClient(io: Redis, options?: IoredisDurabilityOptions): ReplaySeenSetClient;
export declare function makeIoredisCodeRepositoryClient(io: Redis): CodeRepositoryClient;
//# sourceMappingURL=single-key-stores.d.mts.map