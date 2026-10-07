/**
 * The session stores' clients over one ioredis connection. Every MULTI/EXEC reply is checked
 * for a queued failure, and every script runs through `runScript`, EVALSHA-first.
 */
import type { Redis } from "ioredis";
import type { SubjectRevocationClient, SubjectSessionIndexClient, UserSessionStoreClient } from "../../clients.mjs";
import { type IoredisDurabilityOptions } from "../durability.mjs";
export declare function makeIoredisUserSessionStoreClient(io: Redis): UserSessionStoreClient;
export declare function makeIoredisSubjectSessionIndexClient(io: Redis): SubjectSessionIndexClient;
export declare function makeIoredisSubjectRevocationClient(io: Redis, options?: IoredisDurabilityOptions): SubjectRevocationClient;
//# sourceMappingURL=user-sessions.d.mts.map