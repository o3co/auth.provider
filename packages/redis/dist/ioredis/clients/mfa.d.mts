/**
 * The MFA stores' clients over one ioredis connection each, with the durability report both
 * give the boot check. A reservation reply the script does not document throws: an outage,
 * never a verdict.
 */
import type { Redis } from "ioredis";
import type { MfaFactorStoreClient, MfaTransactionStoreClient } from "../../clients.mjs";
import { type IoredisDurabilityOptions } from "../durability.mjs";
/**
 * The `MfaFactorStore`'s client over one ioredis connection. Also part of
 * {@link makeIoredisClients}; exported alone so a deployment can keep enrolled factors on a
 * dedicated database or instance, as the MFA ADR's durability requirements prefer.
 */
export declare function makeIoredisMfaFactorStoreClient(io: Redis, options?: IoredisDurabilityOptions): MfaFactorStoreClient;
/**
 * The `MfaTransactionStore`'s client over one ioredis connection. Also part of
 * {@link makeIoredisClients}; exported alone so a deployment can give it a dedicated database
 * or instance.
 */
export declare function makeIoredisMfaTransactionStoreClient(io: Redis, options?: IoredisDurabilityOptions): MfaTransactionStoreClient;
//# sourceMappingURL=mfa.d.mts.map