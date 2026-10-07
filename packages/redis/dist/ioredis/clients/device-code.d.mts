/**
 * The device authorization store's client over one ioredis connection: each operation one
 * script. A reply the create script does not document is an error, never a collision.
 */
import type { Redis } from "ioredis";
import type { DeviceCodeStoreClient } from "../../clients.mjs";
export declare function makeIoredisDeviceCodeStoreClient(io: Redis): DeviceCodeStoreClient;
//# sourceMappingURL=device-code.d.mts.map