import type { SessionRPRegistry } from "../types.mjs";
/**
 * In-memory SessionRPRegistry. Wraps `createMemorySidHash<RegisteredRP>` keyed
 * by `clientId`. Provides idempotent upsert (replaces earlier registration when
 * back-channel logout URIs change between flows), expiry no-op on past
 * `expiresAt`, and defensive RP-clone on register and list.
 *
 * Per A4 §5.2 + §7.1 + §13.1.
 */
export declare function createInMemorySessionRPRegistry(): SessionRPRegistry;
//# sourceMappingURL=sessionRPRegistry.d.mts.map