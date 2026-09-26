import { z } from "zod";
import type { DPoPReplayStore } from "./replay-store.mjs";
/**
 * Optional ComponentMap slot for the DPoP replay store. When absent,
 * `dpopModule` falls back to the in-memory adapter (dev/test only). Production
 * deployments wire the Redis-backed implementation via:
 *
 * ```ts
 * import { createRedisDPoPReplayStore } from "@o3co/auth-provider-redis/dpop";
 * // ... in your composition module's `provides`:
 * dpopReplayStore: (deps) => createRedisDPoPReplayStore(deps.redisClient)
 * ```
 *
 * Pattern mirrors `webauthnCredentialStore` in core + `accessTokenDenylist`.
 * Per Wave 2 Phase 2 spec §11.2.
 */
declare module "@o3co/auth-provider-core" {
    interface ComponentMap {
        /** Optional DPoP replay store. Defaults to in-memory when absent. */
        readonly dpopReplayStore?: DPoPReplayStore;
    }
}
/**
 * Zod schema for the `oauth.dpop` config slice.
 *
 * Keys use kebab-case to match the HOCON reference.conf keys exactly.
 * HOCON preserves key names verbatim; TypeScript accesses them via
 * bracket notation: `config.oauth.dpop["iat-window-seconds"]`.
 *
 * Per Wave 2 Phase 2 spec §10.
 */
export declare const dpopConfigSchema: z.ZodObject<{
    oauth: z.ZodObject<{
        dpop: z.ZodDefault<z.ZodObject<{
            enabled: z.ZodDefault<z.ZodBoolean>;
            "iat-window-seconds": z.ZodDefault<z.ZodNumber>;
            "alg-whitelist": z.ZodDefault<z.ZodArray<z.ZodString>>;
            "replay-store": z.ZodDefault<z.ZodEnum<{
                memory: "memory";
                redis: "redis";
            }>>;
            "replay-store-ttl-seconds": z.ZodDefault<z.ZodNumber>;
        }, z.core.$strip>>;
    }, z.core.$strip>;
}, z.core.$strip>;
/**
 * Declarative manifest for the DPoP package.
 *
 * When `config.oauth.dpop.enabled` is `false` (the secure default), the
 * mechanism factory returns `null` and core's synthesizer filters it out —
 * no DPoP mechanism is included in the composed `tokenBindingMw`. When
 * `enabled` is `true`, the factory returns the configured DPoP mechanism
 * for core to compose alongside any other binding-mechanism modules
 * (mTLS, future) under the unified `oauth.tokenBinding.dispatch-policy`.
 *
 * The `dpopReplayStore` optional slot is backed by `createMemoryDPoPReplayStore`
 * when absent. Production deployments provide a Redis-backed implementation
 * by wiring the `dpopReplayStore` slot via their composition root.
 *
 * Migrated from the `grantMiddleware` contribution slot (Phase 2) to
 * `tokenBindingMechanisms` (cross-mechanism dispatch refactor, 2026-05-19)
 * so the `DispatchPolicy` can arbitrate cross-module when both DPoP and
 * mTLS are installed. The mechanism itself is unchanged.
 *
 * See ADR `packages/core/docs/adr/2026-05-20-token-binding-first-class-abstraction.md`
 * for the cross-mechanism design rationale.
 */
export declare const dpopModule: import("@o3co/auth-provider-core").Module;
//# sourceMappingURL=module.d.mts.map