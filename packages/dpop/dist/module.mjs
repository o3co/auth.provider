/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import { defineModule } from "@o3co/auth-provider-core";
import { z } from "zod";
import { createMemoryDPoPReplayStore } from "./memory/replay-store.mjs";
import { createDPoPMechanism } from "./verifier.mjs";
// ---------------------------------------------------------------------------
// Config schema
// ---------------------------------------------------------------------------
/**
 * Zod schema for the `oauth.dpop` config slice.
 *
 * Keys use kebab-case to match the HOCON reference.conf keys exactly.
 * HOCON preserves key names verbatim; TypeScript accesses them via
 * bracket notation: `config.oauth.dpop["iat-window-seconds"]`.
 *
 * Per Wave 2 Phase 2 spec §10.
 */
export const dpopConfigSchema = z.object({
    oauth: z.object({
        // NOTE: `oauth.tokenBinding.dispatch-policy` is declared by core's
        // bundled `CoreConfigSchema` since the cross-mechanism dispatch
        // refactor — it applies across ALL installed binding-mechanism modules
        // (DPoP, mTLS, ...). This package no longer redeclares it.
        dpop: z
            .object({
            /** When false (default), the dpop mechanism factory returns null — no DPoP mechanism contributed. */
            enabled: z.boolean().default(false),
            /** Acceptance window for the iat claim in seconds. Default: 60. */
            "iat-window-seconds": z.number().int().positive().default(60),
            /** JOSE algorithm allowlist. Default: ES256, ES384, EdDSA, RS256. */
            "alg-whitelist": z.array(z.string()).default(["ES256", "ES384", "EdDSA", "RS256"]),
            /** Replay store backend selector. "memory" is dev/test only. */
            "replay-store": z.enum(["memory", "redis"]).default("memory"),
            /** TTL for replay entries in seconds. Default: 300. */
            "replay-store-ttl-seconds": z.number().int().positive().default(300),
        })
            .default(() => ({
            enabled: false,
            "iat-window-seconds": 60,
            "alg-whitelist": ["ES256", "ES384", "EdDSA", "RS256"],
            "replay-store": "memory",
            "replay-store-ttl-seconds": 300,
        })),
    }),
});
// ---------------------------------------------------------------------------
// Module manifest
// ---------------------------------------------------------------------------
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
export const dpopModule = defineModule({
    name: "dpop",
    configSchema: dpopConfigSchema,
    requires: ["config"],
    optional: ["logger", "dpopReplayStore"],
    contributes: {
        tokenBindingMechanisms: [
            (deps) => {
                const dpopConfig = deps.config.oauth
                    ?.dpop;
                if (!dpopConfig || dpopConfig.enabled !== true) {
                    // Disabled by config — no mechanism contributed.
                    return null;
                }
                const typedConfig = deps.config;
                // `replay-store = "redis"` is a load-bearing contract for
                // multi-replica deployments: per-process in-memory state would
                // silently accept the same (jti, jkt) on a second replica → replay
                // protection bypassed. Fail boot loudly when config promises redis
                // but the composition root forgot to wire `dpopReplayStore`. The
                // reverse asymmetry (config says "memory" + slot wired) is fine:
                // the wired slot wins because it expresses a stronger guarantee.
                const replayStoreBackend = typedConfig.oauth.dpop["replay-store"];
                if (replayStoreBackend === "redis" && deps.dpopReplayStore === undefined) {
                    throw new Error('dpopModule: config.oauth.dpop.replay-store = "redis" requires the `dpopReplayStore` ComponentMap slot to be wired (e.g. via `createRedisDPoPReplayStore` from `@o3co/auth-provider-redis/dpop`). Configuring "redis" without the slot would silently fall back to a per-process in-memory store and bypass cross-replica replay protection.');
                }
                const replayStore = deps.dpopReplayStore ?? createMemoryDPoPReplayStore();
                return createDPoPMechanism({
                    replayStore,
                    iatWindowSeconds: typedConfig.oauth.dpop["iat-window-seconds"],
                    algWhitelist: typedConfig.oauth.dpop["alg-whitelist"],
                    replayTtlSeconds: typedConfig.oauth.dpop["replay-store-ttl-seconds"],
                    logger: deps.logger,
                });
            },
        ],
    },
});
