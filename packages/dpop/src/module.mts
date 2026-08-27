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

/**
 * DPoP module manifest — wires `createDPoPMechanism` into the grant
 * middleware contribution slot (Wave 2 Token-binding Cluster spec §4.7 /
 * Phase 2 DPoP spec §11.2).
 *
 * Contributions:
 *   - `grantMiddleware[0]` — `tokenBindingMw` wrapping the DPoP mechanism.
 *     Returns `null` (skip) when `config.oauth.dpop.enabled === false`.
 *
 * DI requires:
 *   - `config` — reads `config.oauth.dpop` + `config.oauth.tokenBinding`, and
 *     `config.oauth.jwt.issuer`, whose origin is the authority half of every
 *     proof's expected `htu` (#292).
 *
 * DI optional:
 *   - `logger`           — forwarded to `tokenBindingMw` + `createDPoPMechanism`.
 *   - `dpopReplayStore`  — consumer-wired Redis adapter for production.
 *                          Falls back to in-memory store when absent (dev/test only).
 *
 * The `dpopReplayStore` optional slot is declared here via ComponentMap
 * augmentation so consumers (e.g. `@o3co/auth-provider-redis`) can provide
 * a Redis-backed implementation without modifying this package.
 *
 * Secure-default-opt-in: `oauth.dpop.enabled = false` in reference.conf.
 * Operators must explicitly set `enabled = true` to activate DPoP.
 *
 * Per Wave 2 Phase 2 spec §10 (config) + §11.2 (module) + feedback_secure_default_opt_in.md.
 */

// biome-ignore lint/correctness/noUnusedImports: ComponentMap is used in the `declare module` augmentation below
import type { ComponentMap as _ComponentMap } from "@o3co/auth-provider-core";
import { defineModule } from "@o3co/auth-provider-core";
import { z } from "zod";
import { createMemoryDPoPReplayStore } from "./memory/replay-store.mjs";
import type { DPoPReplayStore } from "./replay-store.mjs";
import { createDPoPMechanism } from "./verifier.mjs";

// ---------------------------------------------------------------------------
// ComponentMap augmentation — dpopReplayStore slot
// ---------------------------------------------------------------------------

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
				"replay-store": "memory" as const,
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
export const dpopModule = defineModule<"config", "logger" | "dpopReplayStore">({
	name: "dpop",
	configSchema: dpopConfigSchema,
	requires: ["config"],
	optional: ["logger", "dpopReplayStore"],
	contributes: {
		tokenBindingMechanisms: [
			(deps) => {
				const dpopConfig = (deps.config as { oauth?: { dpop?: { enabled?: unknown } } }).oauth
					?.dpop;
				if (dpopConfig?.enabled !== true) {
					// Disabled by config — no mechanism contributed.
					return null;
				}

				const typedConfig = deps.config as unknown as {
					oauth: {
						jwt?: { issuer?: unknown };
						dpop: {
							enabled: boolean;
							"iat-window-seconds": number;
							"alg-whitelist": readonly string[];
							"replay-store": "memory" | "redis";
							"replay-store-ttl-seconds": number;
						};
					};
				};

				// #292: the expected `htu` is built from the deployment's own
				// origin rather than reconstructed from `req.protocol` and the
				// `Host` header, which `X-Forwarded-*` rewrites under Express
				// `trust proxy`.
				//
				// `oauth.jwt.issuer` has been required by core's
				// `CoreConfigSchema` since #266/#307, so this is not a second
				// place to configure an origin — it is the same one, read. The
				// guard exists for a composition root that hand-builds a config
				// object without core's schema; `createDPoPMechanism` validates
				// the value itself and produces the operator-facing message.
				const issuer = typedConfig.oauth.jwt?.issuer;
				if (typeof issuer !== "string" || issuer === "") {
					throw new Error(
						"dpopModule: config.oauth.jwt.issuer is required when DPoP is enabled. Its origin " +
							"is what every DPoP proof's `htu` is checked against; without it the AS would " +
							"have to rebuild that origin from the request's own forwarded headers, which a " +
							"caller can choose (o3co/auth.provider#292).",
					);
				}

				// `replay-store = "redis"` is a load-bearing contract for
				// multi-replica deployments: per-process in-memory state would
				// silently accept the same (jti, jkt) on a second replica → replay
				// protection bypassed. Fail boot loudly when config promises redis
				// but the composition root forgot to wire `dpopReplayStore`. The
				// reverse asymmetry (config says "memory" + slot wired) is fine:
				// the wired slot wins because it expresses a stronger guarantee.
				const replayStoreBackend = typedConfig.oauth.dpop["replay-store"];
				if (replayStoreBackend === "redis" && deps.dpopReplayStore === undefined) {
					throw new Error(
						'dpopModule: config.oauth.dpop.replay-store = "redis" requires the `dpopReplayStore` ComponentMap slot to be wired (e.g. via `createRedisDPoPReplayStore` from `@o3co/auth-provider-redis/dpop`). Configuring "redis" without the slot would silently fall back to a per-process in-memory store and bypass cross-replica replay protection.',
					);
				}
				const replayStore: DPoPReplayStore = deps.dpopReplayStore ?? createMemoryDPoPReplayStore();

				return createDPoPMechanism({
					issuer,
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
