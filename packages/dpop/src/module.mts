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
 * DPoP module manifest — contributes `createDPoPMechanism` to core's
 * `tokenBindingMechanisms` slot (Wave 2 Token-binding Cluster spec §4.7 /
 * Phase 2 DPoP spec §11.2).
 *
 * Contributions:
 *   - `tokenBindingMechanisms[0]` — the DPoP mechanism, which core composes
 *     into its single `tokenBindingMw` and its protected-resource check.
 *     Returns `null` (skip) when `config.oauth.dpop.enabled !== true`.
 *   - `discoveryMetadata[0]` — `dpop_signing_alg_values_supported` while
 *     enabled; an empty contribution otherwise.
 *
 * DI requires:
 *   - `config` — reads `config.oauth.dpop` + `config.oauth.tokenBinding`,
 *     `config.oauth.jwt.issuer`, whose origin is the authority half of every
 *     proof's expected `htu` (#292), and `config.deployment.mode`.
 *
 * DI optional:
 *   - `logger`           — forwarded to `tokenBindingMw` + `createDPoPMechanism`.
 *   - `dpopReplayStore`  — consumer-wired shared (Redis) store for production.
 *                          When absent, falls back to a per-process store, which
 *                          forks per replica: boot is refused under
 *                          `deployment.mode = "multi"`, warns
 *                          (`dpop_replay_store_not_shared`) when the mode is
 *                          unset, and is silent under `"single"`.
 *
 * The `dpopReplayStore` optional slot is declared here via ComponentMap
 * augmentation so consumers (e.g. `@o3co/auth-provider-redis`) can provide
 * a Redis-backed implementation without modifying this package.
 *
 * Secure-default-opt-in: `oauth.dpop.enabled = false` in reference.conf.
 * Operators must explicitly set `enabled = true` to activate DPoP.
 *
 * Per Wave 2 Phase 2 spec §10 (config) + §11.2 (module).
 */

// biome-ignore lint/correctness/noUnusedImports: ComponentMap is used in the `declare module` augmentation below
import type { ComponentMap as _ComponentMap } from "@o3co/auth-provider-core";
import {
	assertSecretEntropy,
	BootError,
	consoleLogger,
	defineModule,
} from "@o3co/auth-provider-core";
import { z } from "zod";
import { createMemoryDPoPReplayStore } from "./memory/replay-store.mjs";
import { createDPoPNonceIssuer } from "./nonce.mjs";
import type { DPoPReplayStore } from "./replay-store.mjs";
import { createDPoPMechanism, type DPoPMechanismOptions } from "./verifier.mjs";

// ---------------------------------------------------------------------------
// ComponentMap augmentation — dpopReplayStore slot
// ---------------------------------------------------------------------------

/**
 * Optional ComponentMap slot for the DPoP replay store. When absent,
 * `dpopModule` falls back to the in-memory adapter, which one process alone
 * can use correctly: under `deployment.mode = "multi"` that fallback refuses
 * to boot. Production deployments wire the Redis-backed implementation via:
 *
 * ```ts
 * import { createRedisDPoPReplayStore } from "@o3co/auth-provider-redis/dpop";
 * const store = createRedisDPoPReplayStore({
 *     client: { set: (k, v, _px, ttlMs, _nx) => io.set(k, v, "PX", ttlMs, "NX") as Promise<"OK" | null> },
 * });
 * // either in a composition module's `provides` (a factory):
 * dpopReplayStore: () => store,
 * // or in `createApp`'s `bootstrapComponents` (the value itself):
 * bootstrapComponents: { config, pathResolver, dpopReplayStore: store },
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
				/** Replay store backend selector. "memory" is per-process: one replica only. */
				"replay-store": z.enum(["memory", "redis"]).default("memory"),
				/** TTL for replay entries in seconds. Default: 300. */
				"replay-store-ttl-seconds": z.number().int().positive().default(300),
				// #530: server-provided nonce (RFC 9449 §8 / §9). "never" (the
				// default) asks for none; "as" asks at the token endpoint; "as+rs"
				// also at protected resources. The nonce is an HMAC under `secret`,
				// which every replica shares — required once `required` is not
				// "never", and at least 32 bytes of decoded key material (#282's floor).
				nonce: z
					.object({
						required: z.enum(["never", "as", "as+rs"]).default("never"),
						"ttl-seconds": z.coerce.number().int().positive().default(300),
						secret: z.string().optional(),
					})
					.default(() => ({ required: "never" as const, "ttl-seconds": 300 })),
			})
			.default(() => ({
				enabled: false,
				"iat-window-seconds": 60,
				"alg-whitelist": ["ES256", "ES384", "EdDSA", "RS256"],
				"replay-store": "memory" as const,
				"replay-store-ttl-seconds": 300,
				nonce: { required: "never" as const, "ttl-seconds": 300 },
			})),
	}),
});

// ---------------------------------------------------------------------------
// Module manifest
// ---------------------------------------------------------------------------

/** The manifest's name, and the offender a replica-safety refusal names. */
const MODULE_NAME = "dpop";

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
 * The manifest declares no `replicaSafety`: whether the replay store is
 * per-process depends on whether that slot is filled, which the stage-1 guard
 * cannot see and the mechanism factory can. The factory therefore applies the
 * guard's three states itself when it falls back — `deployment.mode = "multi"`
 * refuses boot (`replica-unsafe-adapter`), unset warns
 * (`dpop_replay_store_not_shared`), `"single"` is silent — the shape the
 * per-process rate-limit fallbacks in session and webauthn use (#474).
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
	name: MODULE_NAME,
	configSchema: dpopConfigSchema,
	requires: ["config"],
	optional: ["logger", "dpopReplayStore"],
	contributes: {
		// RFC 9449 §5.1 authorization-server metadata (#283). Without it a client
		// reading `/.well-known/openid-configuration` cannot discover that this
		// deployment accepts DPoP proofs at all, let alone which JOSE algorithms
		// the verifier will accept — it would have to try one and read the error.
		//
		// The advertised list is the SAME `alg-whitelist` read the mechanism is
		// constructed from below, so an algorithm a client picks off discovery
		// cannot be one the proof verifier then rejects.
		//
		// Contributes an EMPTY contribution (not `null`) when DPoP is disabled:
		// unlike `tokenBindingMechanisms`, the `discoveryMetadata` kind has no
		// null-filtering contract — core's aggregator iterates every collected
		// contribution. An empty one adds no fields, which is what "disabled"
		// means to a reader of the document.
		discoveryMetadata: [
			(deps) => {
				const dpop = (
					deps.config as {
						oauth?: { dpop?: { enabled?: unknown; "alg-whitelist"?: unknown } };
					}
				).oauth?.dpop;
				if (dpop?.enabled !== true) return {};
				const algs = dpop["alg-whitelist"];
				// `oauth.dpop` reaches modules through `composeConfigSchema`, so the
				// whitelist is normally schema-defaulted. A composition root that
				// hand-builds its config bypasses that, and an absent whitelist must
				// not become `dpop_signing_alg_values_supported: undefined` in the
				// served document.
				if (!Array.isArray(algs) || algs.length === 0) return {};
				return { metadata: { dpop_signing_alg_values_supported: [...algs] } };
			},
		],
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
							nonce?: {
								required?: "never" | "as" | "as+rs";
								"ttl-seconds"?: number;
								secret?: unknown;
							};
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
				if (deps.dpopReplayStore === undefined) {
					// The per-process fallback below is replica-unsafe state of the
					// kind core's boot guard refuses (#271), and it sits outside that
					// guard because it is chosen here — by whether a DI slot is
					// filled — rather than declared on the manifest. So it reads the
					// same three-state switch the per-process rate-limit fallbacks
					// read (#474): "multi" refuses, "single" is silent, unset warns.
					// Thrown from a contribution factory, the planner wraps this as
					// `contribute-factory-failed` with this error as its `cause`.
					//
					// The check is whether the slot is empty, nothing more: a
					// per-process store handed into the slot (the exported
					// `createMemoryDPoPReplayStore`) counts as wired, because the
					// wired slot wins and this factory cannot tell what backs it.
					const iatWindowSeconds: unknown = typedConfig.oauth.dpop["iat-window-seconds"];
					// The verifier accepts a proof while |floor(now) - iat| <= W,
					// i.e. from iat - W until iat + W + 1: up to 2W + 1 seconds. A
					// hand-built config can omit W (the verifier then defaults it);
					// the message then names the key instead of a number.
					const replaySpan =
						typeof iatWindowSeconds === "number"
							? `within ±${iatWindowSeconds}s of that replica's clock (up to ${2 * iatWindowSeconds + 1}s)`
							: "within ±oauth.dpop.iat-window-seconds of that replica's clock";
					const deploymentMode = deps.config.deployment?.mode;
					if (deploymentMode === "multi") {
						throw new BootError({
							stage: "applyContributions",
							reason: "replica-unsafe-adapter",
							message: `deployment.mode is "multi" but DPoP is enabled with no dpopReplayStore wired: proofs would be checked against a per-process replay store, so a DPoP proof captured once can be replayed once against each replica while its iat is ${replaySpan}. Wire a shared dpopReplayStore (createRedisDPoPReplayStore from @o3co/auth-provider-redis/dpop) and set oauth.dpop.replay-store = "redis", or set deployment.mode = "single".`,
							details: { reason: "replica-unsafe-adapter", modules: [MODULE_NAME] },
						});
					}
					if (deploymentMode !== "single") {
						(deps.logger ?? consoleLogger).warn(
							{ replayStore: "memory", iatWindowSeconds },
							"dpop_replay_store_not_shared",
						);
					}
				}
				const replayStore: DPoPReplayStore = deps.dpopReplayStore ?? createMemoryDPoPReplayStore();

				// #530: the nonce is an HMAC under a secret every replica shares.
				// Required once a nonce is asked for: a per-replica random key
				// would mint nonces no other replica could verify, and a client
				// bouncing between replicas would never get past use_dpop_nonce.
				const nonceConfig = typedConfig.oauth.dpop.nonce;
				const nonceRequired = nonceConfig?.required ?? "never";
				let nonce: DPoPMechanismOptions["nonce"];
				if (nonceRequired !== "never") {
					const secret = nonceConfig?.secret;
					if (typeof secret !== "string" || secret.length === 0) {
						throw new Error(
							`dpopModule: config.oauth.dpop.nonce.required = "${nonceRequired}" but ` +
								"config.oauth.dpop.nonce.secret is unset (OAUTH_DPOP_NONCE_SECRET). The nonce " +
								"is an HMAC under a secret every replica shares; without one, no nonce this " +
								"replica issues could be verified by another. Set at least 32 bytes of random " +
								'material, or set nonce.required = "never".',
						);
					}
					// The same floor, measured the same way, as every other operator
					// secret (#282): on the decoded value, naming the key and the env
					// var. The issuer checks too; this is the refusal an operator reads.
					assertSecretEntropy(secret, {
						configKey: "oauth.dpop.nonce.secret",
						envVar: "OAUTH_DPOP_NONCE_SECRET",
					});
					nonce = {
						required: nonceRequired,
						issuer: createDPoPNonceIssuer({
							secret,
							ttlSeconds: nonceConfig?.["ttl-seconds"] ?? 300,
						}),
					};
				}

				return createDPoPMechanism({
					issuer,
					replayStore,
					iatWindowSeconds: typedConfig.oauth.dpop["iat-window-seconds"],
					algWhitelist: typedConfig.oauth.dpop["alg-whitelist"],
					replayTtlSeconds: typedConfig.oauth.dpop["replay-store-ttl-seconds"],
					logger: deps.logger,
					...(nonce === undefined ? {} : { nonce }),
				});
			},
		],
	},
});
