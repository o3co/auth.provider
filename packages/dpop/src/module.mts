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
 *   - `config` — reads `config.oauth.dpop` + `config.oauth.tokenBinding`, and
 *     `config.oauth.jwt.issuer`, whose origin is the authority half of every
 *     proof's expected `htu` (#292).
 *
 * DI optional:
 *   - `logger`         — handed to `createDPoPMechanism`; core's
 *                        `consoleLogger` when absent, so the mechanism's
 *                        warnings are not dropped.
 *   - `replaySeenSet`  — core's seen-set, where every accepted proof's `jti`
 *                        is recorded (`dpop-proof:<jkt>`). Optional to wire
 *                        because DPoP left disabled records nothing; with
 *                        DPoP enabled and the slot empty, boot is refused in
 *                        every `deployment.mode`. Whether the set is shared
 *                        is the providing module's declaration, read by
 *                        core's replica-safety guard: the memory seen-set
 *                        module is refused under `"multi"` and warned about
 *                        when the mode is unset. This module adds no check of
 *                        its own.
 *
 * Secure-default-opt-in: `oauth.dpop.enabled = false` in reference.conf.
 * Operators must explicitly set `enabled = true` to activate DPoP.
 *
 * Per Wave 2 Phase 2 spec §10 (config) + §11.2 (module).
 */

import { assertSecretEntropy, consoleLogger, defineModule } from "@o3co/auth-provider-core";
import { z } from "zod";
import { createDPoPNonceIssuer } from "./nonce.mjs";
import { createDPoPMechanism, type DPoPMechanismOptions } from "./verifier.mjs";

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
				// `replay-store` is retired: proofs are recorded in the
				// `replaySeenSet` slot, and core's schema refuses the key by name.
				/** How long a proof's replay record is kept, in seconds. Default: 300. */
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
				"replay-store-ttl-seconds": 300,
				nonce: { required: "never" as const, "ttl-seconds": 300 },
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
 * Every accepted proof is recorded in core's `replaySeenSet` slot, which
 * this module reads and does not fill. The manifest declares no
 * `replicaSafety` because it holds no state: the module that provides the
 * seen-set declares whether it forks per replica, and core's stage-1 guard
 * reads that declaration — `memoryReplaySeenSetModule` is refused under
 * `deployment.mode = "multi"`, warned about when the mode is unset, and
 * silent under `"single"`. An enabled mechanism with no seen-set at all is
 * refused at boot in every mode: it would have nowhere to record a proof,
 * and so no way to refuse its replay.
 *
 * Migrated from the `grantMiddleware` contribution slot (Phase 2) to
 * `tokenBindingMechanisms` (cross-mechanism dispatch refactor, 2026-05-19)
 * so the `DispatchPolicy` can arbitrate cross-module when both DPoP and
 * mTLS are installed. The mechanism itself is unchanged.
 *
 * See ADR `packages/core/docs/adr/2026-05-20-token-binding-first-class-abstraction.md`
 * for the cross-mechanism design rationale.
 */
export const dpopModule = defineModule<"config", "logger" | "replaySeenSet">({
	name: "dpop",
	configSchema: dpopConfigSchema,
	requires: ["config"],
	optional: ["logger", "replaySeenSet"],
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

				// One logger for everything the mechanism reports. With no `logger`
				// component wired it is core's `consoleLogger`, as for every other
				// module that declares the slot optional: the mechanism's own
				// warnings (a replay TTL too short for the iat window, a seen-set
				// that cannot be reached) must not be the ones that vanish.
				const logger = deps.logger ?? consoleLogger;

				const typedConfig = deps.config as unknown as {
					oauth: {
						jwt?: { issuer?: unknown };
						dpop: {
							enabled: boolean;
							"iat-window-seconds": number;
							"alg-whitelist": readonly string[];
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

				// Every accepted proof is recorded in the seen-set; without one the
				// mechanism could not refuse a replay at all. There is no
				// per-process fallback to choose on the composition's behalf: which
				// set backs the slot — and whether it is shared across replicas —
				// is the providing module's declaration, which core's
				// replica-safety guard has already read by the time this runs.
				const replaySeenSet = deps.replaySeenSet;
				if (replaySeenSet === undefined) {
					throw new Error(
						"dpopModule: oauth.dpop.enabled = true requires a replaySeenSet component. " +
							"Every accepted DPoP proof's jti is recorded there so the same proof is " +
							"accepted once; without it no replay could be refused. Install " +
							"memoryReplaySeenSetModule (single replica only) or redisReplaySeenSetModule " +
							"(shared across replicas), or leave DPoP disabled.",
					);
				}

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
					replaySeenSet,
					iatWindowSeconds: typedConfig.oauth.dpop["iat-window-seconds"],
					algWhitelist: typedConfig.oauth.dpop["alg-whitelist"],
					replayTtlSeconds: typedConfig.oauth.dpop["replay-store-ttl-seconds"],
					logger,
					...(nonce === undefined ? {} : { nonce }),
				});
			},
		],
	},
});
