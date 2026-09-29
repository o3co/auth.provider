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
 * DPoP module manifest: contributes the DPoP mechanism to core's
 * `tokenBindingMechanisms` slot (composed into `tokenBindingMw` and the
 * protected-resource check) and `dpop_signing_alg_values_supported` to
 * discovery metadata. DPoP is off unless `oauth.dpop.enabled = true`.
 *
 * DI requires `config`: `config.oauth.dpop`, and `config.oauth.jwt.issuer`
 * when no module provides `oauthTokenSettings` (the issuer's origin is the
 * authority half of every proof's expected `htu`).
 *
 * DI optional:
 *   - `logger` — handed to the mechanism; core's `consoleLogger` when absent.
 *   - `replaySeenSet` — where every accepted proof's `jti` is recorded
 *     (`dpop-proof:<jkt>`). Optional because disabled DPoP records nothing;
 *     with DPoP enabled and the slot empty, boot is refused in every
 *     `deployment.mode`.
 *   - `oauthTokenSettings` — the issuer, provided by the oauth module from
 *     `oauth {}`; the configuration's when absent.
 */

import {
	assertSecretEntropy,
	checkOAuthTokenSettings,
	consoleLogger,
	defineModule,
} from "@o3co/auth-provider-core";
import { z } from "zod";
import { createDPoPNonceIssuer } from "./nonce.mjs";
import { createDPoPMechanism, type DPoPMechanismOptions } from "./verifier.mjs";

// ---------------------------------------------------------------------------
// Config schema
// ---------------------------------------------------------------------------

/**
 * Zod schema for the `oauth.dpop` config slice. Keys are kebab-case to match
 * the HOCON reference.conf keys verbatim, read with bracket notation:
 * `config.oauth.dpop["iat-window-seconds"]`.
 */
export const dpopConfigSchema = z.object({
	oauth: z.object({
		// `oauth.tokenBinding.dispatch-policy` is declared by core's
		// `CoreConfigSchema`: it applies across every binding mechanism.
		dpop: z
			.object({
				/** When false (default), the dpop mechanism factory returns null — no DPoP mechanism contributed. */
				enabled: z.boolean().default(false),
				/** Acceptance window for the iat claim in seconds. Default: 60. */
				"iat-window-seconds": z.number().int().positive().default(60),
				/** JOSE algorithm allowlist. Default: ES256, ES384, EdDSA, RS256. */
				"alg-whitelist": z.array(z.string()).default(["ES256", "ES384", "EdDSA", "RS256"]),
				// No `replay-store` key: proofs are recorded in the `replaySeenSet`
				// slot, and core's schema refuses that key by name.
				/** How long a proof's replay record is kept, in seconds. Default: 300. */
				"replay-store-ttl-seconds": z.number().int().positive().default(300),
				// Server-provided nonce (RFC 9449 §8 / §9). "never" (the default)
				// asks for none; "as" asks at the token endpoint; "as+rs" also at
				// protected resources. The nonce is an HMAC under `secret`, which
				// every replica shares — required once `required` is not "never",
				// and at least 32 bytes of decoded key material.
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
 * The `oauth.dpop` section as the module declares it: its schema, the
 * package's `config/reference.conf` holding its defaults, and its path. The
 * `configSchema` declares the same path with the same schema, so boot parses
 * the value there twice — the `configSchema` over what core's base made of
 * it, then the section over that, written back at its path — which is
 * idempotent.
 */
const DPOP_SECTION_SCHEMA = dpopConfigSchema.shape.oauth.shape.dpop;

/**
 * Declarative manifest for the DPoP package.
 *
 * With `config.oauth.dpop.enabled` false (the default) the mechanism factory
 * returns `null` and core leaves DPoP out of the composed `tokenBindingMw`.
 * With it true, core composes the mechanism alongside any other binding
 * mechanism (mTLS) under `oauth.tokenBinding.dispatch-policy`.
 *
 * Every accepted proof is recorded in core's `replaySeenSet` slot, which
 * this module reads and does not fill, so the manifest declares no
 * `replicaSafety`: the seen-set's provider declares whether it forks per
 * replica, and core's guard reads that — `memoryReplaySeenSetModule` is
 * refused under `deployment.mode = "multi"`, warned about when the mode is
 * unset, and silent under `"single"`. An enabled mechanism with no seen-set
 * is refused at boot in every mode: it could not refuse a replay.
 *
 * See ADR 2026-05-20-token-binding-first-class-abstraction.
 */
export const dpopModule = defineModule<
	"config",
	"logger" | "replaySeenSet" | "oauthTokenSettings",
	typeof DPOP_SECTION_SCHEMA
>({
	name: "dpop",
	configSchema: dpopConfigSchema,
	section: {
		schema: DPOP_SECTION_SCHEMA,
		reference: new URL("../config/reference.conf", import.meta.url),
		at: "oauth.dpop",
	},
	requires: ["config"],
	// `oauthTokenSettings`: the issuer, which the oauth module provides;
	// read from the configuration when no module does.
	optional: ["logger", "replaySeenSet", "oauthTokenSettings"],
	contributes: {
		// RFC 9449 §5.1 authorization-server metadata: without it a client
		// cannot discover that DPoP is accepted, or with which algorithms.
		// The list is the same `alg-whitelist` the mechanism is built from
		// below, so an algorithm picked off discovery is never one the
		// verifier rejects. Disabled DPoP contributes `{}`, not `null`: the
		// `discoveryMetadata` kind has no null-filtering contract.
		discoveryMetadata: [
			(deps) => {
				const dpop = (
					deps.config as {
						oauth?: { dpop?: { enabled?: unknown; "alg-whitelist"?: unknown } };
					}
				).oauth?.dpop;
				if (dpop?.enabled !== true) return {};
				const algs = dpop["alg-whitelist"];
				// Boot's composed parse layers the package's reference.conf, so the
				// whitelist is normally there; a hand-built config may lack it, and
				// the served document must not carry `undefined` for it.
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

				// Core's `consoleLogger` when no `logger` is wired, so the mechanism's
				// own warnings (a replay TTL too short for the iat window, an
				// unreachable seen-set) do not vanish.
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

				// The expected `htu` is built from the deployment's own origin, not
				// from `req.protocol` and `Host`, which `X-Forwarded-*` rewrites
				// under Express `trust proxy`. That origin is `oauth.jwt.issuer`
				// (required by core's `CoreConfigSchema`), read through the
				// `oauthTokenSettings` slot, checked, when the oauth module provides
				// it, else from the configuration. The guard is for a hand-built
				// config; `createDPoPMechanism` validates the value itself and
				// produces the operator-facing message.
				const issuer =
					deps.oauthTokenSettings === undefined
						? typedConfig.oauth.jwt?.issuer
						: checkOAuthTokenSettings(deps.oauthTokenSettings, deps.config).issuer;
				if (typeof issuer !== "string" || issuer === "") {
					throw new Error(
						"dpopModule: config.oauth.jwt.issuer is required when DPoP is enabled. Its origin " +
							"is what every DPoP proof's `htu` is checked against; without it the AS would " +
							"have to rebuild that origin from the request's own forwarded headers, which a " +
							"caller can choose (o3co/auth.provider#292).",
					);
				}

				// Without a seen-set no replay could be refused. There is no
				// per-process fallback: which set backs the slot, and whether it is
				// shared across replicas, is the providing module's declaration,
				// already read by core's replica-safety guard.
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

				// The nonce is an HMAC under a secret every replica shares, required
				// once a nonce is asked for: a per-replica random key would mint
				// nonces no other replica could verify, and a client bouncing
				// between replicas would never get past use_dpop_nonce.
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
					// secret: on the decoded value, naming the key and the env var.
					// The issuer checks too; this is the refusal an operator reads.
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
