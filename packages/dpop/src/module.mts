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
 * discovery metadata, both built from its own section, `dpop {}`, parsed
 * with {@link dpopConfigSchema} before any factory runs. DPoP is off unless
 * `dpop.enabled = true`. A key still written at `oauth.dpop`, the section's
 * old path, refuses boot naming the new one, and so does a nonce variable's
 * old name unless its new name carries the same value.
 *
 * DI requires `config`: `oauth.jwt.issuer` when no module provides
 * `oauthTokenSettings` (the issuer's origin is the authority half of every
 * proof's expected `htu`).
 *
 * DI optional:
 *   - `logger` — handed to the mechanism; core's `consoleLogger` when absent.
 *   - `replaySeenSet` — where every accepted proof's `jti` is recorded
 *     (`dpop-proof:<jkt>`). Optional because disabled DPoP records nothing;
 *     with DPoP enabled and the slot empty, boot is refused in every
 *     `core.deployment.mode`.
 *   - `oauthTokenSettings` — the issuer, provided by the oauth module from
 *     `oauth {}`; the configuration's when absent.
 */

import {
	assertSecretEntropy,
	checkOAuthTokenSettings,
	coerceBooleanFromEnv,
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
 * The schema of `dpop {}`, the module's own section. Strict at every level: a
 * key it does not declare refuses boot. Each leaf reads the string an
 * environment variable carries.
 */
export const dpopConfigSchema = z
	.object({
		/** When false (default), the dpop mechanism factory returns null — no DPoP mechanism contributed. */
		enabled: coerceBooleanFromEnv.default(false),
		/** Acceptance window for the iat claim in seconds. Default: 60. */
		iatWindowSeconds: z.coerce.number().int().positive().default(60),
		/** JOSE algorithm allowlist. Default: ES256, ES384, EdDSA, RS256. */
		algWhitelist: z.array(z.string()).default(["ES256", "ES384", "EdDSA", "RS256"]),
		/** How long a proof's replay record is kept, in seconds. Default: 300. */
		replayStoreTtlSeconds: z.coerce.number().int().positive().default(300),
		// Server-provided nonce (RFC 9449 §8 / §9). "never" (the default) asks
		// for none; "as" asks at the token endpoint; "as+rs" also at protected
		// resources. The nonce is an HMAC under `secret`, which every replica
		// shares — required once `required` is not "never", and at least 32
		// bytes of decoded key material.
		nonce: z
			.object({
				required: z.enum(["never", "as", "as+rs"]).default("never"),
				ttlSeconds: z.coerce.number().int().positive().default(300),
				secret: z.string().optional(),
			})
			.strict()
			.default(() => ({ required: "never" as const, ttlSeconds: 300 })),
	})
	.strict()
	.default(() => ({
		enabled: false,
		iatWindowSeconds: 60,
		algWhitelist: ["ES256", "ES384", "EdDSA", "RS256"],
		replayStoreTtlSeconds: 300,
		nonce: { required: "never" as const, ttlSeconds: 300 },
	}));

// ---------------------------------------------------------------------------
// Module manifest
// ---------------------------------------------------------------------------

/** `oauth.jwt.issuer` as the configuration carries it. */
const configuredIssuer = (config: unknown): unknown =>
	(config as { oauth?: { jwt?: { issuer?: unknown } } } | undefined)?.oauth?.jwt?.issuer;

/**
 * Declarative manifest for the DPoP package.
 *
 * With `dpop.enabled` false (the default) the mechanism factory
 * returns `null` and core leaves DPoP out of the composed `tokenBindingMw`.
 * With it true, core composes the mechanism alongside any other binding
 * mechanism (mTLS) under `core.tokenBinding.dispatchPolicy`.
 *
 * Every accepted proof is recorded in core's `replaySeenSet` slot, which
 * this module reads and does not fill, so the manifest declares no
 * `replicaSafety`: the seen-set's provider declares whether it forks per
 * replica, and core's guard reads that — `memoryReplaySeenSetModule` is
 * refused under `core.deployment.mode = "multi"`, warned about when the mode is
 * unset, and silent under `"single"`. An enabled mechanism with no seen-set
 * is refused at boot in every mode: it could not refuse a replay.
 *
 * See ADR 2026-05-20-token-binding-first-class-abstraction.
 */
export const dpopModule = defineModule<
	"config",
	"logger" | "replaySeenSet" | "oauthTokenSettings",
	typeof dpopConfigSchema
>({
	name: "dpop",
	// The package's `config/reference.conf` holds this section's defaults,
	// binds the nonce variables at their new paths and nothing at the old
	// one, and captures the renamed variables' old and new names. Only the
	// nonce keys have a variable.
	section: {
		schema: dpopConfigSchema,
		reference: new URL("../config/reference.conf", import.meta.url),
		relocatedFrom: {
			"oauth.dpop": { to: "", environmentVariable: null },
			"oauth.dpop.iat-window-seconds": { to: "iatWindowSeconds", environmentVariable: null },
			"oauth.dpop.alg-whitelist": { to: "algWhitelist", environmentVariable: null },
			"oauth.dpop.replay-store-ttl-seconds": {
				to: "replayStoreTtlSeconds",
				environmentVariable: null,
			},
			"oauth.dpop.replay-store": null,
			"oauth.dpop.nonce.required": "nonce.required",
			"oauth.dpop.nonce.ttl-seconds": "nonce.ttlSeconds",
			"oauth.dpop.nonce.secret": "nonce.secret",
		},
		renamedVariables: {
			OAUTH_DPOP_NONCE_REQUIRED: "oauth.dpop.nonce.required",
			OAUTH_DPOP_NONCE_TTL_SECONDS: "oauth.dpop.nonce.ttl-seconds",
			OAUTH_DPOP_NONCE_SECRET: "oauth.dpop.nonce.secret",
		},
	},
	requires: ["config"],
	// `oauthTokenSettings`: the issuer, which the oauth module provides;
	// read from the configuration when no module does.
	optional: ["logger", "replaySeenSet", "oauthTokenSettings"],
	contributes: {
		// RFC 9449 §5.1 authorization-server metadata: without it a client
		// cannot discover that DPoP is accepted, or with which algorithms.
		// The list is the same `algWhitelist` the mechanism is built from
		// below, so an algorithm picked off discovery is never one the
		// verifier rejects. Disabled DPoP contributes `{}`, not `null`: the
		// `discoveryMetadata` kind has no null-filtering contract.
		discoveryMetadata: [
			({ section }) => {
				if (!section.enabled || section.algWhitelist.length === 0) return {};
				return { metadata: { dpop_signing_alg_values_supported: [...section.algWhitelist] } };
			},
		],
		tokenBindingMechanisms: [
			(deps) => {
				const { section } = deps;
				if (!section.enabled) {
					// Disabled by config — no mechanism contributed.
					return null;
				}

				// Core's `consoleLogger` when no `logger` is wired, so the mechanism's
				// own warnings (a replay TTL too short for the iat window, an
				// unreachable seen-set) do not vanish.
				const logger = deps.logger ?? consoleLogger;

				// The expected `htu` is built from the deployment's own origin, not
				// from `req.protocol` and `Host`, which `X-Forwarded-*` rewrites
				// under Express `trust proxy`. That origin is `oauth.jwt.issuer`,
				// read through the `oauthTokenSettings` slot, checked, when the
				// oauth module provides it, else from the configuration. The guard
				// is for a hand-built config; `createDPoPMechanism` validates the
				// value itself and produces the operator-facing message.
				const issuer =
					deps.oauthTokenSettings === undefined
						? configuredIssuer(deps.config)
						: checkOAuthTokenSettings(deps.oauthTokenSettings, deps.config).issuer;
				if (typeof issuer !== "string" || issuer === "") {
					throw new Error(
						"dpopModule: oauth.jwt.issuer is required when DPoP is enabled. Its origin " +
							"is what every DPoP proof's `htu` is checked against; without it the AS would " +
							"have to rebuild that origin from the request's own forwarded headers, which a " +
							"caller can choose.",
					);
				}

				// Without a seen-set no replay could be refused. There is no
				// per-process fallback: which set backs the slot, and whether it is
				// shared across replicas, is the providing module's declaration,
				// already read by core's replica-safety guard.
				const replaySeenSet = deps.replaySeenSet;
				if (replaySeenSet === undefined) {
					throw new Error(
						"dpopModule: dpop.enabled = true requires a replaySeenSet component. " +
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
				const nonceConfig = section.nonce;
				let nonce: DPoPMechanismOptions["nonce"];
				if (nonceConfig.required !== "never") {
					const secret = nonceConfig.secret;
					if (secret === undefined || secret.length === 0) {
						throw new Error(
							`dpopModule: dpop.nonce.required = "${nonceConfig.required}" but ` +
								"dpop.nonce.secret is unset (DPOP_NONCE_SECRET). The nonce " +
								"is an HMAC under a secret every replica shares; without one, no nonce this " +
								"replica issues could be verified by another. Set at least 32 bytes of random " +
								'material, or set nonce.required = "never".',
						);
					}
					// The same floor, measured the same way, as every other operator
					// secret: on the decoded value, naming the key and the env var.
					// The issuer checks too; this is the refusal an operator reads.
					assertSecretEntropy(secret, {
						configKey: "dpop.nonce.secret",
						envVar: "DPOP_NONCE_SECRET",
					});
					nonce = {
						required: nonceConfig.required,
						issuer: createDPoPNonceIssuer({ secret, ttlSeconds: nonceConfig.ttlSeconds }),
					};
				}

				return createDPoPMechanism({
					issuer,
					replaySeenSet,
					iatWindowSeconds: section.iatWindowSeconds,
					algWhitelist: section.algWhitelist,
					replayTtlSeconds: section.replayStoreTtlSeconds,
					logger,
					...(nonce === undefined ? {} : { nonce }),
				});
			},
		],
	},
});
