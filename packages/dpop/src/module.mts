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
 * with {@link dpopConfigSchema} before any factory runs. The section's
 * defaults live in the package's `config/reference.conf` alone. DPoP is off
 * unless `dpop.enabled = true`, the module's switch (`section.isEnabled`),
 * which reads an absent section or key as off: off, the module registers
 * nothing and requires nothing. A key still written at `oauth.dpop`, the
 * section's old path, refuses boot naming the new one, and so does a nonce
 * variable's old name set, whether or not its new name is set.
 *
 * DI requires `oauthTokenSettings`: the deployment's issuer, whose origin is
 * the authority half of every proof's expected `htu`. The oauth module
 * provides it; a composition without that module fills the slot itself.
 *
 * DI optional:
 *   - `logger` — handed to the mechanism; core's `consoleLogger` when absent.
 *   - `replaySeenSet` — where every accepted proof's `jti` is recorded
 *     (`dpop-proof:<jkt>`). Optional so that the slot's absence is refused
 *     by the module, in every `core.deployment.mode`, naming why.
 */

import {
	assertSecretEntropy,
	checkOAuthTokenSettings,
	coerceBooleanFromEnv,
	consoleLogger,
	defineModule,
	wholeNumberInRangeFromEnv,
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
 * environment variable carries. It fills no default: the package's
 * `config/reference.conf` ships every value, so a key a composition leaves
 * out of a section it writes refuses boot, naming the key. Absent, the
 * section is `undefined`, which the switch reads as off.
 */
export const dpopConfigSchema = z
	.object({
		/** The module's switch: on only when true; absent is off. */
		enabled: coerceBooleanFromEnv.optional(),
		/** Acceptance window for the iat claim in seconds. */
		iatWindowSeconds: wholeNumberInRangeFromEnv(1),
		/** JOSE algorithm allowlist. */
		algWhitelist: z.array(z.string()),
		/** How long a proof's replay record is kept, in seconds. */
		replayStoreTtlSeconds: wholeNumberInRangeFromEnv(1),
		// Server-provided nonce (RFC 9449 §8 / §9). "never" asks for none;
		// "as" asks at the token endpoint; "as+rs" also at protected
		// resources. The nonce is an HMAC under `secret`, which every replica
		// shares — required once `required` is not "never", and at least 32
		// bytes of decoded key material.
		nonce: z
			.object({
				required: z.enum(["never", "as", "as+rs"]),
				ttlSeconds: wholeNumberInRangeFromEnv(1),
				secret: z.string().optional(),
			})
			.strict(),
	})
	.strict()
	.optional();

/** The section a factory reads. */
type DPoPSection = NonNullable<z.output<typeof dpopConfigSchema>>;

/**
 * The section a factory is handed. Boot runs a factory only while the
 * switch answers true, which an absent section does not; a factory called
 * directly with none is refused, naming the section.
 */
function enabledSection(section: DPoPSection | undefined): DPoPSection {
	if (section === undefined) {
		throw new Error("dpopModule: a factory ran with no dpop section; DPoP is off without one.");
	}
	return section;
}

// ---------------------------------------------------------------------------
// Module manifest
// ---------------------------------------------------------------------------

/**
 * Declarative manifest for the DPoP package.
 *
 * With `dpop.enabled` false (the shipped value) or absent the module
 * registers nothing.
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
	"oauthTokenSettings",
	"logger" | "replaySeenSet",
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
		isEnabled: (section) => section?.enabled === true,
	},
	// `oauthTokenSettings`: the issuer, which the oauth module provides.
	requires: ["oauthTokenSettings"],
	optional: ["logger", "replaySeenSet"],
	contributes: {
		// RFC 9449 §5.1 authorization-server metadata: without it a client
		// cannot discover that DPoP is accepted, or with which algorithms.
		// The list is the same `algWhitelist` the mechanism is built from
		// below, so an algorithm picked off discovery is never one the
		// verifier rejects. An empty list contributes `{}`, not `null`: the
		// `discoveryMetadata` kind has no null-filtering contract.
		discoveryMetadata: [
			(deps) => {
				const { algWhitelist } = enabledSection(deps.section);
				if (algWhitelist.length === 0) return {};
				return { metadata: { dpop_signing_alg_values_supported: [...algWhitelist] } };
			},
		],
		tokenBindingMechanisms: [
			(deps) => {
				const section = enabledSection(deps.section);
				// Core's `consoleLogger` when no `logger` is wired, so the mechanism's
				// own warnings (a replay TTL too short for the iat window, an
				// unreachable seen-set) do not vanish.
				const logger = deps.logger ?? consoleLogger;

				// The expected `htu` is built from the deployment's own origin, not
				// from `req.protocol` and `Host`, which `X-Forwarded-*` rewrites
				// under Express `trust proxy`. That origin is the issuer the
				// `oauthTokenSettings` slot carries. Boot holds the slot to its
				// contract before any reader; the check here refuses a value a
				// direct caller hands in, naming the member it lacks.
				const { issuer } = checkOAuthTokenSettings(deps.oauthTokenSettings);

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
