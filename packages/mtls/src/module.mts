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
 * mTLS module manifest — wires `createMtlsMechanism` into the grant
 * middleware contribution slot (Wave 2 Token-binding Cluster spec §4.7 /
 * Phase 3 spec §11.1).
 *
 * Contributions:
 *   - `grantMiddleware[0]` — `tokenBindingMw` wrapping the mTLS mechanism.
 *     Returns `null` (skip) when `config.oauth.mtls.enabled === false`.
 *
 * DI requires: `config` (reads `config.oauth.mtls` + `config.oauth.tokenBinding`).
 * DI optional: `logger` (forwarded to `tokenBindingMw` + `createMtlsMechanism`).
 *
 * No `ComponentMap` augmentation is needed for mTLS — unlike DPoP, the
 * mechanism has no consumer-wired dependencies (no replay store).
 *
 * Secure-default-opt-in: `oauth.mtls.enabled = false` in reference.conf.
 * Operators must explicitly set `enabled = true` to activate mTLS. Since
 * issue #280 the same discipline applies to where the certificate comes from:
 * `oauth.mtls.source` defaults to `"tls-layer"`, and the forwarded-header
 * source additionally requires an explicit `oauth.mtls.trusted-proxies`
 * allowlist.
 *
 * Per Wave 2 Phase 3 spec §10 (config) + §11 (module) + feedback_secure_default_opt_in.md.
 */

import { defineModule } from "@o3co/auth-provider-core";
import { z } from "zod";
import { createMtlsMechanism } from "./extractor.mjs";

// ---------------------------------------------------------------------------
// Config schema
// ---------------------------------------------------------------------------

/**
 * Zod schema for the `oauth.mtls` config slice.
 *
 * Keys use kebab-case to match the HOCON reference.conf keys verbatim.
 * HOCON preserves key names exactly; TypeScript accesses them via bracket
 * notation: `config.oauth.mtls["cert-header"]`.
 *
 * NOTE: `oauth.tokenBinding.dispatch-policy` is declared by core's bundled
 * `CoreConfigSchema` since the cross-mechanism dispatch refactor — it
 * applies across ALL installed binding-mechanism modules (DPoP, mTLS, ...).
 * This package no longer redeclares it.
 *
 * Per Wave 2 Phase 3 spec §10.2.
 */
export const mtlsConfigSchema = z.object({
	oauth: z.object({
		mtls: z
			.object({
				/** When false (default), mtlsModule contributes null — no mTLS middleware mounted. */
				enabled: z.boolean().default(false),
				/**
				 * Where the leaf cert comes from. Defaults to `"tls-layer"`
				 * (issue #280): RFC 8705 §3 wants the certificate from the
				 * transport, and a forwarded header only substitutes for it when
				 * the forwarding hop is authenticated — which `"header"` now
				 * requires via `trusted-proxies`.
				 */
				source: z.enum(["header", "tls-layer"]).default("tls-layer"),
				/** Header name carrying the forwarded leaf cert (header source only). */
				"cert-header": z.string().min(1).default("x-forwarded-client-cert"),
				/** Dialect for the forwarded-cert header (header source only). */
				"cert-header-dialect": z.enum(["envoy", "plain-pem"]).default("envoy"),
				/**
				 * Peer addresses allowed to forward a client certificate header
				 * (header source only). Each entry is an IPv4 / IPv6 literal or
				 * the `"loopback"` keyword. Empty by default — nothing is trusted
				 * implicitly — and `source = "header"` with an empty list fails
				 * boot.
				 */
				"trusted-proxies": z.array(z.string()).readonly().default([]),
				/** Trust posture: "self-signed" accepts any well-formed cert; "pki" requires trusted-cas. */
				mode: z.enum(["self-signed", "pki"]).default("self-signed"),
				/** Trust anchors for mode = "pki". Each entry: literal PEM or "file:<path>". */
				"trusted-cas": z.array(z.string()).readonly().default([]),
			})
			.default(() => ({
				enabled: false,
				source: "tls-layer" as const,
				"cert-header": "x-forwarded-client-cert",
				"cert-header-dialect": "envoy" as const,
				"trusted-proxies": [],
				mode: "self-signed" as const,
				"trusted-cas": [],
			})),
	}),
});

// ---------------------------------------------------------------------------
// Module manifest
// ---------------------------------------------------------------------------

/**
 * Declarative manifest for the mTLS package.
 *
 * When `config.oauth.mtls.enabled` is `false` (the secure default), the
 * mechanism factory returns `null` and core's synthesizer filters it out —
 * no mTLS mechanism is included in the composed `tokenBindingMw`. When
 * `enabled` is `true`, the factory returns the configured mTLS mechanism
 * for core to compose alongside any other binding-mechanism modules
 * (DPoP, future) under the unified `oauth.tokenBinding.dispatch-policy`.
 *
 * Boot-time fail-loud invariants (Phase 3 spec §11.2, extended by issue #280):
 *
 *   0. `source === "header"` + empty `trusted-proxies` → throw. A forwarded
 *      certificate header is an assertion made by whoever opened the
 *      connection; without an allowlist naming which peers may make it, the
 *      header is the credential and anyone routable to this process can mint
 *      one. RFC 8705 §3 requires the certificate to come from the TLS layer or
 *      from an authenticated trusted proxy — this is what makes the second
 *      arm true.
 *
 *   1. `mode === "pki"` + empty `trusted-cas` → throw. Without trusted CAs,
 *      chain validation cannot proceed. Failing boot directs the operator
 *      straight to the misconfig instead of either silently failing open
 *      (no validation) or failing closed on every request (no audit signal).
 *
 *   2. `mode === "pki"` + `source === "tls-layer"` → throw (Codex Round 1
 *      Important #1 fix). The narrow PKI mode requires the intermediate
 *      chain (XFCC `Chain=` parameter); TLS-layer full-chain extraction is
 *      deferred to a future phase (§1.3). Rejecting at boot avoids the same
 *      silent-fail ambiguity.
 *
 * `createMtlsMechanism` re-enforces both invariants defensively, but the
 * module fires first and produces operator-friendly error messages.
 *
 * Migrated from the `grantMiddleware` contribution slot (Phase 3 Sub-PR 3b)
 * to `tokenBindingMechanisms` (cross-mechanism dispatch refactor, 2026-05-19)
 * so the `DispatchPolicy` can arbitrate cross-module when both DPoP and
 * mTLS are installed.
 *
 * See ADR `packages/core/docs/adr/2026-05-20-token-binding-first-class-abstraction.md`
 * for the cross-mechanism design rationale.
 */
export const mtlsModule = defineModule<"config", "logger">({
	name: "mtls",
	configSchema: mtlsConfigSchema,
	requires: ["config"],
	optional: ["logger"],
	contributes: {
		// RFC 8705 §3.3 authorization-server metadata (#283). When enabled, this
		// module binds the issued access token to the client certificate
		// (`cnf["x5t#S256"]`), and a client has no other way to discover that the
		// AS will do so.
		//
		// Not gated on `source`: #280 made the certificate come from the TLS layer
		// by default and put a trusted-proxy allowlist behind the forwarded-header
		// path, but both paths produce the same confirmation claim on the same
		// token. The RFC 8705 §3.3 flag describes the TOKEN, not the transport the
		// certificate arrived over.
		//
		// Absent (rather than `false`) when disabled — RFC 8705 §3.3 already
		// defines omission as `false`, and an omitted field cannot collide with
		// another contributor's value in core's aggregator.
		//
		// This is deliberately the ONLY field contributed: this package implements
		// RFC 8705 §3 token binding, NOT §2 mTLS client authentication, so
		// `tls_client_auth` / `self_signed_tls_client_auth` must never appear in
		// `token_endpoint_auth_methods_supported` — the token endpoint does not
		// accept a certificate as a client credential.
		discoveryMetadata: [
			(deps) => {
				const mtls = (deps.config as { oauth?: { mtls?: { enabled?: unknown } } }).oauth?.mtls;
				if (mtls?.enabled !== true) return {};
				return { metadata: { tls_client_certificate_bound_access_tokens: true } };
			},
		],
		tokenBindingMechanisms: [
			(deps) => {
				const mtlsConfig = (deps.config as { oauth?: { mtls?: { enabled?: unknown } } }).oauth
					?.mtls;
				if (mtlsConfig?.enabled !== true) {
					// Disabled by config — no mechanism contributed.
					return null;
				}

				const typedConfig = deps.config as unknown as {
					oauth: {
						mtls: {
							enabled: boolean;
							source: "header" | "tls-layer";
							"cert-header": string;
							"cert-header-dialect": "envoy" | "plain-pem";
							"trusted-proxies": readonly string[];
							mode: "self-signed" | "pki";
							"trusted-cas": readonly string[];
						};
					};
				};

				const cfg = typedConfig.oauth.mtls;

				// --- Boot-time fail-loud check 0: header source requires an
				// explicit trusted-proxy allowlist (issue #280). ---
				//
				// Without it the forwarded header IS the credential: any client
				// that can open a connection to this process can assert any
				// certificate. Fail boot rather than run a deployment whose mTLS
				// binding proves nothing.
				if (cfg.source === "header" && (cfg["trusted-proxies"]?.length ?? 0) === 0) {
					throw new Error(
						'mtlsModule: config.oauth.mtls.source = "header" requires a non-empty ' +
							"oauth.mtls.trusted-proxies allowlist. A forwarded client-certificate header " +
							"is only evidence of a TLS handshake when the hop that forwarded it is " +
							'authenticated. List the reverse proxy\'s peer address (or "loopback" for a ' +
							'sidecar), or use source = "tls-layer" and terminate TLS at this process.',
					);
				}

				// --- Boot-time fail-loud check 1: PKI mode requires trusted-cas. ---
				if (cfg.mode === "pki" && cfg["trusted-cas"].length === 0) {
					throw new Error(
						'mtlsModule: config.oauth.mtls.mode = "pki" requires a non-empty oauth.mtls.trusted-cas. ' +
							"Without trusted CAs, chain validation cannot proceed.",
					);
				}

				// --- Boot-time fail-loud check 2: PKI + tls-layer is not supported. ---
				if (cfg.mode === "pki" && cfg.source === "tls-layer") {
					throw new Error(
						'mtlsModule: config.oauth.mtls.mode = "pki" with source = "tls-layer" is not supported in Phase 3. ' +
							"The narrow PKI mode requires the intermediate chain (e.g., the Envoy XFCC " +
							"Chain= parameter); TLS-layer full-chain extraction is deferred to a future " +
							'phase. Use source = "header" with cert-header-dialect = "envoy" for PKI mode, ' +
							'or use mode = "self-signed" with TLS-layer source.',
					);
				}

				return createMtlsMechanism({
					source: cfg.source,
					certHeader: cfg["cert-header"],
					certHeaderDialect: cfg["cert-header-dialect"],
					trustedProxies: cfg["trusted-proxies"],
					mode: cfg.mode,
					trustedCas: cfg["trusted-cas"],
					logger: deps.logger,
				});
			},
		],
	},
});
