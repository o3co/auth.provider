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
 * mTLS module manifest: contributes the RFC 8705 certificate-binding
 * mechanism to core's `tokenBindingMechanisms` slot, and
 * `tls_client_certificate_bound_access_tokens` to discovery, both only while
 * `oauth.mtls.enabled` (off by default in reference.conf). The settings under
 * `oauth.tokenBinding`, the dispatch policy among them, are core's.
 *
 * Secure defaults: the certificate comes from the TLS layer
 * (`source = "tls-layer"`), and the forwarded-header source requires an
 * explicit `trusted-proxies` allowlist.
 */

import { defineModule } from "@o3co/auth-provider-core";
import { z } from "zod";
import { createMtlsMechanism } from "./extractor.mjs";
import {
	DEFAULT_SIGNATURE_ALGORITHMS,
	SIGNATURE_ALGORITHM_NAMES,
	type SignatureAlgorithmName,
} from "./fullPki/algorithms.mjs";
import {
	FULL_PKI_DEFAULT_MAX_CHAIN_DEPTH,
	FULL_PKI_DEFAULT_MIN_RSA_KEY_BITS,
} from "./fullPki/defaults.mjs";

// ---------------------------------------------------------------------------
// Config schema
// ---------------------------------------------------------------------------

/**
 * Zod schema for the `oauth.mtls` config slice. Keys are kebab-case to match
 * reference.conf verbatim (`config.oauth.mtls["cert-header"]`).
 * `oauth.tokenBinding.dispatch-policy` belongs to core's schema, since it
 * spans every binding mechanism.
 */
export const mtlsConfigSchema = z.object({
	oauth: z.object({
		mtls: z
			.object({
				/** When false (default), mtlsModule contributes null — no mTLS middleware mounted. */
				enabled: z.boolean().default(false),
				/**
				 * Where the leaf cert comes from. Defaults to `"tls-layer"`: RFC 8705
				 * §3 wants the certificate from the transport, and a forwarded header
				 * substitutes only when the forwarding hop is authenticated
				 * (`trusted-proxies`).
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
				/**
				 * Trust posture. `"self-signed"` accepts any well-formed cert;
				 * `"pki"` runs the narrow chain walk; `"full-pki"` runs RFC 5280
				 * path validation with revocation. The latter two require
				 * `trusted-cas`.
				 */
				mode: z.enum(["self-signed", "pki", "full-pki"]).default("self-signed"),
				/** Trust anchors for mode = "pki" / "full-pki". Each entry: literal PEM or "file:<path>". */
				"trusted-cas": z.array(z.string()).readonly().default([]),
				/**
				 * Settings for `mode = "full-pki"` only. `revocation.mode` and
				 * `revocation.on-unavailable` have no defaults: what to do when
				 * revocation status cannot be obtained has no universally right
				 * answer, so the operator must write one down.
				 */
				"full-pki": z
					.object({
						/** Maximum certificates in a path, leaf and anchor included. */
						"max-chain-depth": z
							.number()
							.int()
							.min(2)
							.max(16)
							.default(FULL_PKI_DEFAULT_MAX_CHAIN_DEPTH),
						/** Signature algorithms permitted at every hop. */
						"signature-algorithms": z
							.array(z.enum(SIGNATURE_ALGORITHM_NAMES as unknown as [string, ...string[]]))
							.readonly()
							.default(DEFAULT_SIGNATURE_ALGORITHMS as unknown as string[]),
						/** Minimum RSA modulus in bits. Ignored for EC and EdDSA keys. */
						"min-rsa-key-bits": z
							.number()
							.int()
							.min(1024)
							.default(FULL_PKI_DEFAULT_MIN_RSA_KEY_BITS),
						revocation: z
							.object({
								/**
								 * `"crl"` fetches distribution points, `"ocsp"` asks the
								 * responders named in `authorityInfoAccess`, `"both"` asks OCSP
								 * first and falls back to the CRL when the responder cannot
								 * answer; an OCSP `unknown` is an answer, which the CRL may only
								 * turn into a refusal. `"disabled"` is an explicit statement,
								 * not an omission — see the boot check below.
								 */
								mode: z.enum(["crl", "ocsp", "both", "disabled"]),
								"on-unavailable": z.enum(["reject", "allow"]),
								/** Hosts revocation material may be fetched from. */
								"allowed-hosts": z.array(z.string()).readonly().default([]),
								"fetch-timeout-ms": z.number().int().min(1).default(3000),
								"cache-ttl-seconds": z.number().int().min(0).default(3600),
								"max-response-bytes": z.number().int().min(1).default(1_048_576),
								/**
								 * Refuse an OCSP response that does not echo the request's
								 * nonce (RFC 6960 §4.4.1). On by default: without it a captured
								 * `good` replays until its `nextUpdate`. Turn it off only for a
								 * responder that omits the nonce (RFC 8954); freshness then
								 * rests on `thisUpdate` / `nextUpdate` alone.
								 */
								"ocsp-require-nonce": z.boolean().default(true),
							})
							.optional(),
					})
					.optional(),
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
 * The `oauth.mtls` section: its schema, the package's `config/reference.conf`
 * holding its defaults, and its path. `configSchema` declares the same path
 * with the same schema until the section moves under the module's name, so
 * boot parses the value twice (idempotently).
 */
const MTLS_SECTION_SCHEMA = mtlsConfigSchema.shape.oauth.shape.mtls;

/**
 * Declarative manifest for the mTLS package. Disabled (the default), the
 * mechanism factory returns `null` and core leaves it out; enabled, core
 * composes it with any other binding mechanisms under
 * `oauth.tokenBinding.dispatch-policy` (see
 * `packages/core/docs/adr/2026-05-20-token-binding-first-class-abstraction.md`).
 *
 * Boot refuses:
 * - `source = "header"` with no `trusted-proxies`: the forwarded header would
 *   be the credential, mintable by anyone who can reach this process (RFC 8705
 *   §3 requires the TLS layer or an authenticated proxy);
 * - `mode = "pki"` or `"full-pki"` with no `trusted-cas`;
 * - `mode = "full-pki"` without explicit `revocation.mode` and
 *   `.on-unavailable`, or with a fetching mode and no `allowed-hosts`;
 * - `mode = "pki"` with `source = "tls-layer"`: the narrow walk takes its
 *   intermediates from the XFCC `Chain=` parameter.
 *
 * `createMtlsMechanism` re-checks these defensively; the module fails first,
 * with operator-friendly messages.
 */
export const mtlsModule = defineModule<"config", "logger", typeof MTLS_SECTION_SCHEMA>({
	name: "mtls",
	configSchema: mtlsConfigSchema,
	section: {
		schema: MTLS_SECTION_SCHEMA,
		reference: new URL("../config/reference.conf", import.meta.url),
		at: "oauth.mtls",
	},
	requires: ["config"],
	optional: ["logger"],
	contributes: {
		// RFC 8705 §3.3: a client has no other way to learn that access tokens
		// are bound to its certificate (`cnf["x5t#S256"]`). Not gated on
		// `source`: the flag describes the token, not the transport. Omitted
		// rather than `false` when disabled — omission already means `false`,
		// and cannot collide in core's aggregator. The only field contributed:
		// this package implements §3 token binding, not §2 client
		// authentication, so `tls_client_auth` must never be advertised.
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
							mode: "self-signed" | "pki" | "full-pki";
							"trusted-cas": readonly string[];
							"full-pki"?: {
								"max-chain-depth"?: number;
								"signature-algorithms"?: readonly SignatureAlgorithmName[];
								"min-rsa-key-bits"?: number;
								revocation?: {
									mode: "crl" | "ocsp" | "both" | "disabled";
									"on-unavailable": "reject" | "allow";
									"allowed-hosts": readonly string[];
									"fetch-timeout-ms": number;
									"cache-ttl-seconds": number;
									"max-response-bytes": number;
									"ocsp-require-nonce": boolean;
								};
							};
						};
					};
				};

				const cfg = typedConfig.oauth.mtls;

				// --- Boot-time fail-loud check 0: header source requires an
				// explicit trusted-proxy allowlist. ---
				//
				// Without it the forwarded header IS the credential: anyone who can
				// connect to this process can assert any certificate.
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
				if ((cfg.mode === "pki" || cfg.mode === "full-pki") && cfg["trusted-cas"].length === 0) {
					throw new Error(
						`mtlsModule: config.oauth.mtls.mode = "${cfg.mode}" requires a non-empty oauth.mtls.trusted-cas. ` +
							"Without trusted CAs, chain validation cannot proceed.",
					);
				}

				// --- Boot-time fail-loud checks for full-pki. ---
				//
				// The revocation settings have no defaults: "the CRL endpoint is
				// unreachable" and "the certificate is not revoked" are different
				// facts, and only the operator can decide which one to act on.
				if (cfg.mode === "full-pki") {
					const fullPki = cfg["full-pki"];
					if (fullPki?.revocation === undefined) {
						throw new Error(
							'mtlsModule: config.oauth.mtls.mode = "full-pki" requires ' +
								"oauth.mtls.full-pki.revocation.mode and .on-unavailable to be set " +
								'explicitly. Set mode = "crl", "ocsp" or "both" to check revocation, ' +
								'or mode = "disabled" ' +
								"to state that this deployment accepts that a revoked certificate " +
								"keeps binding tokens until it expires. There is no default because " +
								"both are defensible and only the operator knows which applies.",
						);
					}
					if (
						fullPki.revocation.mode !== "disabled" &&
						fullPki.revocation["allowed-hosts"].length === 0
					) {
						// An OCSP responder URL is a destination inside a certificate
						// exactly as a CRL distribution point is: the same layer applies.
						throw new Error(
							`mtlsModule: oauth.mtls.full-pki.revocation.mode = "${fullPki.revocation.mode}" requires a ` +
								"non-empty oauth.mtls.full-pki.revocation.allowed-hosts. A CRL " +
								"distribution point or an OCSP responder is a URL inside a " +
								"certificate, so fetching one makes this process issue a request " +
								"to a destination someone else chose. List the hosts your CA " +
								"publishes CRLs on or answers OCSP from — the same separation " +
								"oauth.mtls.trusted-proxies draws for forwarded headers.",
						);
					}
				}

				// --- Boot-time fail-loud check 2: narrow PKI + tls-layer is not supported. ---
				//
				// `mode = "pki"` takes its intermediates from the XFCC `Chain=`
				// parameter; `full-pki` reads the chain from the TLS session
				// (`tlsChain.mts`) and is not restricted.
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
					...(cfg["full-pki"] ? { fullPki: cfg["full-pki"] } : {}),
					logger: deps.logger,
				});
			},
		],
	},
});
