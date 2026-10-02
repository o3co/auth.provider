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
 * `tls_client_certificate_bound_access_tokens` to discovery, both built from
 * its own section, `mtls {}`, parsed with {@link mtlsConfigSchema} before any
 * factory runs. `mtls.enabled` (off in reference.conf) is the module's switch
 * (`section.isEnabled`): off, the module registers nothing. A key still
 * written at `oauth.mtls`, the section's old path, refuses boot naming the
 * new one. The settings under `core.tokenBinding`, the dispatch policy among
 * them, are core's.
 *
 * Secure defaults: the certificate comes from the TLS layer
 * (`source = "tls-layer"`), and the forwarded-header source requires an
 * explicit `trustedProxies` allowlist.
 */

import {
	coerceBooleanFromEnv,
	defineModule,
	wholeNumberInRangeFromEnv,
} from "@o3co/auth-provider-core";
import { z } from "zod";
import { createMtlsMechanism, type MtlsMechanismOptions } from "./extractor.mjs";
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
 * The schema of `mtls {}`, the module's own section. Strict at every level: a
 * key it does not declare refuses boot. Each scalar leaf reads the string an
 * environment variable carries.
 */
export const mtlsConfigSchema = z
	.object({
		/** The module's switch: false (default), and the module registers nothing. */
		enabled: coerceBooleanFromEnv.default(false),
		/**
		 * Where the leaf cert comes from. Defaults to `"tls-layer"`: RFC 8705 §3
		 * wants the certificate from the transport, and a forwarded header
		 * substitutes only when the forwarding hop is authenticated
		 * (`trustedProxies`).
		 */
		source: z.enum(["header", "tls-layer"]).default("tls-layer"),
		/** Header name carrying the forwarded leaf cert (header source only). */
		certHeader: z.string().min(1).default("x-forwarded-client-cert"),
		/** Dialect for the forwarded-cert header (header source only). */
		certHeaderDialect: z.enum(["envoy", "plain-pem"]).default("envoy"),
		/**
		 * Peer addresses allowed to forward a client certificate header (header
		 * source only). Each entry is an IPv4 / IPv6 literal, a CIDR range or a
		 * named range. Empty by default — nothing is trusted implicitly — and
		 * `source = "header"` with an empty list fails boot.
		 */
		trustedProxies: z.array(z.string()).readonly().default([]),
		/**
		 * Trust posture. `"self-signed"` accepts any well-formed cert; `"pki"`
		 * runs the narrow chain walk; `"full-pki"` runs RFC 5280 path validation
		 * with revocation. The latter two require `trustedCas`.
		 */
		mode: z.enum(["self-signed", "pki", "full-pki"]).default("self-signed"),
		/** Trust anchors for mode = "pki" / "full-pki". Each entry: literal PEM or "file:<path>". */
		trustedCas: z.array(z.string()).readonly().default([]),
		/**
		 * Settings for `mode = "full-pki"` only. `revocation.mode` and
		 * `revocation.onUnavailable` have no defaults: what to do when revocation
		 * status cannot be obtained has no universally right answer, so the
		 * operator must write one down.
		 */
		fullPki: z
			.object({
				/** Maximum certificates in a path, leaf and anchor included. */
				maxChainDepth: wholeNumberInRangeFromEnv(2, 16).default(FULL_PKI_DEFAULT_MAX_CHAIN_DEPTH),
				/** Signature algorithms permitted at every hop. */
				signatureAlgorithms: z
					.array(z.enum(SIGNATURE_ALGORITHM_NAMES as unknown as [string, ...string[]]))
					.readonly()
					.default(DEFAULT_SIGNATURE_ALGORITHMS as unknown as string[]),
				/** Minimum RSA modulus in bits. Ignored for EC and EdDSA keys. */
				minRsaKeyBits: wholeNumberInRangeFromEnv(1024).default(FULL_PKI_DEFAULT_MIN_RSA_KEY_BITS),
				revocation: z
					.object({
						/**
						 * `"crl"` fetches distribution points, `"ocsp"` asks the responders
						 * named in `authorityInfoAccess`, `"both"` asks OCSP first and falls
						 * back to the CRL when the responder cannot answer; an OCSP
						 * `unknown` is an answer, which the CRL may only turn into a
						 * refusal. `"disabled"` is an explicit statement, not an omission —
						 * see the boot check below.
						 */
						mode: z.enum(["crl", "ocsp", "both", "disabled"]),
						onUnavailable: z.enum(["reject", "allow"]),
						/** Hosts revocation material may be fetched from. */
						allowedHosts: z.array(z.string()).readonly().default([]),
						fetchTimeoutMs: wholeNumberInRangeFromEnv(1).default(3000),
						cacheTtlSeconds: wholeNumberInRangeFromEnv(0).default(3600),
						maxResponseBytes: wholeNumberInRangeFromEnv(1).default(1_048_576),
						/**
						 * Refuse an OCSP response that does not echo the request's nonce
						 * (RFC 6960 §4.4.1). On by default: without it a captured `good`
						 * replays until its `nextUpdate`. Turn it off only for a responder
						 * that omits the nonce (RFC 8954); freshness then rests on
						 * `thisUpdate` / `nextUpdate` alone.
						 */
						ocspRequireNonce: coerceBooleanFromEnv.default(true),
					})
					.strict()
					.optional(),
			})
			.strict()
			.optional(),
	})
	.strict()
	.default(() => ({
		enabled: false,
		source: "tls-layer" as const,
		certHeader: "x-forwarded-client-cert",
		certHeaderDialect: "envoy" as const,
		trustedProxies: [],
		mode: "self-signed" as const,
		trustedCas: [],
	}));

/** The `mtls` section as its schema leaves it. */
type MtlsSection = z.output<typeof mtlsConfigSchema>;

type FullPkiSection = NonNullable<MtlsSection["fullPki"]>;

/** `mtls.fullPki`, its revocation decided, in the shape `createMtlsMechanism` takes it. */
const fullPkiOption = (
	fullPki: FullPkiSection,
	revocation: NonNullable<FullPkiSection["revocation"]>,
): NonNullable<MtlsMechanismOptions["fullPki"]> => ({
	"max-chain-depth": fullPki.maxChainDepth,
	"signature-algorithms": fullPki.signatureAlgorithms as readonly SignatureAlgorithmName[],
	"min-rsa-key-bits": fullPki.minRsaKeyBits,
	revocation: {
		mode: revocation.mode,
		"on-unavailable": revocation.onUnavailable,
		"allowed-hosts": revocation.allowedHosts,
		"fetch-timeout-ms": revocation.fetchTimeoutMs,
		"cache-ttl-seconds": revocation.cacheTtlSeconds,
		"max-response-bytes": revocation.maxResponseBytes,
		"ocsp-require-nonce": revocation.ocspRequireNonce,
	},
});

// ---------------------------------------------------------------------------
// Module manifest
// ---------------------------------------------------------------------------

/**
 * Declarative manifest for the mTLS package. Disabled (the default), the
 * module registers nothing; enabled, core composes it with any other binding mechanisms under
 * `core.tokenBinding.dispatchPolicy` (see
 * `packages/core/docs/adr/2026-05-20-token-binding-first-class-abstraction.md`).
 *
 * Boot refuses:
 * - `source = "header"` with no `trustedProxies`: the forwarded header would
 *   be the credential, mintable by anyone who can reach this process (RFC 8705
 *   §3 requires the TLS layer or an authenticated proxy);
 * - `mode = "pki"` or `"full-pki"` with no `trustedCas`;
 * - `mode = "full-pki"` without explicit `revocation.mode` and
 *   `.onUnavailable`, or with a fetching mode and no `allowedHosts`;
 * - `mode = "pki"` with `source = "tls-layer"`: the narrow walk takes its
 *   intermediates from the XFCC `Chain=` parameter.
 *
 * `createMtlsMechanism` re-checks these defensively; the module fails first,
 * with operator-friendly messages.
 */
export const mtlsModule = defineModule<never, "logger", typeof mtlsConfigSchema>({
	name: "mtls",
	// The package's `config/reference.conf` holds this section's defaults. No
	// variable binds a key of it, so the refusal of an old path names none.
	section: {
		schema: mtlsConfigSchema,
		reference: new URL("../config/reference.conf", import.meta.url),
		relocatedFrom: {
			"oauth.mtls": { to: "", environmentVariable: null },
			"oauth.mtls.cert-header": { to: "certHeader", environmentVariable: null },
			"oauth.mtls.cert-header-dialect": { to: "certHeaderDialect", environmentVariable: null },
			"oauth.mtls.trusted-proxies": { to: "trustedProxies", environmentVariable: null },
			"oauth.mtls.trusted-cas": { to: "trustedCas", environmentVariable: null },
			"oauth.mtls.full-pki": { to: "fullPki", environmentVariable: null },
			"oauth.mtls.full-pki.max-chain-depth": {
				to: "fullPki.maxChainDepth",
				environmentVariable: null,
			},
			"oauth.mtls.full-pki.signature-algorithms": {
				to: "fullPki.signatureAlgorithms",
				environmentVariable: null,
			},
			"oauth.mtls.full-pki.min-rsa-key-bits": {
				to: "fullPki.minRsaKeyBits",
				environmentVariable: null,
			},
			"oauth.mtls.full-pki.revocation.on-unavailable": {
				to: "fullPki.revocation.onUnavailable",
				environmentVariable: null,
			},
			"oauth.mtls.full-pki.revocation.allowed-hosts": {
				to: "fullPki.revocation.allowedHosts",
				environmentVariable: null,
			},
			"oauth.mtls.full-pki.revocation.fetch-timeout-ms": {
				to: "fullPki.revocation.fetchTimeoutMs",
				environmentVariable: null,
			},
			"oauth.mtls.full-pki.revocation.cache-ttl-seconds": {
				to: "fullPki.revocation.cacheTtlSeconds",
				environmentVariable: null,
			},
			"oauth.mtls.full-pki.revocation.max-response-bytes": {
				to: "fullPki.revocation.maxResponseBytes",
				environmentVariable: null,
			},
			"oauth.mtls.full-pki.revocation.ocsp-require-nonce": {
				to: "fullPki.revocation.ocspRequireNonce",
				environmentVariable: null,
			},
		},
		isEnabled: (section) => section.enabled,
	},
	optional: ["logger"],
	contributes: {
		// RFC 8705 §3.3: a client has no other way to learn that access tokens
		// are bound to its certificate (`cnf["x5t#S256"]`). Not gated on
		// `source`: the flag describes the token, not the transport. Never
		// `false`: a disabled module registers nothing, and omission already
		// means `false`. The only field contributed:
		// this package implements §3 token binding, not §2 client
		// authentication, so `tls_client_auth` must never be advertised.
		discoveryMetadata: [() => ({ metadata: { tls_client_certificate_bound_access_tokens: true } })],
		tokenBindingMechanisms: [
			(deps) => {
				const cfg = deps.section;
				// --- Boot-time fail-loud check 0: header source requires an
				// explicit trusted-proxy allowlist. ---
				//
				// Without it the forwarded header IS the credential: anyone who can
				// connect to this process can assert any certificate.
				if (cfg.source === "header" && cfg.trustedProxies.length === 0) {
					throw new Error(
						'mtlsModule: mtls.source = "header" requires a non-empty ' +
							"mtls.trustedProxies allowlist. A forwarded client-certificate header " +
							"is only evidence of a TLS handshake when the hop that forwarded it is " +
							'authenticated. List the reverse proxy\'s peer address (or "loopback" for a ' +
							'sidecar), or use source = "tls-layer" and terminate TLS at this process.',
					);
				}

				// --- Boot-time fail-loud check 1: PKI mode requires trustedCas. ---
				if ((cfg.mode === "pki" || cfg.mode === "full-pki") && cfg.trustedCas.length === 0) {
					throw new Error(
						`mtlsModule: mtls.mode = "${cfg.mode}" requires a non-empty mtls.trustedCas. ` +
							"Without trusted CAs, chain validation cannot proceed.",
					);
				}

				// --- Boot-time fail-loud checks for full-pki. ---
				//
				// The revocation settings have no defaults: "the CRL endpoint is
				// unreachable" and "the certificate is not revoked" are different
				// facts, and only the operator can decide which one to act on. The
				// mechanism reads `fullPki` in this mode alone.
				let fullPkiOptions: MtlsMechanismOptions["fullPki"];
				if (cfg.mode === "full-pki") {
					const fullPki = cfg.fullPki;
					if (fullPki?.revocation === undefined) {
						throw new Error(
							'mtlsModule: mtls.mode = "full-pki" requires ' +
								"mtls.fullPki.revocation.mode and .onUnavailable to be set " +
								'explicitly. Set mode = "crl", "ocsp" or "both" to check revocation, ' +
								'or mode = "disabled" ' +
								"to state that this deployment accepts that a revoked certificate " +
								"keeps binding tokens until it expires. There is no default because " +
								"both are defensible and only the operator knows which applies.",
						);
					}
					if (
						fullPki.revocation.mode !== "disabled" &&
						fullPki.revocation.allowedHosts.length === 0
					) {
						// An OCSP responder URL is a destination inside a certificate
						// exactly as a CRL distribution point is: the same layer applies.
						throw new Error(
							`mtlsModule: mtls.fullPki.revocation.mode = "${fullPki.revocation.mode}" requires a ` +
								"non-empty mtls.fullPki.revocation.allowedHosts. A CRL " +
								"distribution point or an OCSP responder is a URL inside a " +
								"certificate, so fetching one makes this process issue a request " +
								"to a destination someone else chose. List the hosts your CA " +
								"publishes CRLs on or answers OCSP from — the same separation " +
								"mtls.trustedProxies draws for forwarded headers.",
						);
					}
					fullPkiOptions = fullPkiOption(fullPki, fullPki.revocation);
				}

				// --- Boot-time fail-loud check 2: narrow PKI + tls-layer is not supported. ---
				//
				// `mode = "pki"` takes its intermediates from the XFCC `Chain=`
				// parameter; `full-pki` reads the chain from the TLS session
				// (`tlsChain.mts`) and is not restricted.
				if (cfg.mode === "pki" && cfg.source === "tls-layer") {
					throw new Error(
						'mtlsModule: mtls.mode = "pki" with source = "tls-layer" is not supported. ' +
							"The narrow PKI mode takes the intermediate chain from the forwarded " +
							"certificate header (e.g., the Envoy XFCC Chain= parameter), never from the TLS " +
							'session. Use source = "header" with certHeaderDialect = "envoy" for PKI mode, ' +
							'mode = "full-pki", which reads the chain from the TLS session, or ' +
							'mode = "self-signed" with TLS-layer source.',
					);
				}

				return createMtlsMechanism({
					source: cfg.source,
					certHeader: cfg.certHeader,
					certHeaderDialect: cfg.certHeaderDialect,
					trustedProxies: cfg.trustedProxies,
					mode: cfg.mode,
					trustedCas: cfg.trustedCas,
					...(fullPkiOptions === undefined ? {} : { fullPki: fullPkiOptions }),
					logger: deps.logger,
				});
			},
		],
	},
});
