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
 * `createMtlsMechanism`: the RFC 8705 §3 client-certificate-bound access-token
 * mechanism as a `TokenBindingMechanism`. `extract(req)` takes the certificate
 * from the TLS layer (or a header from an allowlisted proxy), checks its
 * validity window and, in the PKI modes, its chain, and returns its
 * `x5t#S256` thumbprint (RFC 8705 §3.1). The steps are numbered in the code.
 */

import { X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import {
	createTrustedProxyMatcher,
	type Logger,
	lineSafeText,
	loggableError,
	type TokenBindingMechanism,
} from "@o3co/auth-provider-core";
import type { Request } from "express";
import { MtlsError } from "./errors.mjs";
import type { SignatureAlgorithmName } from "./fullPki/algorithms.mjs";
import { type FullPkiTuning, resolveFullPkiTuning } from "./fullPki/defaults.mjs";
import { createFullPkiValidator, type FullPkiValidator } from "./fullPki/validate.mjs";
import { type CertHeaderDialect, parseEnvoyXfccHeader, parsePlainPemHeader } from "./headers.mjs";
import { pemToDer } from "./pem.mjs";
import { validateCertChain } from "./pki.mjs";
import { computeCertThumbprint } from "./thumbprint.mjs";
import { type DetailedPeerCertificateLike, peerChainFrom } from "./tlsChain.mjs";

// ---------------------------------------------------------------------------
// Public type
// ---------------------------------------------------------------------------

/** Options for {@link createMtlsMechanism}. */
export interface MtlsMechanismOptions {
	/**
	 * Where the leaf certificate comes from. Defaults to `"tls-layer"` —
	 * RFC 8705 §3 wants the certificate from the transport, and a forwarded
	 * header is only equivalent when the forwarding hop is authenticated.
	 *
	 * `"header"` therefore requires a non-empty {@link trustedProxies}.
	 */
	readonly source?: "header" | "tls-layer";
	readonly certHeader?: string;
	readonly certHeaderDialect?: CertHeaderDialect;
	/**
	 * Peer addresses permitted to forward a client certificate header, in
	 * core's trusted-proxy vocabulary (also Express's `trust proxy`): an IP
	 * literal, a CIDR range, or `loopback` / `linklocal` / `uniquelocal`.
	 * Required (non-empty) when `source === "header"`, ignored otherwise.
	 */
	readonly trustedProxies?: readonly string[];
	readonly mode: "self-signed" | "pki" | "full-pki";
	readonly trustedCas?: readonly string[];
	/**
	 * Settings for `mode = "full-pki"`, required in that mode. `mtlsModule`
	 * refuses boot without the revocation decision; a hand-built composition
	 * root without it is caught at construction.
	 */
	readonly fullPki?: {
		readonly "max-chain-depth"?: number;
		readonly "signature-algorithms"?: readonly SignatureAlgorithmName[];
		readonly "min-rsa-key-bits"?: number;
		readonly revocation?: {
			readonly mode: "crl" | "ocsp" | "both" | "disabled";
			readonly "on-unavailable": "reject" | "allow";
			readonly "allowed-hosts": readonly string[];
			readonly "fetch-timeout-ms": number;
			readonly "cache-ttl-seconds": number;
			readonly "max-response-bytes": number;
			/** OCSP only. Defaults to `true` (RFC 8954). */
			readonly "ocsp-require-nonce"?: boolean;
		};
	};
	readonly logger?: Logger;
}

// ---------------------------------------------------------------------------
// Constants — defaults
// ---------------------------------------------------------------------------

const DEFAULT_CERT_HEADER = "x-forwarded-client-cert";
const DEFAULT_DIALECT: CertHeaderDialect = "envoy";

/**
 * The certificate comes from the TLS layer unless the operator says otherwise.
 * RFC 8705 §3 requires it to come from the TLS layer or from an authenticated
 * trusted proxy, and only the first is safe to assume: a header trusted from
 * anyone lets anyone who can reach the process assert any client identity.
 */
const DEFAULT_SOURCE = "tls-layer" as const;

// ---------------------------------------------------------------------------
// Internal — minimal duck-typed shape for `req.socket.getPeerCertificate()`
// ---------------------------------------------------------------------------

/**
 * The minimum of Node's TLSSocket this file uses, duck-typed so a non-TLS
 * socket needs no narrowing to `tls.TLSSocket`.
 */
interface TlsLikeSocket {
	getPeerCertificate?: (detailed?: boolean) => DetailedPeerCertificateLike | undefined;
}

const isTlsLikeSocket = (s: unknown): s is TlsLikeSocket =>
	typeof s === "object" &&
	s !== null &&
	typeof (s as { getPeerCertificate?: unknown }).getPeerCertificate === "function";

/**
 * The address of the peer that opened this connection. Never `req.ip`, which
 * Express rewrites from `X-Forwarded-For` under `trust proxy`: that would
 * authenticate a header with another header. `undefined` (destroyed socket,
 * Unix-domain listener) is treated as untrusted by the matcher.
 */
const peerAddressOf = (req: Request): string | undefined =>
	(req.socket as { remoteAddress?: string } | undefined)?.remoteAddress;

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Translate the `full-pki` config slice into the validator's options.
 *
 * The revocation block has no defaults by design (README, "Revocation has no
 * defaults, on purpose"), so its absence means a composition root bypassed
 * the module manifest, and construction is refused rather than choosing
 * either policy silently.
 */
const buildFullPkiValidator = (
	options: MtlsMechanismOptions,
	trustedCas: readonly X509Certificate[],
	tuning: FullPkiTuning,
): FullPkiValidator => {
	// `tuning` comes from the caller so the peer-chain walk and the validator
	// cannot read the chain depth twice and disagree.
	const cfg = options.fullPki;
	if (cfg?.revocation === undefined) {
		throw new Error(
			'createMtlsMechanism: mode = "full-pki" requires fullPki.revocation.mode and ' +
				".on-unavailable. There is no default: whether an unreachable CRL endpoint " +
				"blocks logins or is waved through is a decision only the operator can make.",
		);
	}
	const revocation = cfg.revocation;
	return createFullPkiValidator({
		trustedCas,
		algorithms: {
			signatureAlgorithms: tuning.signatureAlgorithms,
			minRsaKeyBits: tuning.minRsaKeyBits,
		},
		maxChainDepth: tuning.maxChainDepth,
		revocation:
			revocation.mode === "disabled"
				? { mode: "disabled" }
				: {
						mode: revocation.mode,
						onUnavailable: revocation["on-unavailable"],
						allowedHosts: revocation["allowed-hosts"],
						fetchTimeoutMs: revocation["fetch-timeout-ms"],
						cacheTtlSeconds: revocation["cache-ttl-seconds"],
						maxResponseBytes: revocation["max-response-bytes"],
						...(revocation["ocsp-require-nonce"] === undefined
							? {}
							: { ocspRequireNonce: revocation["ocsp-require-nonce"] }),
					},
		...(options.logger ? { logger: options.logger } : {}),
	});
};

/**
 * Create an mTLS `TokenBindingMechanism`:
 *
 *   - `kind === "mtls"`.
 *   - `intentExplicit === false`: certificate presentation is ambient at the
 *     transport layer (RFC 8705 §3), even when forwarded in a header.
 *   - `extract(req)` returns `null` when no certificate is presented, a
 *     `TokenBinding` on success, and throws `MtlsError` on failure.
 *
 * Configuration errors throw at construction, as defense-in-depth for
 * callers that bypass `mtlsModule` (README, "Boot-time fail-loud
 * invariants").
 */
export const createMtlsMechanism = (options: MtlsMechanismOptions): TokenBindingMechanism => {
	const certHeader = options.certHeader ?? DEFAULT_CERT_HEADER;
	const dialect: CertHeaderDialect = options.certHeaderDialect ?? DEFAULT_DIALECT;
	const { mode, logger } = options;
	const source = options.source ?? DEFAULT_SOURCE;

	// --- Boot-time validation (defense-in-depth; mtlsModule also enforces) ---

	// Without an allowlist of peers that may forward it, the header IS the
	// credential and anyone routable to this process can mint one.
	if (source === "header" && (options.trustedProxies?.length ?? 0) === 0) {
		throw new Error(
			'createMtlsMechanism: source = "header" requires a non-empty trustedProxies allowlist. ' +
				"A forwarded client-certificate header is only evidence of a TLS handshake when the " +
				"hop that forwarded it is authenticated; without the allowlist any client that can " +
				"reach this process could assert any certificate. List the reverse proxy's address " +
				'or CIDR range (or "loopback" for a sidecar), or use source = "tls-layer".',
		);
	}

	// Built once so a malformed allowlist entry fails boot rather than every
	// request. Core's matcher, the vocabulary shared with `http.trustProxy`;
	// it is matched against the socket peer (`peerAddressOf`).
	const isTrustedProxy =
		source === "header"
			? createTrustedProxyMatcher(options.trustedProxies ?? [], { label: "trusted-proxies" })
			: () => false as boolean;

	if (mode === "pki" || mode === "full-pki") {
		const trustedCas = options.trustedCas;
		if (!trustedCas || trustedCas.length === 0) {
			throw new Error(
				`createMtlsMechanism: mode = "${mode}" requires a non-empty trustedCas list. ` +
					"Without trusted CAs, chain validation cannot proceed.",
			);
		}
		// `full-pki` reads the peer chain from the TLS session (`tlsChain.mts`),
		// so this restriction is the narrow mode's alone.
		if (mode === "pki" && source === "tls-layer") {
			throw new Error(
				'createMtlsMechanism: mode = "pki" with source = "tls-layer" is not supported. ' +
					"The narrow PKI mode requires the intermediate chain (e.g., the Envoy XFCC " +
					"Chain= parameter). Use " +
					'source = "header" with certHeaderDialect = "envoy" and a trustedProxies ' +
					"allowlist for PKI mode, or use " +
					'mode = "self-signed" with TLS-layer source, or mode = "full-pki" which ' +
					"reads the chain from the TLS session (#341).",
			);
		}
	}

	// Parse trusted CAs once at construction (PKI modes only).
	const trustedCaCerts: readonly X509Certificate[] =
		mode === "pki" || mode === "full-pki"
			? // biome-ignore lint/style/noNonNullAssertion: boot-time check above guarantees defined for both PKI modes
				options.trustedCas!.map((entry, index) => {
					const pem = resolveTrustedCaEntry(entry, index);
					try {
						return new X509Certificate(pem);
					} catch (err) {
						throw new Error(
							`createMtlsMechanism: trustedCas[${index}] is not a parseable X.509 certificate`,
							{ cause: err },
						);
					}
				})
			: [];

	// Built once: the CRL cache lives in the validator, so a per-request
	// validator would re-fetch every distribution point on every token request
	// and amplify traffic at the CA.
	// `fullPkiTuning` is shared by the validator and the TLS peer-chain walk
	// below, which must agree on the depth: the walk truncates at its bound, so
	// a larger walk bound would make the validator's refusal unreachable, and a
	// smaller one would drop the anchor ("no path to trust anchor" for a chain
	// that is merely long).
	const fullPkiTuning = mode === "full-pki" ? resolveFullPkiTuning(options.fullPki) : null;
	const fullPkiValidator: FullPkiValidator | null =
		mode === "full-pki"
			? // biome-ignore lint/style/noNonNullAssertion: set together with the mode above
				buildFullPkiValidator(options, trustedCaCerts, fullPkiTuning!)
			: null;

	return {
		kind: "mtls",
		intentExplicit: false,

		extract: async (req: Request) => {
			// --- Step 1: Source resolve ---
			let certPem: string | undefined;
			let chainPem: string | undefined;
			let leafDer: Uint8Array | undefined;
			let tlsChainCerts: readonly Uint8Array[] = [];

			if (source === "header") {
				const headerValue = req.get(certHeader);
				if (headerValue === undefined) {
					// Ambient: no cert at this hop. Checked before the proxy
					// allowlist so an unbound request from a direct client is not
					// an error.
					return null;
				}

				// --- Step 1b: Proxy authentication ---
				//
				// RFC 8705 §3 accepts a forwarded certificate only from an
				// authenticated trusted proxy; the connection's peer address is
				// the one thing the sender cannot choose.
				//
				// Rejects rather than returning null (CONTRIBUTING.md §4): a
				// present header from a disallowed peer is invalid material, and
				// downgrading it to unbound would let an injected header strip a
				// binding off someone else's request.
				const remoteAddress = peerAddressOf(req);
				if (!isTrustedProxy(remoteAddress)) {
					logger?.warn({ remoteAddress, certHeader }, "mtls_untrusted_proxy_rejected");
					throw new MtlsError(
						"untrusted_proxy",
						`forwarded client certificate header '${certHeader}' arrived from a peer that is not in the trusted-proxy allowlist`,
						{ remoteAddress },
					);
				}

				// --- Step 2: Header dialect parse ---
				let parsed: { certPem: string; chainPem?: string };
				try {
					parsed =
						dialect === "envoy"
							? parseEnvoyXfccHeader(headerValue)
							: parsePlainPemHeader(headerValue);
				} catch (err) {
					throw new MtlsError(
						"malformed_header",
						`${dialect} header parse failure`,
						{ dialect },
						{
							cause: err,
						},
					);
				}
				certPem = parsed.certPem;
				chainPem = parsed.chainPem;
			} else {
				// source === "tls-layer"
				const socket = req.socket as unknown;
				if (!isTlsLikeSocket(socket) || socket.getPeerCertificate === undefined) {
					throw new MtlsError(
						"tls_peer_unavailable",
						"request socket does not expose getPeerCertificate() — mTLS requires a TLS-terminated connection",
					);
				}
				// `full-pki` needs the intermediates, and only the detailed form
				// carries them. The narrow form stays the default everywhere else
				// so the cheaper call is what a self-signed deployment makes.
				const wantsChain = mode === "full-pki";
				const peer = socket.getPeerCertificate(wantsChain);
				if (!peer?.raw || peer.raw.length === 0) {
					// Ambient — no client cert presented at TLS layer.
					return null;
				}
				if (wantsChain) {
					// One more than the validator's bound, so an over-long chain
					// reaches the validator and is refused as too long, not as
					// "no path to trust anchor".
					const chain = peerChainFrom(peer, (fullPkiTuning?.maxChainDepth ?? 6) + 1);
					// `peerChainFrom` returns null only for the empty-raw case the
					// branch above already answered, so this is the same absence.
					if (chain === null) return null;
					leafDer = chain.leafDer;
					tlsChainCerts = chain.chainDer;
				} else {
					leafDer = new Uint8Array(peer.raw);
				}
			}

			// --- Step 3: PEM → DER (header) or already-DER (tls-layer) ---
			if (certPem !== undefined) {
				try {
					leafDer = pemToDer(certPem);
				} catch (err) {
					throw new MtlsError("cert_decode_failed", "PEM decode failed", undefined, { cause: err });
				}
			}
			// biome-ignore lint/style/noNonNullAssertion: leafDer is set in both branches above
			const der = leafDer!;

			// Every parser's refusal here becomes an MtlsError with fixed text and
			// the parser's error as `cause`.
			let x509: X509Certificate;
			let chainCerts: readonly X509Certificate[] = [];
			try {
				x509 = new X509Certificate(der);
			} catch (err) {
				throw new MtlsError("cert_decode_failed", "DER parse failed", undefined, { cause: err });
			}

			if (tlsChainCerts.length > 0) {
				try {
					chainCerts = tlsChainCerts.map((der) => new X509Certificate(der));
				} catch (err) {
					throw new MtlsError("cert_decode_failed", "TLS peer chain DER parse failed", undefined, {
						cause: err,
					});
				}
			}

			if (chainPem !== undefined) {
				// Envoy XFCC Chain= may contain one or many concatenated PEMs.
				// Split on -----BEGIN CERTIFICATE----- boundaries and parse each.
				const blocks = splitPemBlocks(chainPem);
				try {
					chainCerts = blocks.map((b) => new X509Certificate(b));
				} catch (err) {
					throw new MtlsError("cert_decode_failed", "Chain= entry DER parse failed", undefined, {
						cause: err,
					});
				}
			}

			// --- Step 4: Validity window ---
			const now = new Date();
			if (now < new Date(x509.validFrom)) {
				throw new MtlsError(
					"cert_not_yet_valid",
					`client certificate notBefore (${x509.validFrom}) is in the future`,
					{ notBefore: x509.validFrom },
				);
			}
			if (now > new Date(x509.validTo)) {
				throw new MtlsError(
					"cert_expired",
					`client certificate notAfter (${x509.validTo}) is in the past`,
					{ notAfter: x509.validTo },
				);
			}

			// --- Step 5: chain validation (both PKI modes) ---
			if (fullPkiValidator !== null) {
				const result = await fullPkiValidator.validate(x509, chainCerts, now);
				if (!result.ok && result.outage) {
					// The server's outage, not a verdict: a revocation source did not
					// answer usefully. Refused `unavailable` — the dispatcher answers
					// 503 and writes the one line, so nothing is logged here.
					throw new MtlsError(
						"revocation_unavailable",
						"client certificate revocation status could not be determined",
						{ step: result.step },
						// The validator's account, one member per source that could not
						// be used (an MtlsRevocationUnavailableError).
						result.cause !== undefined ? { cause: result.cause } : undefined,
					);
				}
				if (!result.ok) {
					// `err` is the projection of a library error behind the refusal, when
					// one threw — never its text, which `detail` does not carry either.
					logger?.warn(
						{
							step: result.step,
							// Built from the certificate's own text (a subject, a URL
							// it names): one line and capped.
							detail: lineSafeText(result.detail),
							...(result.cause !== undefined ? { err: loggableError(result.cause) } : {}),
						},
						"mtls_full_pki_validation_failed",
					);
					throw new MtlsError(
						"chain_validation_failed",
						`client certificate failed RFC 5280 path validation: ${result.step}`,
						{ step: result.step, detail: result.detail },
						result.cause !== undefined ? { cause: result.cause } : undefined,
					);
				}
			} else if (mode === "pki") {
				const result = validateCertChain(x509, chainCerts, trustedCaCerts, now);
				if (!result.ok) {
					logger?.warn({ step: result.step }, "mtls_chain_validation_failed");
					throw new MtlsError(
						"chain_validation_failed",
						`client certificate failed PKI chain validation: ${result.step}`,
						{ step: result.step },
					);
				}
			}

			// --- Step 6: Thumbprint (RFC 8705 §3.1) ---
			const thumbprint = computeCertThumbprint(der);

			// --- Step 7: Return TokenBinding ---
			return {
				kind: "mtls",
				confirmation: { "x5t#S256": thumbprint },
			};
		},
	};
};

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Resolve a `trustedCas` entry into PEM: a literal PEM block passes through,
 * and `file:<path>` is read as-is (absolute, or relative to the process cwd).
 * Sync I/O is fine because this runs once at construction, before any
 * request. A read failure throws with the entry index and the read's error as
 * `cause`.
 */
const resolveTrustedCaEntry = (entry: string, index: number): string => {
	if (entry.startsWith("file:")) {
		const path = entry.slice("file:".length);
		try {
			return readFileSync(path, "utf8");
		} catch (err) {
			throw new Error(
				`createMtlsMechanism: trustedCas[${index}] = "${entry}": failed to read file at ${path}`,
				{ cause: err },
			);
		}
	}
	return entry;
};

/**
 * Split XFCC `Chain=`, which may concatenate several PEM certificates, into
 * PEM blocks in order. Order does not matter to `validateCertChain`.
 */
const splitPemBlocks = (multiPem: string): readonly string[] => {
	const BEGIN = "-----BEGIN CERTIFICATE-----";
	const END = "-----END CERTIFICATE-----";
	const blocks: string[] = [];
	let cursor = 0;
	while (cursor < multiPem.length) {
		const beginIdx = multiPem.indexOf(BEGIN, cursor);
		if (beginIdx === -1) break;
		const endIdx = multiPem.indexOf(END, beginIdx);
		if (endIdx === -1) break;
		blocks.push(multiPem.slice(beginIdx, endIdx + END.length));
		cursor = endIdx + END.length;
	}
	return blocks;
};
