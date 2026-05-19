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
 * `createMtlsMechanism` factory — implements the RFC 8705 §3 client-cert-bound
 * access-token mechanism as a `TokenBindingMechanism`.
 *
 * The returned mechanism's `extract(req)` executes the 7-step total-order
 * sequence specified in Wave 2 Phase 3 spec §6:
 *
 *   1. Source resolve  (header or tls-layer)
 *   2. Dialect parse   (envoy XFCC / plain-PEM) — header source only
 *   3. PEM → DER       (header) / DER pluck (tls-layer)
 *   4. Validity window (notBefore <= now <= notAfter)
 *   5. PKI chain walk  (mode === "pki" only; see pki.mts §7.2)
 *   6. Thumbprint      (RFC 8705 §3.1, computeCertThumbprint)
 *   7. Return          ({ kind: "mtls", confirmation: { "x5t#S256": ... } })
 *
 * Per spec §6 (extraction algorithm) + §8 (factory contract).
 */

import { X509Certificate } from "node:crypto";
import type { Logger, TokenBindingMechanism } from "@o3co/auth-provider-core";
import type { Request } from "express";
import { parseDerToCertificate } from "./certificate.mjs";
import { MtlsError } from "./errors.mjs";
import { type CertHeaderDialect, parseEnvoyXfccHeader, parsePlainPemHeader } from "./headers.mjs";
import { pemToDer } from "./pem.mjs";
import { validateCertChain } from "./pki.mjs";
import { computeCertThumbprint } from "./thumbprint.mjs";

// ---------------------------------------------------------------------------
// Public type
// ---------------------------------------------------------------------------

/** Per Wave 2 Phase 3 spec §5.2. */
export interface MtlsMechanismOptions {
	readonly source: "header" | "tls-layer";
	readonly certHeader?: string;
	readonly certHeaderDialect?: CertHeaderDialect;
	readonly mode: "self-signed" | "pki";
	readonly trustedCas?: readonly string[];
	readonly logger?: Logger;
}

// ---------------------------------------------------------------------------
// Constants — defaults
// ---------------------------------------------------------------------------

const DEFAULT_CERT_HEADER = "x-forwarded-client-cert";
const DEFAULT_DIALECT: CertHeaderDialect = "envoy";

// ---------------------------------------------------------------------------
// Internal — minimal duck-typed shape for `req.socket.getPeerCertificate()`
// ---------------------------------------------------------------------------

/**
 * Node's TLSSocket exposes `getPeerCertificate({ raw: Buffer, ... })`. We
 * duck-type the bare minimum we use to keep the type surface small and to
 * avoid pulling in `tls.TLSSocket` (which would force consumers using a
 * non-TLS socket through type narrowing).
 */
interface TlsLikeSocket {
	getPeerCertificate?: () => { readonly raw?: Buffer } | undefined;
}

const isTlsLikeSocket = (s: unknown): s is TlsLikeSocket =>
	typeof s === "object" &&
	s !== null &&
	typeof (s as { getPeerCertificate?: unknown }).getPeerCertificate === "function";

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create an mTLS `TokenBindingMechanism`. The returned mechanism:
 *
 *   - `kind === "mtls"`.
 *   - `intentExplicit === false` — mTLS cert presentation is ambient at the
 *     transport layer (RFC 8705 §3); even when sourced from a forwarded
 *     header, the underlying signal is not an application-layer artifact.
 *   - `extract(req)` returns `null` when no cert is presented (ambient
 *     dispatch), `TokenBinding` on success, throws `MtlsError` on failure.
 *
 * Boot-time checks (defense-in-depth for programmatic callers that bypass
 * `mtlsModule`):
 *
 *   - `mode === "pki"` + empty `trustedCas` → throw at construction.
 *   - `mode === "pki"` + `source === "tls-layer"` → throw at construction
 *     (Codex Round 1 Important #1 fix — TLS-layer full-chain extraction
 *     is deferred to a future phase per spec §1.3).
 *
 * Per spec §8 + §11.2.
 */
export const createMtlsMechanism = (options: MtlsMechanismOptions): TokenBindingMechanism => {
	const certHeader = options.certHeader ?? DEFAULT_CERT_HEADER;
	const dialect: CertHeaderDialect = options.certHeaderDialect ?? DEFAULT_DIALECT;
	const { source, mode, logger } = options;

	// --- Boot-time validation (defense-in-depth; mtlsModule also enforces) ---
	if (mode === "pki") {
		const trustedCas = options.trustedCas;
		if (!trustedCas || trustedCas.length === 0) {
			throw new Error(
				'createMtlsMechanism: mode = "pki" requires a non-empty trustedCas list. ' +
					"Without trusted CAs, chain validation cannot proceed.",
			);
		}
		if (source === "tls-layer") {
			throw new Error(
				'createMtlsMechanism: mode = "pki" with source = "tls-layer" is not supported in Phase 3. ' +
					"The narrow PKI mode requires the intermediate chain (e.g., the Envoy XFCC " +
					"Chain= parameter); TLS-layer full-chain extraction is deferred. Use " +
					'source = "header" with certHeaderDialect = "envoy" for PKI mode, or use ' +
					'mode = "self-signed" with TLS-layer source.',
			);
		}
	}

	// Pre-parse trusted CAs once (PKI mode only).
	const trustedCaCerts: readonly X509Certificate[] =
		mode === "pki"
			? // biome-ignore lint/style/noNonNullAssertion: boot-time check above guarantees defined when mode === "pki"
				options.trustedCas!.map((pem, index) => {
					try {
						return new X509Certificate(pem);
					} catch (err) {
						throw new Error(
							`createMtlsMechanism: trustedCas[${index}] is not a parseable X.509 certificate: ${(err as Error).message}`,
						);
					}
				})
			: [];

	return {
		kind: "mtls",
		intentExplicit: false,

		extract: async (req: Request) => {
			// --- Step 1: Source resolve ---
			let certPem: string | undefined;
			let chainPem: string | undefined;
			let leafDer: Uint8Array | undefined;

			if (source === "header") {
				const headerValue = req.get(certHeader);
				if (headerValue === undefined) {
					// Ambient — no cert presented at this hop. Skip downstream dispatch.
					return null;
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
						`${dialect} header parse failure: ${(err as Error).message}`,
						{ dialect },
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
				const peer = socket.getPeerCertificate();
				if (!peer || !peer.raw || peer.raw.length === 0) {
					// Ambient — no client cert presented at TLS layer.
					return null;
				}
				leafDer = new Uint8Array(peer.raw);
			}

			// --- Step 3: PEM → DER (header) or already-DER (tls-layer) ---
			if (certPem !== undefined) {
				try {
					leafDer = pemToDer(certPem);
				} catch (err) {
					throw new MtlsError("cert_decode_failed", `PEM decode failed: ${(err as Error).message}`);
				}
			}
			// biome-ignore lint/style/noNonNullAssertion: leafDer is set in both branches above
			const der = leafDer!;

			// Parse to X509Certificate for validity + chain steps. parseDerToCertificate
			// throws plain Error on malformed DER — wrap to MtlsError.
			let x509: X509Certificate;
			let chainCerts: readonly X509Certificate[] = [];
			try {
				parseDerToCertificate(der); // exercises the same parse path + defensive copy
				x509 = new X509Certificate(der);
			} catch (err) {
				throw new MtlsError("cert_decode_failed", `DER parse failed: ${(err as Error).message}`);
			}

			if (chainPem !== undefined) {
				// Envoy XFCC Chain= may contain one or many concatenated PEMs.
				// Split on -----BEGIN CERTIFICATE----- boundaries and parse each.
				const blocks = splitPemBlocks(chainPem);
				try {
					chainCerts = blocks.map((b) => new X509Certificate(b));
				} catch (err) {
					throw new MtlsError(
						"cert_decode_failed",
						`Chain= entry DER parse failed: ${(err as Error).message}`,
					);
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

			// --- Step 5: PKI chain validation (mode === "pki" only) ---
			if (mode === "pki") {
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
 * Split a possibly-multi-PEM string into individual PEM blocks. Used for
 * XFCC Chain= which may concatenate multiple intermediate certs.
 *
 * Returns an empty array for empty input. Preserves block ordering — Envoy's
 * Chain= lists intermediates in leaf-first order (closest to leaf first, root
 * CA-signed last), matching the order `validateCertChain` walks.
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
