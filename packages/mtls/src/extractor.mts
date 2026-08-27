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
 * The returned mechanism's `extract(req)` executes the total-order sequence
 * specified in Wave 2 Phase 3 spec §6, with the source-authentication step
 * added by issue #280:
 *
 *   1. Source resolve  (tls-layer by default, or header)
 *   1b. Proxy authentication — header source only: the peer that opened the
 *       connection must be in the configured trusted-proxy allowlist
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
import { readFileSync } from "node:fs";
import type { Logger, TokenBindingMechanism } from "@o3co/auth-provider-core";
import type { Request } from "express";
import { MtlsError } from "./errors.mjs";
import { type CertHeaderDialect, parseEnvoyXfccHeader, parsePlainPemHeader } from "./headers.mjs";
import { pemToDer } from "./pem.mjs";
import { validateCertChain } from "./pki.mjs";
import { createTrustedProxyMatcher } from "./proxy.mjs";
import { computeCertThumbprint } from "./thumbprint.mjs";

// ---------------------------------------------------------------------------
// Public type
// ---------------------------------------------------------------------------

/** Per Wave 2 Phase 3 spec §5.2. */
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
	 * Peer addresses permitted to forward a client certificate header. Each
	 * entry is an IPv4 / IPv6 literal or the `"loopback"` keyword; see
	 * `proxy.mts`. Required (non-empty) when `source === "header"`, ignored
	 * otherwise.
	 */
	readonly trustedProxies?: readonly string[];
	readonly mode: "self-signed" | "pki";
	readonly trustedCas?: readonly string[];
	readonly logger?: Logger;
}

// ---------------------------------------------------------------------------
// Constants — defaults
// ---------------------------------------------------------------------------

const DEFAULT_CERT_HEADER = "x-forwarded-client-cert";
const DEFAULT_DIALECT: CertHeaderDialect = "envoy";

/**
 * The certificate comes from the TLS layer unless the operator says otherwise
 * (issue #280).
 *
 * The pre-#280 default was `"header"`, which meant enabling mTLS trusted an
 * `X-Forwarded-Client-Cert` value from whoever opened the connection. Anyone
 * who could reach the process could then assert any client identity — the
 * header is the credential, and nothing proved it came from the proxy. RFC
 * 8705 §3 requires the certificate to come from the TLS layer or from an
 * authenticated trusted proxy, and only one of those two is safe to assume.
 */
const DEFAULT_SOURCE = "tls-layer" as const;

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

/**
 * The address of the peer that opened this connection.
 *
 * Deliberately `req.socket.remoteAddress` and never `req.ip`: `req.ip` is
 * rewritten from `X-Forwarded-For` whenever Express `trust proxy` is on, so
 * authenticating the forwarding hop with it would mean authenticating a header
 * with another header. `undefined` (destroyed socket, Unix-domain listener) is
 * carried through and treated as untrusted by the matcher.
 */
const peerAddressOf = (req: Request): string | undefined =>
	(req.socket as { remoteAddress?: string } | undefined)?.remoteAddress;

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
 *   - `source === "header"` + empty `trustedProxies` → throw at construction
 *     (issue #280 — a forwarded certificate is only evidence of anything when
 *     the forwarding hop is authenticated).
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
	const { mode, logger } = options;
	const source = options.source ?? DEFAULT_SOURCE;

	// --- Boot-time validation (defense-in-depth; mtlsModule also enforces) ---

	// Issue #280: the header source is an assertion made by whoever opened the
	// connection. Without an allowlist naming which peers may make it, the
	// header IS the credential and anyone routable to this process can mint one.
	// Refuse to construct a mechanism that would accept it from anywhere.
	if (source === "header" && (options.trustedProxies?.length ?? 0) === 0) {
		throw new Error(
			'createMtlsMechanism: source = "header" requires a non-empty trustedProxies allowlist. ' +
				"A forwarded client-certificate header is only evidence of a TLS handshake when the " +
				"hop that forwarded it is authenticated; without the allowlist any client that can " +
				"reach this process could assert any certificate. List the reverse proxy's address " +
				'(or "loopback" for a sidecar), or use source = "tls-layer".',
		);
	}

	// Built once at construction so a malformed allowlist entry fails boot
	// rather than every request. Empty in tls-layer mode, where it is unused.
	const isTrustedProxy =
		source === "header"
			? createTrustedProxyMatcher(options.trustedProxies ?? [])
			: () => false as boolean;

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
					'source = "header" with certHeaderDialect = "envoy" and a trustedProxies ' +
					"allowlist for PKI mode, or use " +
					'mode = "self-signed" with TLS-layer source.',
			);
		}
	}

	// Pre-parse trusted CAs once at construction (PKI mode only). Each entry
	// is either a literal PEM block or a `file:<path>` reference resolved
	// synchronously at boot — the latter mirrors the operator-friendly form
	// documented in reference.conf and spec §7.1.
	const trustedCaCerts: readonly X509Certificate[] =
		mode === "pki"
			? // biome-ignore lint/style/noNonNullAssertion: boot-time check above guarantees defined when mode === "pki"
				options.trustedCas!.map((entry, index) => {
					const pem = resolveTrustedCaEntry(entry, index);
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
					//
					// Checked BEFORE the proxy allowlist on purpose: absence is
					// absence no matter who is connecting, and an ordinary unbound
					// request from a direct client must not become an error.
					return null;
				}

				// --- Step 1b: Proxy authentication (issue #280) ---
				//
				// RFC 8705 §3 accepts a forwarded certificate only from an
				// authenticated trusted proxy. The peer address of the open
				// connection is the one thing on this request the sender cannot
				// choose, so it is what the allowlist is checked against.
				//
				// This REJECTS rather than returning null. Per CONTRIBUTING.md §4,
				// `null` means "absent"; a header that is present but came from
				// somewhere it may not come from is invalid material, and invalid
				// material fails the request instead of downgrading it to unbound —
				// otherwise injecting this header would be a way to strip a binding
				// off someone else's request.
				const remoteAddress = peerAddressOf(req);
				if (!isTrustedProxy(remoteAddress)) {
					logger?.warn({ remoteAddress, certHeader }, "mtls_untrusted_proxy_rejected");
					throw new MtlsError(
						"untrusted_proxy",
						`forwarded client certificate header "${certHeader}" arrived from a peer that is not in the trusted-proxy allowlist`,
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
				if (!peer?.raw || peer.raw.length === 0) {
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

			// Parse to X509Certificate for validity + chain steps. `new X509Certificate(der)`
			// throws DOMException / Error on malformed DER — wrap to MtlsError so the
			// audit pipeline gets the structured reason.
			let x509: X509Certificate;
			let chainCerts: readonly X509Certificate[] = [];
			try {
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
 * Resolve a single `trustedCas` entry into a PEM string. Supports two forms:
 *
 *   - Literal PEM block (starts with `-----BEGIN CERTIFICATE-----`) — passed
 *     through verbatim.
 *   - `file:<path>` — the file at `<path>` is read synchronously at boot
 *     and its contents returned. The path is taken as-is (absolute or
 *     relative to the auth-provider process's cwd); operators are expected
 *     to provide absolute paths via reference.conf or env-substituted HOCON.
 *
 * Sync I/O is appropriate here because it runs once at module construction
 * (boot time), before any request is served. A file-read failure throws a
 * plain Error with the entry index for operator debugging.
 *
 * Per Wave 2 Phase 3 spec §7.1.
 */
const resolveTrustedCaEntry = (entry: string, index: number): string => {
	if (entry.startsWith("file:")) {
		const path = entry.slice("file:".length);
		try {
			return readFileSync(path, "utf8");
		} catch (err) {
			throw new Error(
				`createMtlsMechanism: trustedCas[${index}] = "${entry}": failed to read file at ${path}: ${(err as Error).message}`,
			);
		}
	}
	return entry;
};

/**
 * Split a possibly-multi-PEM string into individual PEM blocks. Used for
 * XFCC Chain= which may concatenate multiple intermediate certs.
 *
 * Returns an empty array for empty input. Block ordering is preserved
 * (informational only — `validateCertChain` is order-independent via
 * `find()` lookup, so callers are not required to present leaf-first).
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
