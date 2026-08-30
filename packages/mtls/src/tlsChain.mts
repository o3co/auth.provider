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
 * Reading the peer's certificate **chain** from the TLS session (#341, the
 * "Related: TLS-layer chains" section).
 *
 * Before this, `mode = "pki"` with `source = "tls-layer"` was refused at boot:
 * the narrow walk needed intermediates, and the only place it knew to find
 * them was the Envoy XFCC `Chain=` parameter. That left the RFC 8705 §3 shape
 * — terminate TLS here, take the certificate from the handshake — unable to
 * use PKI validation at all, even though #280 had just made `tls-layer` the
 * default source.
 *
 * `getPeerCertificate(true)` returns the chain as a linked list through
 * `issuerCertificate`. Two things about that list need care:
 *
 *  - **It is circular at the root.** A self-signed anchor's
 *    `issuerCertificate` points at itself, so a walk that only tests for
 *    `undefined` never terminates.
 *  - **It is peer-supplied.** The client chooses what to send, so the walk is
 *    bounded by depth rather than trusted to be short.
 *
 * The anchor the client sent is deliberately kept in the returned chain and
 * *not* treated as trusted. Trust comes from `oauth.mtls.trusted-cas` alone;
 * a chain that terminates in an anchor the operator did not configure fails
 * path validation, which is the whole point of configuring them.
 */

/** The shape of `getPeerCertificate(true)` that this module reads. */
export interface DetailedPeerCertificateLike {
	readonly raw?: Buffer;
	readonly issuerCertificate?: DetailedPeerCertificateLike;
}

export interface PeerChain {
	readonly leafDer: Uint8Array;
	/** Intermediates and any anchor the peer sent, nearest-issuer first. */
	readonly chainDer: readonly Uint8Array[];
}

/**
 * @param maxDepth total certificates to read, leaf included. A peer that
 * sends more has the remainder ignored rather than the request refused: path
 * validation bounds the chain it will accept anyway, and refusing here would
 * turn a verbose-but-valid client into an error at a layer that cannot
 * explain itself.
 */
export const peerChainFrom = (
	peer: DetailedPeerCertificateLike | undefined,
	maxDepth: number,
): PeerChain | null => {
	if (!peer?.raw || peer.raw.length === 0) return null;

	const leafDer = new Uint8Array(peer.raw);
	const chainDer: Uint8Array[] = [];
	const seen = new Set<string>([Buffer.from(leafDer).toString("base64")]);

	let current = peer.issuerCertificate;
	while (current?.raw && current.raw.length > 0 && chainDer.length + 1 < maxDepth) {
		const der = new Uint8Array(current.raw);
		const fingerprint = Buffer.from(der).toString("base64");
		// Terminates the self-referential root, and any loop a peer constructs.
		if (seen.has(fingerprint)) break;
		seen.add(fingerprint);
		chainDer.push(der);
		current = current.issuerCertificate;
	}

	return { leafDer, chainDer };
};
