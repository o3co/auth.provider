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
 * Reads the peer's certificate chain from the TLS session, for `full-pki`
 * with `source = "tls-layer"`. `getPeerCertificate(true)` links the chain
 * through `issuerCertificate`, and that list:
 *
 *  - is circular at the root (a self-signed anchor is its own issuer), so the
 *    walk tracks what it has seen;
 *  - is peer-supplied, so the walk is bounded by depth.
 *
 * An anchor the client sent stays in the chain and is not trusted: trust
 * comes from `mtls.trustedCas` alone.
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
 * @param maxDepth total certificates to read, leaf included. The rest of a
 * longer chain is ignored rather than refused here: path validation bounds
 * the chain anyway, and can explain its refusal.
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
