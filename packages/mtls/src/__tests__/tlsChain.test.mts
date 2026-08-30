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
 * Reading the peer chain out of a TLS session (#341).
 *
 * The linked list `getPeerCertificate(true)` returns is circular at the root
 * and supplied by the peer, so the two things worth pinning are that the walk
 * terminates and that it is bounded.
 */

import { describe, expect, it } from "vitest";
import { type DetailedPeerCertificateLike, peerChainFrom } from "#/tlsChain.mjs";

const cert = (byte: number): { raw: Buffer } => ({ raw: Buffer.from([byte]) });

/** Links `certs` leaf-first, leaving the last one pointing at itself. */
const linked = (bytes: readonly number[]): DetailedPeerCertificateLike => {
	const nodes = bytes.map(
		(b) => cert(b) as DetailedPeerCertificateLike & { issuerCertificate?: unknown },
	);
	nodes.forEach((node, i) => {
		// A self-signed root's issuerCertificate is itself — Node documents this,
		// and a walk that only tests for `undefined` never returns.
		node.issuerCertificate = nodes[i + 1] ?? node;
	});
	return nodes[0] as DetailedPeerCertificateLike;
};

describe("peerChainFrom", () => {
	it("returns the leaf and the intermediates above it", () => {
		const chain = peerChainFrom(linked([1, 2, 3]), 6);
		expect(chain).not.toBeNull();
		expect(Array.from(chain?.leafDer ?? [])).toEqual([1]);
		expect((chain?.chainDer ?? []).map((d) => Array.from(d))).toEqual([[2], [3]]);
	});

	it("terminates on the self-referential root rather than looping", () => {
		// A single self-signed certificate: `issuerCertificate` is the node
		// itself. Without the seen-set this call does not return.
		const chain = peerChainFrom(linked([1]), 6);
		expect(chain?.chainDer).toEqual([]);
	});

	it("terminates on a cycle a peer constructs", () => {
		const a = cert(1) as DetailedPeerCertificateLike & { issuerCertificate?: unknown };
		const b = cert(2) as DetailedPeerCertificateLike & { issuerCertificate?: unknown };
		a.issuerCertificate = b;
		b.issuerCertificate = a;

		const chain = peerChainFrom(a, 6);
		expect((chain?.chainDer ?? []).map((d) => Array.from(d))).toEqual([[2]]);
	});

	it("stops at maxDepth, counting the leaf", () => {
		const chain = peerChainFrom(linked([1, 2, 3, 4, 5]), 3);
		expect((chain?.chainDer ?? []).length).toBe(2);
	});

	it("reports absence for a handshake with no client certificate", () => {
		expect(peerChainFrom(undefined, 6)).toBeNull();
		expect(peerChainFrom({ raw: Buffer.alloc(0) }, 6)).toBeNull();
	});
});
