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
import type { X509Certificate } from "node:crypto";

/**
 * Narrow PKI mode chain validation per Wave 2 Phase 3 spec §7.2.
 *
 * **This is NOT full RFC 5280 path validation.** The narrow mode checks:
 *
 *   1. Leaf cert validity window (`notBefore <= now <= notAfter`).
 *   2. Chain walk hop-by-hop, with fingerprint cycle detection.
 *   3. Per-intermediate validity window.
 *   4. Per-intermediate `basicConstraints.CA === true` (RFC 5280 §4.2.1.9).
 *   5. Per-hop **pair check**: `checkIssued` (DN / AKID / SKID match) AND
 *      `isSignedBy` (cryptographic signature). Applied at both intermediate
 *      hops and the terminal trust anchor — see `isSignedBy`'s JSDoc for why
 *      both are required.
 *   6. Trust-anchor validity window.
 *
 * The narrow mode is sufficient for the common single-private-CA M2M
 * deployment shape (RFC 8705 §2.1). Operators needing full path validation
 * (name constraints, policy mappings, CRL/OCSP, path length) MUST defer
 * deployment until `mode = "full-pki"` arm ships — README §"PKI Mode Scope"
 * documents the scope-out, and `mtlsModule` boot-time check rejects
 * misconfigurations that would silently fail.
 *
 * **Why explicit boolean return, not throw**: the call site (extractor.mts
 * step 5) wraps the failure into `MtlsError("chain_validation_failed", ...)`.
 * Threading `{ ok, step }` lets the extractor populate the audit `detail`
 * field with the specific failing check name without parsing an exception
 * message. Mirrors `parseProof` from `@o3co/auth-provider-dpop`.
 *
 * Per spec §7.2 + §7.3 (checks NOT performed) + §7.4 (RFC 8705 §7.4 alignment).
 */
type ValidationResult = { readonly ok: true } | { readonly ok: false; readonly step: string };

/**
 * Probe `basicConstraints` for `CA: TRUE`. Node's `X509Certificate.ca`
 * (boolean) is the canonical accessor — see
 * <https://nodejs.org/api/crypto.html#x509certificateca>.
 *
 * **Why not `keyUsage` check too**: RFC 5280 §4.2.1.3 says a cert MUST have
 * `keyCertSign` to sign certs IF keyUsage is present at all. Most CAs do
 * include `keyCertSign`. The spec §7.2 narrow check list intentionally
 * skips the keyUsage assertion to match what `X509Certificate` exposes
 * directly — adding keyUsage parsing would require ASN.1 walking which
 * the spec defers to the future `full-pki` arm.
 */
const issuerIsCA = (issuer: X509Certificate): boolean => issuer.ca === true;

/**
 * Cryptographically verify that `subject` was signed by `issuer`'s private key.
 *
 * `X509Certificate.verify(publicKey)` performs the signature check; it does NOT
 * also check DN or extensions (those are checkIssued's job). The pair must be
 * gated TOGETHER: checkIssued for the DN/AKID/SKID match, then `verify` for the
 * cryptographic proof.
 *
 * **Why this is load-bearing**: `X509_check_issued` (OpenSSL primitive backing
 * Node's `checkIssued`) does NOT verify signatures — its docs are explicit. The
 * incidental AKID/SKID checks reject many naive forges, but they are not a
 * security guarantee: an attacker who omits the AKID extension entirely (legal
 * per RFC 5280) or carefully crafts a matching AKID can bypass `checkIssued`
 * without ever proving cryptographic relation to the issuer. The explicit
 * `verify(publicKey)` closes the gap and matches the spec §7.2 "current signed
 * directly by …" contract that the README "PKI Mode Scope" advertises.
 *
 * Returns `false` on any verification failure (mismatched signature, algorithm
 * mismatch, etc.) — the caller maps this to a chain-validation failure with the
 * specific failing hop named in `step`.
 */
const isSignedBy = (subject: X509Certificate, issuer: X509Certificate): boolean => {
	try {
		return subject.verify(issuer.publicKey);
	} catch {
		// `verify` throws when the public key type is incompatible with the
		// subject's signature algorithm. Treat as a verification failure — the
		// chain is rejected, not the whole request.
		return false;
	}
};

export const validateCertChain = (
	leaf: X509Certificate,
	intermediates: readonly X509Certificate[],
	trustedCas: readonly X509Certificate[],
	now: Date,
): ValidationResult => {
	// Step 1: leaf validity window. Step §6.4 of extractor.mts also runs this,
	// but the chain walk repeats it as a defensive double-check — the function
	// is also reachable from other call sites in tests.
	if (now < new Date(leaf.validFrom)) return { ok: false, step: "leaf cert not yet valid" };
	if (now > new Date(leaf.validTo)) return { ok: false, step: "leaf cert expired" };

	// Step 2: chain walk. Track fingerprints to detect cycles — a malicious
	// chain could otherwise loop forever or exhaust stack.
	//
	// Per-hop cost is up to 4 .find() scans over the (trustedCas) and
	// (intermediates) arrays — verified-pair lookup + DN-only fallback for
	// the audit-signal distinction. Realistic deployments have <5 hops and
	// <20 anchors so the O(N²) shape is trivially fine; merging the two
	// scans would obscure the audit-reason branching and is not worth it.
	let current = leaf;
	const seen = new Set<string>();
	// Walk depth is bounded by `intermediates.length + 1` (one terminal hop to
	// the trust anchor). +1 prevents off-by-one when leaf is directly signed
	// by an anchor with no intermediates.
	for (let i = 0; i < intermediates.length + 1; i++) {
		const fingerprint = current.fingerprint256;
		if (seen.has(fingerprint)) return { ok: false, step: "cycle detected" };
		seen.add(fingerprint);

		// Trust-anchor match: gated by BOTH checkIssued (DN/AKID/SKID) and
		// isSignedBy (cryptographic signature). checkIssued alone does not
		// verify the signature, so a forged cert with matching DN could
		// otherwise pass — see isSignedBy's JSDoc.
		const anchor = trustedCas.find((ca) => current.checkIssued(ca) && isSignedBy(current, ca));
		if (anchor) {
			if (now < new Date(anchor.validFrom)) {
				return { ok: false, step: "trust anchor not yet valid" };
			}
			if (now > new Date(anchor.validTo)) {
				return { ok: false, step: "trust anchor expired" };
			}
			return { ok: true };
		}

		// Defense-in-depth: if a trust anchor was DN-matched but the signature
		// didn't verify (i.e., checkIssued succeeded but isSignedBy failed),
		// reject explicitly so the audit signal distinguishes "no candidate
		// anchor" from "candidate present but signature invalid".
		const dnMatchedAnchor = trustedCas.find((ca) => current.checkIssued(ca));
		if (dnMatchedAnchor) {
			return {
				ok: false,
				step: "trust anchor matched by DN but signature verification failed",
			};
		}

		const issuer = intermediates.find(
			(iss) => current.checkIssued(iss) && isSignedBy(current, iss),
		);
		if (!issuer) {
			// Same defense-in-depth distinction for intermediates.
			const dnMatchedIssuer = intermediates.find((iss) => current.checkIssued(iss));
			if (dnMatchedIssuer) {
				return {
					ok: false,
					step: "intermediate matched by DN but signature verification failed",
				};
			}
			return { ok: false, step: "no path to trust anchor" };
		}

		if (now < new Date(issuer.validFrom)) {
			return { ok: false, step: "intermediate not yet valid" };
		}
		if (now > new Date(issuer.validTo)) {
			return { ok: false, step: "intermediate expired" };
		}
		if (!issuerIsCA(issuer)) {
			return {
				ok: false,
				step: "intermediate has basicConstraints CA=false (non-CA cannot sign certs per RFC 5280 §4.2.1.9)",
			};
		}

		current = issuer;
	}
	return { ok: false, step: "chain depth exceeded intermediates count" };
};
