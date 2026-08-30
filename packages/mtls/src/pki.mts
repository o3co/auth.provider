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
 *   2. Leaf certificate profile: `basicConstraints.CA === false` and, when the
 *      extension is present, an `extendedKeyUsage` including `clientAuth`
 *      (RFC 5280 §4.2.1.9 + §4.2.1.12). Added by issue #280.
 *   3. Chain walk hop-by-hop, with fingerprint cycle detection.
 *   4. Per-intermediate validity window.
 *   5. Per-intermediate `basicConstraints.CA === true` (RFC 5280 §4.2.1.9).
 *   6. Per-hop **pair check**: `checkIssued` (DN / AKID / SKID match) AND
 *      `isSignedBy` (cryptographic signature). Applied at both intermediate
 *      hops and the terminal trust anchor — see `isSignedBy`'s JSDoc for why
 *      both are required.
 *   7. Trust-anchor validity window, and `basicConstraints.CA === true` on the
 *      anchor itself (issue #280).
 *
 * The narrow mode is sufficient for the common single-private-CA M2M
 * deployment shape (RFC 8705 §2.1). Operators needing full path validation
 * (name constraints, policy mappings, CRL/OCSP, path length) MUST defer
 * deployment until `mode = "full-pki"` arm ships — README §"PKI Mode Scope"
 * documents the scope-out, and `mtlsModule` boot-time check rejects
 * misconfigurations that would silently fail.
 *
 * ### Revocation is NOT checked — deliberately, and tracked
 *
 * Nothing here consults a CRL (RFC 5280 §6.3) or an OCSP responder
 * (RFC 6960). A client certificate that has been revoked continues to bind
 * tokens until its `notAfter` passes. This is a **known, accepted gap** in the
 * narrow mode, not an oversight: revocation needs a fetch path, a cache, and
 * an operator-visible soft-fail / hard-fail policy, none of which belong in a
 * synchronous pure function. It is tracked with the rest of the outstanding
 * RFC 5280 checks in **o3co/auth.provider#341**.
 *
 * Until it ships, the mitigation is short certificate lifetimes and rotation,
 * plus the RFC 8705 §7.4 advice to keep `trusted-cas` as small as possible.
 *
 * **Why explicit boolean return, not throw**: the call site (extractor.mts
 * step 5) wraps the failure into `MtlsError("chain_validation_failed", ...)`.
 * Threading `{ ok, step }` lets the extractor populate the audit `detail`
 * field with the specific failing check name without parsing an exception
 * message. Mirrors `parseProof` from `@o3co/auth-provider-dpop`.
 *
 * Per spec §7.2 + §7.3 (checks NOT performed) + §7.4 (RFC 8705 §7.4 alignment).
 */
export type ValidationResult =
	| { readonly ok: true }
	| { readonly ok: false; readonly step: string };

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
 * OID of the TLS Web Client Authentication extended key usage
 * (RFC 5280 §4.2.1.12 / RFC 5246 appendix).
 */
const EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";

/**
 * OID of `anyExtendedKeyUsage` (RFC 5280 §4.2.1.12). A certificate carrying it
 * asserts no purpose restriction, so it satisfies a `clientAuth` requirement.
 */
const EKU_ANY = "2.5.29.37.0";

/**
 * Check the leaf against the client-certificate profile (issue #280).
 *
 * Two properties, both readable from what `X509Certificate` exposes directly:
 *
 *   - **`basicConstraints`.** A `CA:TRUE` certificate is not a client
 *     credential. Binding a token to one binds it to an identity that can also
 *     mint other identities, so a single leaked CA key becomes a token-binding
 *     bypass rather than "just" a CA compromise.
 *   - **`extendedKeyUsage`.** When present, it MUST include `clientAuth` (or
 *     `anyExtendedKeyUsage`). This is what stops a server certificate — which
 *     a web PKI hands out on request for any domain you control — from being
 *     presented as a client credential.
 *
 * **Absence of `extendedKeyUsage` is accepted.** RFC 5280 §4.2.1.12 makes the
 * extension a restriction, not a grant: "If the extension is present, then the
 * certificate MUST only be used for one of the purposes indicated." A leaf
 * without it is unconstrained. Reading absence as "no permitted purposes"
 * would reject every deployment whose private CA does not stamp an EKU, and
 * would not be the RFC's reading.
 *
 * **Naming trap:** Node's `X509Certificate.keyUsage` returns the **extended**
 * key usage OIDs, not the `keyUsage` bit string. The RFC 5280 §4.2.1.3
 * `keyCertSign` check on issuers is therefore NOT implementable from this
 * accessor and is tracked in #341 with the rest of the path-validation gap.
 */
export const checkClientLeafProfile = (leaf: X509Certificate): ValidationResult => {
	if (leaf.ca === true) {
		return {
			ok: false,
			step: "leaf certificate has basicConstraints CA=true (a CA certificate is not a client certificate)",
		};
	}

	// `keyUsage` is Node's accessor for extendedKeyUsage — see the trap above.
	const eku = leaf.keyUsage;
	if (eku !== undefined && !eku.includes(EKU_CLIENT_AUTH) && !eku.includes(EKU_ANY)) {
		return {
			ok: false,
			step: "leaf certificate extendedKeyUsage does not include clientAuth (RFC 5280 §4.2.1.12)",
		};
	}

	return { ok: true };
};

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

	// Step 2 (#280): leaf certificate profile. Runs BEFORE the chain walk so a
	// server certificate presented as a client credential reports that, rather
	// than reporting "no path to trust anchor" and sending the operator to look
	// at their CA configuration instead of the certificate they issued.
	const profile = checkClientLeafProfile(leaf);
	if (!profile.ok) return profile;

	// Step 3: chain walk. Track fingerprints to detect cycles — a malicious
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
			// #280: the anchor list is operator-supplied, so a paste error can put
			// an end-entity certificate in it. Terminating on something that is
			// not allowed to issue certificates would accept a chain no other
			// verifier would.
			if (!issuerIsCA(anchor)) {
				return {
					ok: false,
					step: "trust anchor has basicConstraints CA=false (a non-CA cannot be a trust anchor per RFC 5280 §4.2.1.9)",
				};
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
