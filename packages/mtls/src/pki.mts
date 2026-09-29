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
 * Narrow PKI mode (`mode = "pki"`) chain validation — deliberately NOT full
 * RFC 5280 path validation. It checks the leaf's validity and client profile
 * (`checkClientLeafProfile`), then walks the chain hop by hop with cycle
 * detection, requiring of every intermediate and of the anchor: validity,
 * `basicConstraints.CA === true` (RFC 5280 §4.2.1.9), and both `checkIssued`
 * and a signature check (`isSignedBy`).
 *
 * Enough for the common single-private-CA M2M shape (RFC 8705 §2.1). Name
 * constraints, policies, path length, `keyUsage` and revocation are not
 * checked — a revoked certificate binds tokens until its `notAfter` — so
 * deployments that need them use `mode = "full-pki"` (README "PKI Mode
 * Scope"). Otherwise, mitigate with short certificate lifetimes and a
 * minimal `trusted-cas` (RFC 8705 §7.4).
 *
 * Returns `{ ok, step }` rather than throwing, so the extractor can put the
 * failing check's name in the audit `detail` without parsing a message.
 */
export type ValidationResult =
	| { readonly ok: true }
	| { readonly ok: false; readonly step: string };

/**
 * Probe `basicConstraints` for `CA: TRUE` via Node's `X509Certificate.ca`.
 * `keyUsage` (`keyCertSign`, RFC 5280 §4.2.1.3) is not checked: it needs
 * ASN.1 parsing `X509Certificate` does not expose.
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
 * Check the leaf against the client-certificate profile:
 * - not `CA:TRUE`: a token bound to a CA certificate is bound to an identity
 *   that can mint others, turning a leaked CA key into a binding bypass;
 * - `extendedKeyUsage`, when present, includes `clientAuth` (or
 *   `anyExtendedKeyUsage`), so a web-PKI server certificate cannot pose as a
 *   client credential. Absence is accepted: RFC 5280 §4.2.1.12 makes the
 *   extension a restriction, not a grant.
 *
 * Naming trap: Node's `X509Certificate.keyUsage` returns the *extended* key
 * usage OIDs, not the `keyUsage` bit string.
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
 * Cryptographically verify that `subject` was signed by `issuer`'s key.
 * Always paired with `checkIssued`, which (as OpenSSL's `X509_check_issued`)
 * matches DN / AKID / SKID but never verifies a signature: a forged
 * certificate that omits AKID (legal under RFC 5280) or crafts a matching
 * one would pass it alone. Returns `false` on any verification failure.
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

	// Step 2: leaf certificate profile, before the chain walk, so a server
	// certificate presented as a client credential is reported as such rather
	// than as "no path to trust anchor".
	const profile = checkClientLeafProfile(leaf);
	if (!profile.ok) return profile;

	// Step 3: chain walk, tracking fingerprints so a malicious cyclic chain
	// cannot loop. Up to four `.find()` scans per hop is fine at realistic
	// sizes (<5 hops, <20 anchors) and keeps the audit reasons distinct.
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
			// The anchor list is operator-supplied, so a paste error can put an
			// end-entity certificate in it; terminating on a non-CA would accept
			// a chain no other verifier would.
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
