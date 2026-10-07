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
const issuerIsCA = (issuer) => issuer.ca === true;
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
const isSignedBy = (subject, issuer) => {
    try {
        return subject.verify(issuer.publicKey);
    }
    catch {
        // `verify` throws when the public key type is incompatible with the
        // subject's signature algorithm. Treat as a verification failure — the
        // chain is rejected, not the whole request.
        return false;
    }
};
export const validateCertChain = (leaf, intermediates, trustedCas, now) => {
    // Step 1: leaf validity window. Step §6.4 of extractor.mts also runs this,
    // but the chain walk repeats it as a defensive double-check — the function
    // is also reachable from other call sites in tests.
    if (now < new Date(leaf.validFrom))
        return { ok: false, step: "leaf cert not yet valid" };
    if (now > new Date(leaf.validTo))
        return { ok: false, step: "leaf cert expired" };
    // Step 2: chain walk. Track fingerprints to detect cycles — a malicious
    // chain could otherwise loop forever or exhaust stack.
    //
    // Per-hop cost is up to 4 .find() scans over the (trustedCas) and
    // (intermediates) arrays — verified-pair lookup + DN-only fallback for
    // the audit-signal distinction. Realistic deployments have <5 hops and
    // <20 anchors so the O(N²) shape is trivially fine; merging the two
    // scans would obscure the audit-reason branching and is not worth it.
    let current = leaf;
    const seen = new Set();
    // Walk depth is bounded by `intermediates.length + 1` (one terminal hop to
    // the trust anchor). +1 prevents off-by-one when leaf is directly signed
    // by an anchor with no intermediates.
    for (let i = 0; i < intermediates.length + 1; i++) {
        const fingerprint = current.fingerprint256;
        if (seen.has(fingerprint))
            return { ok: false, step: "cycle detected" };
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
        const issuer = intermediates.find((iss) => current.checkIssued(iss) && isSignedBy(current, iss));
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
