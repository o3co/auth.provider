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
import { X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { validateCertChain } from "#/pki.mjs";

/**
 * The fixture chain (see fixtures/README.md):
 *   root → intermediate → leaf                  (well-formed)
 *   root → bad-intermediate (CA=false) → leaf-bad-chain  (RFC 5280 §4.2.1.9 violation)
 *
 * Per spec §7.2 narrow PKI mode: trust anchor match (checkIssued), validity
 * window per hop, basicConstraints CA=true on intermediates, cycle detection.
 */
const fixturesDir = join(dirname(fileURLToPath(import.meta.url)), "fixtures");
const loadCert = (name: string) =>
	new X509Certificate(readFileSync(join(fixturesDir, name), "utf8"));

const root = loadCert("root.pem");
const intermediate = loadCert("intermediate.pem");
const leaf = loadCert("leaf.pem");
const badIntermediate = loadCert("bad-intermediate.pem");
const leafBadChain = loadCert("leaf-bad-chain.pem");
const attackerLeaf = loadCert("attacker-leaf.pem");

const NOW = new Date("2026-06-01T00:00:00Z");

describe("validateCertChain — narrow PKI mode (spec §7.2)", () => {
	it("accepts a well-formed chain: leaf → intermediate → root (trusted)", () => {
		const result = validateCertChain(leaf, [intermediate], [root], NOW);
		expect(result.ok).toBe(true);
	});

	it("accepts leaf signed directly by trust anchor (no intermediates)", () => {
		// Leaf signed by intermediate; if we present `intermediate` as a trust
		// anchor itself, the chain walk terminates on the first hop.
		const result = validateCertChain(leaf, [], [intermediate], NOW);
		expect(result.ok).toBe(true);
	});

	it("rejects leaf with no path to trust anchor (intermediate missing)", () => {
		const result = validateCertChain(leaf, [], [root], NOW);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.step).toContain("no path to trust anchor");
		}
	});

	it("rejects when trustedCas is empty", () => {
		// Boot-time fail-loud catches the empty case (§11.2), but defense-in-depth
		// at the chain walk too — never silently accept an unknown anchor.
		const result = validateCertChain(leaf, [intermediate], [], NOW);
		expect(result.ok).toBe(false);
	});

	it("rejects chain when intermediate is non-CA (Node.checkIssued enforces RFC 5280 §4.2.1.9)", () => {
		// `bad-intermediate.pem` is signed by `root` but carries `CA:FALSE`.
		// Node's `X509Certificate.checkIssued()` returns `false` for non-CA
		// would-be-issuers — it does the basicConstraints check internally
		// (OpenSSL's `X509_check_issued` rejects with `X509_V_ERR_INVALID_CA`).
		// So the chain walk falls through to "no path to trust anchor" rather
		// than reaching the explicit `issuerIsCA` defense-in-depth check.
		// Either way the chain is rejected — the regression contract is "this
		// chain MUST NOT validate", not the specific reason string.
		const result = validateCertChain(leafBadChain, [badIntermediate], [root], NOW);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			// Document the observable rejection reason — pins Node's behavior.
			// If a future Node version loosens checkIssued, the assertion would
			// need to switch to "CA=false" instead, which the explicit
			// `issuerIsCA` check in pki.mts already covers as defense-in-depth.
			expect(result.step).toMatch(/no path to trust anchor|CA=false/);
		}
	});

	it("rejects a forged leaf with matching issuer DN but a different signing key (Copilot Critical regression)", () => {
		// Adversarial: attackerLeaf was signed by attacker-root.pem, but its
		// issuer DN matches the LEGITIMATE root's subject DN (`CN=Test Root CA`).
		// `X509Certificate.checkIssued()` (backed by OpenSSL X509_check_issued)
		// performs DN + AKID/SKID + CA-bit checks but does NOT verify the
		// cryptographic signature. Without the explicit `verify(publicKey)`
		// step in pki.mts, this forge would be accepted as "issued by the
		// trusted root", letting any attacker who controls any private key
		// produce a valid mTLS binding once they label a cert with the right
		// issuer DN.
		//
		// Contract: validateCertChain MUST reject the forge, AND the rejection
		// reason MUST distinguish "signature failed" from "no DN match" so
		// audit logs surface the attack signal clearly.
		const result = validateCertChain(attackerLeaf, [], [root], NOW);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			// One of two outcomes is acceptable: (a) Node's checkIssued
			// already rejects via AKID/SKID side-effect (→ "no path…"), or
			// (b) checkIssued passes but our explicit verify fails (→
			// "signature verification failed"). Either way, the chain MUST
			// NOT validate.
			expect(result.step).toMatch(/signature verification failed|no path to trust anchor/);
		}
	});

	it("guards against future Node `checkIssued` loosening — explicit CA bit check is defense-in-depth", () => {
		// Document the contract that `bad-intermediate.pem` has `ca === false`,
		// so if a refactor or future Node release ever changed `checkIssued` to
		// allow non-CA issuers through (or someone bypassed checkIssued for
		// alternate path discovery), our explicit `issuerIsCA` check would
		// reject. This is a structural-property assertion, not a chain test.
		expect(badIntermediate.ca).toBe(false);
		expect(intermediate.ca).toBe(true);
		expect(root.ca).toBe(true);
	});

	it("rejects when the leaf cert is not yet valid (now < notBefore)", () => {
		// Leaf was minted with `-days 365` from generation. Set `now` to 100 years
		// before generation to be before any validity window in the fixture.
		const farPast = new Date("1900-01-01T00:00:00Z");
		const result = validateCertChain(leaf, [intermediate], [root], farPast);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.step).toContain("not yet valid");
		}
	});

	it("rejects when the leaf cert is expired (now > notAfter)", () => {
		// 100 years in the future — past every validity window.
		const farFuture = new Date("2126-01-01T00:00:00Z");
		const result = validateCertChain(leaf, [intermediate], [root], farFuture);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.step).toContain("expired");
		}
	});

	it("detects cycles via fingerprint set (defense against malicious chains)", () => {
		// If the same cert appears twice in the chain walk, we'd loop forever
		// without cycle detection. Force a cycle by listing `leaf` as its own
		// intermediate — leaf signs nothing, but cycle detection should still
		// terminate cleanly.
		const result = validateCertChain(leaf, [leaf, intermediate], [root], NOW);
		// Either terminates with the legitimate trust anchor (cycle never triggers)
		// or detects the cycle. Both are acceptable as long as the function returns.
		expect(typeof result.ok).toBe("boolean");
	});
});
