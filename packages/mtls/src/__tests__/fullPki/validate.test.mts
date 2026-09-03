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
 * `mode = "full-pki"` — the checks #341 enumerated, and the revocation
 * behaviour that is the reason the issue was filed.
 *
 * Each `it` maps to one item on the issue's list, and the revocation block
 * exercises the distinction the issue insists on: "the CRL endpoint is down"
 * and "the certificate is revoked" must be separable, operator-chosen
 * outcomes.
 */

import type * as pkijs from "pkijs";
import { describe, expect, it, vi } from "vitest";
import {
	checkAlgorithmPolicy,
	DEFAULT_SIGNATURE_ALGORITHMS,
	SIGNATURE_ALGORITHM_OIDS,
} from "#/fullPki/algorithms.mjs";
import { FULL_PKI_DEFAULTS, resolveFullPkiTuning } from "#/fullPki/defaults.mjs";
import type { FullPkiOptions, RevocationPolicy } from "#/fullPki/validate.mjs";
import { createFullPkiValidator } from "#/fullPki/validate.mjs";
import { mtlsConfigSchema } from "#/module.mjs";
import type { Minted } from "./pkiFactory.mjs";
import {
	basicConstraints,
	clientAuthEku,
	criticalClientAuthEku,
	crlDistributionPoints,
	dnsSan,
	emptyCriticalKeyUsage,
	issuingDistributionPoint,
	KEY_USAGE,
	keyUsage,
	mint,
	mintCa,
	mintCrl,
	mintIntermediate,
	mintLeaf,
	nameConstraints,
	reasonPartitionedCrlDistributionPoint,
	serverAuthEku,
	unknownCriticalExtension,
	unparseableCriticalKeyUsage,
} from "./pkiFactory.mjs";

const NOW = new Date("2027-01-01T00:00:00Z");
/** The intermediate issues the leaf, so the leaf's CRL is published by it. */
const INT_CRL_URL = "http://crl.test/int.crl";
/** The root issues the intermediate, so the intermediate's CRL comes from the root. */
const ROOT_CRL_URL = "http://crl.test/root.crl";

const REVOCATION_OFF: RevocationPolicy = { mode: "disabled" };

const crlPolicy = (onUnavailable: "reject" | "allow"): RevocationPolicy => ({
	mode: "crl",
	onUnavailable,
	allowedHosts: ["crl.test"],
	fetchTimeoutMs: 1_000,
	cacheTtlSeconds: 3_600,
	maxResponseBytes: 1_000_000,
});

/**
 * A `fetch` that answers from a fixed table and records every call, so a test
 * can assert not only what came back but whether a request happened at all —
 * which is the whole point of the allowlist and of validating before
 * fetching.
 */
const stubFetch = (table: Record<string, Uint8Array | number>) => {
	const calls: string[] = [];
	const impl = (async (input: URL | RequestInfo) => {
		const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
		calls.push(url);
		const entry = table[url];
		if (entry === undefined) return new Response(null, { status: 404 });
		if (typeof entry === "number") return new Response(null, { status: entry });
		return new Response(entry as unknown as BodyInit, { status: 200 });
	}) as unknown as typeof globalThis.fetch;
	return { impl, calls };
};

/**
 * `stubFetch` that records each request immediately but answers none of them
 * until `release()` — to observe what is in flight while nothing has answered.
 */
const deferredFetch = (table: Record<string, Uint8Array | number>) => {
	const inner = stubFetch(table);
	const calls: string[] = [];
	const gate = { release: (): void => {} };
	const opened = new Promise<void>((resolve) => {
		gate.release = resolve;
	});
	const impl = (async (input: URL | RequestInfo, init?: RequestInit) => {
		calls.push(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
		await opened;
		return inner.impl(input, init);
	}) as unknown as typeof globalThis.fetch;
	return { impl, calls, release: () => gate.release() };
};

/** Let queued I/O callbacks run, up to `ticks` times or until `done()` holds. */
const waitFor = async (done: () => boolean, ticks = 200): Promise<void> => {
	for (let i = 0; i < ticks && !done(); i++) {
		await new Promise<void>((resolve) => setImmediate(resolve));
	}
};

const validator = (trustedCas: readonly Minted[], overrides: Partial<FullPkiOptions> = {}) =>
	createFullPkiValidator({
		trustedCas: trustedCas.map((ca) => ca.x509),
		algorithms: { signatureAlgorithms: DEFAULT_SIGNATURE_ALGORITHMS, minRsaKeyBits: 2048 },
		maxChainDepth: 6,
		revocation: REVOCATION_OFF,
		...overrides,
	});

// ---------------------------------------------------------------------------
// Path validation — the RFC 5280 checks the narrow mode could not express
// ---------------------------------------------------------------------------

describe("full-pki path validation", () => {
	it("accepts leaf → intermediate → root", async () => {
		const root = await mintCa("Root", 1);
		const int = await mintIntermediate("Intermediate", 2, root);
		const leaf = await mintLeaf("client", 10, int);

		const result = await validator([root]).validate(leaf.x509, [int.x509], NOW);
		expect(result).toEqual({ ok: true });
	});

	it("rejects a chain whose anchor is not configured", async () => {
		const root = await mintCa("Root", 1);
		const rogue = await mintCa("Rogue Root", 100);
		const int = await mintIntermediate("Intermediate", 2, rogue);
		const leaf = await mintLeaf("client", 10, int);

		const result = await validator([root]).validate(leaf.x509, [int.x509], NOW);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.step).toBe("no path to trust anchor");
	});

	it("rejects an unrecognised CRITICAL extension (#341 item 4, RFC 5280 §6.1.2)", async () => {
		// The narrow mode ignored these, which is the exact opposite of what
		// "critical" means: the issuer marked the extension as one a validator
		// must understand before trusting the certificate.
		const root = await mintCa("Root", 1);
		const leaf = await mint({
			cn: "client",
			serial: 10,
			issuer: root,
			extensions: [basicConstraints(false), clientAuthEku(), unknownCriticalExtension()],
		});

		const result = await validator([root]).validate(leaf.x509, [], NOW);
		expect(result.ok).toBe(false);
	});

	it("rejects an issuer whose keyUsage omits keyCertSign (#341 item 5)", async () => {
		// RFC 5280 §4.2.1.3: when keyUsage is present on a CA it MUST include
		// keyCertSign to sign certificates. Node's X509Certificate.keyUsage
		// returns *extended* key usage, so the narrow mode could not see this.
		const root = await mintCa("Root", 1);
		const int = await mintIntermediate("Intermediate", 2, root, {
			extensions: [basicConstraints(true), keyUsage(KEY_USAGE.digitalSignature)],
		});
		const leaf = await mintLeaf("client", 10, int);

		const result = await validator([root]).validate(leaf.x509, [int.x509], NOW);
		expect(result.ok).toBe(false);
	});

	it("rejects a path deeper than pathLenConstraint permits (#341 item 6)", async () => {
		// `pathlen:0` on the root says "no sub-CAs beneath me". The chain below
		// has one, so the root's own statement forbids it. pkijs does not
		// implement this check — `checkPathLength` in validate.mts does.
		const root = await mintCa("Root", 1, {
			extensions: [basicConstraints(true, 0), keyUsage(KEY_USAGE.keyCertSign | KEY_USAGE.cRLSign)],
		});
		const int = await mintIntermediate("Intermediate", 2, root);
		const leaf = await mintLeaf("client", 10, int);

		const result = await validator([root]).validate(leaf.x509, [int.x509], NOW);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.step).toBe("pathLenConstraint exceeded");
	});

	it("accepts a path exactly at pathLenConstraint", async () => {
		// The boundary in the other direction: `pathlen:0` on the *intermediate*
		// permits the leaf directly beneath it. An off-by-one here would reject
		// every ordinary two-hop chain.
		const root = await mintCa("Root", 1);
		const int = await mintIntermediate("Intermediate", 2, root, {
			extensions: [basicConstraints(true, 0), keyUsage(KEY_USAGE.keyCertSign | KEY_USAGE.cRLSign)],
		});
		const leaf = await mintLeaf("client", 10, int);

		const result = await validator([root]).validate(leaf.x509, [int.x509], NOW);
		expect(result).toEqual({ ok: true });
	});

	it("enforces excluded name constraints (#341 item 3)", async () => {
		// A trust anchor constrained to a namespace was treated as unconstrained
		// by the narrow mode — an intermediate could issue for anything.
		const root = await mintCa("Root", 1);
		const int = await mintIntermediate("Intermediate", 2, root, {
			extensions: [
				basicConstraints(true),
				keyUsage(KEY_USAGE.keyCertSign | KEY_USAGE.cRLSign),
				nameConstraints({ excludedDns: ["forbidden.test"] }),
			],
		});
		const leaf = await mint({
			cn: "client",
			serial: 10,
			issuer: int,
			extensions: [basicConstraints(false), clientAuthEku(), dnsSan(["host.forbidden.test"])],
		});

		const result = await validator([root]).validate(leaf.x509, [int.x509], NOW);
		expect(result.ok).toBe(false);
	});

	it("accepts a name inside the permitted subtree", async () => {
		const root = await mintCa("Root", 1);
		const int = await mintIntermediate("Intermediate", 2, root, {
			extensions: [
				basicConstraints(true),
				keyUsage(KEY_USAGE.keyCertSign | KEY_USAGE.cRLSign),
				nameConstraints({ permittedDns: ["allowed.test"] }),
			],
		});
		const leaf = await mint({
			cn: "client",
			serial: 10,
			issuer: int,
			extensions: [basicConstraints(false), clientAuthEku(), dnsSan(["host.allowed.test"])],
		});

		const result = await validator([root]).validate(leaf.x509, [int.x509], NOW);
		expect(result).toEqual({ ok: true });
	});

	it("refuses a CRITICAL keyUsage whose value is not parseable DER", async () => {
		// The other half of RFC 5280 §6.1.2: the rule covers an unrecognised
		// critical extension *or* one "that contains information that it cannot
		// process". The OID here is recognised, so a check that compares only
		// OIDs accepts it — while nothing has actually read the restriction.
		const root = await mintCa("Root", 1);
		const leaf = await mint({
			cn: "client",
			serial: 10,
			issuer: root,
			extensions: [basicConstraints(false), clientAuthEku(), unparseableCriticalKeyUsage()],
		});

		const result = await validator([root]).validate(leaf.x509, [], NOW);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.step).toBe("unparseable critical extension");
	});

	it("refuses a CRITICAL keyUsage that parses but carries no bits", async () => {
		// The subtler form: everything parses, and an empty bit string reads as
		// "no restrictions" — the inverse of what a critical restriction means.
		// Absence of the extension is unconstrained; an unreadable value is not.
		const root = await mintCa("Root", 1);
		const leaf = await mint({
			cn: "client",
			serial: 10,
			issuer: root,
			extensions: [basicConstraints(false), clientAuthEku(), emptyCriticalKeyUsage()],
		});

		const result = await validator([root]).validate(leaf.x509, [], NOW);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.step).toBe("unparseable leaf keyUsage");
	});

	it("refuses a critical extendedKeyUsage on a CA, which would mean EKU chaining", async () => {
		// Recognised on the leaf, where `checkClientLeafProfile` acts on it.
		// On a CA it asks for a constraint RFC 5280 does not define and this
		// module does not implement, so "critical" must mean refused.
		const root = await mintCa("Root", 1);
		const int = await mintIntermediate("Intermediate", 2, root, {
			extensions: [
				basicConstraints(true),
				keyUsage(KEY_USAGE.keyCertSign | KEY_USAGE.cRLSign),
				criticalClientAuthEku(),
			],
		});
		const leaf = await mintLeaf("client", 10, int);

		const result = await validator([root]).validate(leaf.x509, [int.x509], NOW);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.step).toBe("unrecognised critical extension");
	});

	it("keeps the narrow mode's leaf profile: a CA certificate is not a client credential", async () => {
		// The stricter arm must not be weaker anywhere. `full-pki` imports the
		// same `checkClientLeafProfile` `mode = "pki"` uses rather than
		// restating it.
		const root = await mintCa("Root", 1);
		const leaf = await mint({
			cn: "client",
			serial: 10,
			issuer: root,
			extensions: [basicConstraints(true), clientAuthEku()],
		});

		const result = await validator([root]).validate(leaf.x509, [], NOW);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.step).toContain("CA=true");
	});

	it("keeps the narrow mode's leaf profile: a serverAuth-only certificate is refused", async () => {
		const root = await mintCa("Root", 1);
		const leaf = await mint({
			cn: "client",
			serial: 10,
			issuer: root,
			extensions: [basicConstraints(false), serverAuthEku()],
		});

		const result = await validator([root]).validate(leaf.x509, [], NOW);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.step).toContain("clientAuth");
	});

	it("refuses a leaf whose keyUsage excludes digitalSignature", async () => {
		// A client certificate authenticates by signing in the handshake, so
		// this keyUsage describes a key that cannot do what the certificate is
		// being presented to do.
		const root = await mintCa("Root", 1);
		const leaf = await mint({
			cn: "client",
			serial: 10,
			issuer: root,
			extensions: [basicConstraints(false), keyUsage(KEY_USAGE.keyEncipherment), clientAuthEku()],
		});

		const result = await validator([root]).validate(leaf.x509, [], NOW);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.step).toBe("leaf keyUsage excludes digitalSignature");
	});

	it("accepts a leaf with no keyUsage extension at all", async () => {
		// RFC 5280 §4.2.1.3 makes the extension a restriction, not a grant.
		const root = await mintCa("Root", 1);
		const leaf = await mint({
			cn: "client",
			serial: 10,
			issuer: root,
			extensions: [basicConstraints(false), clientAuthEku()],
		});

		const result = await validator([root]).validate(leaf.x509, [], NOW);
		expect(result).toEqual({ ok: true });
	});

	it("refuses a chain longer than maxChainDepth before verifying any signature", async () => {
		const root = await mintCa("Root", 1);
		const leaf = await mintLeaf("client", 10, root);
		const filler = Array.from({ length: 8 }, () => leaf.x509);

		const result = await validator([root], { maxChainDepth: 3 }).validate(leaf.x509, filler, NOW);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.step).toBe("chain too long");
	});
});

// ---------------------------------------------------------------------------
// Algorithm policy (#341 item 8)
// ---------------------------------------------------------------------------

describe("full-pki algorithm policy", () => {
	it("rejects an RSA key below the configured minimum", async () => {
		const root = await mintCa("Root", 1);
		const leaf = await mintLeaf("client", 10, root, { algorithm: "rsa-1024" });

		const result = await validator([root]).validate(leaf.x509, [], NOW);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.step).toBe("rsa key too small");
	});

	it("accepts an RSA key at the configured minimum", async () => {
		const root = await mintCa("Root", 1);
		const leaf = await mintLeaf("client", 10, root, { algorithm: "rsa-2048" });

		const result = await validator([root]).validate(leaf.x509, [], NOW);
		expect(result).toEqual({ ok: true });
	});

	it("rejects a signature algorithm outside the allowlist", async () => {
		// Unit-level rather than through the engine: whether Node's WebCrypto
		// will even verify a SHA-1 ECDSA signature is a platform detail, and the
		// policy must hold regardless of which layer notices first.
		const root = await mintCa("Root", 1);
		const check = checkAlgorithmPolicy(root.x509, "1.2.840.10045.4.1", {
			signatureAlgorithms: DEFAULT_SIGNATURE_ALGORITHMS,
			minRsaKeyBits: 2048,
		});
		expect(check.ok).toBe(false);
	});

	it("applies the allowlist to every certificate on the path, not only the leaf", async () => {
		// A chain is as strong as its weakest hop. Narrowing the policy to
		// EdDSA rejects an ECDSA root even though the leaf is unchanged.
		const root = await mintCa("Root", 1);
		const leaf = await mintLeaf("client", 10, root);

		const result = await validator([root], {
			algorithms: { signatureAlgorithms: ["ed25519"], minRsaKeyBits: 2048 },
		}).validate(leaf.x509, [], NOW);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.step).toBe("signature algorithm not permitted");
	});

	it("has no name for SHA-1 at all, so no configuration can allow it", () => {
		expect(Object.values(SIGNATURE_ALGORITHM_OIDS)).not.toContain("1.2.840.10045.4.1");
		expect(Object.values(SIGNATURE_ALGORITHM_OIDS)).not.toContain("1.2.840.113549.1.1.5");
	});
});

describe("full-pki tuning defaults", () => {
	it("bounds the chain even when max-chain-depth never reaches the validator", async () => {
		// A composition root that builds the mechanism by hand bypasses
		// `mtlsConfigSchema` and its defaults. An absent depth arriving as
		// `undefined` makes `presented > undefined` evaluate to `false`, so the
		// bound silently stops existing — a fail-open with nothing raised at
		// boot. `resolveFullPkiTuning` is what stops that.
		const resolved = resolveFullPkiTuning(undefined);
		expect(resolved.maxChainDepth).toBe(FULL_PKI_DEFAULTS.maxChainDepth);
		expect(resolved.minRsaKeyBits).toBe(FULL_PKI_DEFAULTS.minRsaKeyBits);
		expect(resolved.signatureAlgorithms.length).toBeGreaterThan(0);
	});

	it("keeps the values a caller did supply", async () => {
		const resolved = resolveFullPkiTuning({
			"max-chain-depth": 3,
			"min-rsa-key-bits": 4096,
			"signature-algorithms": ["ed25519"],
		});
		expect(resolved).toEqual({
			maxChainDepth: 3,
			minRsaKeyBits: 4096,
			signatureAlgorithms: ["ed25519"],
		});
	});

	it("treats an empty signature-algorithms list as unset rather than as 'permit nothing'", async () => {
		// An empty allowlist would reject every certificate at every hop. That
		// is a configuration mistake, not a policy, and failing every request
		// with no boot signal is the worst way to report it.
		const resolved = resolveFullPkiTuning({ "signature-algorithms": [] });
		expect(resolved.signatureAlgorithms).toEqual(FULL_PKI_DEFAULTS.signatureAlgorithms);
	});

	it("the schema default and the code default are the same value", async () => {
		// Two consumers, one source. Written twice they would eventually
		// disagree, and only the path nobody tests by default would notice.
		const parsed = mtlsConfigSchema.parse({
			oauth: {
				mtls: {
					enabled: true,
					mode: "full-pki",
					"full-pki": { revocation: { mode: "disabled", "on-unavailable": "reject" } },
				},
			},
		});
		expect(parsed.oauth.mtls["full-pki"]?.["max-chain-depth"]).toBe(
			FULL_PKI_DEFAULTS.maxChainDepth,
		);
		expect(parsed.oauth.mtls["full-pki"]?.["min-rsa-key-bits"]).toBe(
			FULL_PKI_DEFAULTS.minRsaKeyBits,
		);
	});
});

// ---------------------------------------------------------------------------
// Revocation (#341 item 1) — the reason the issue exists
// ---------------------------------------------------------------------------

describe("full-pki revocation", () => {
	/**
	 * Every certificate on the path except the anchor needs its own revocation
	 * answer, and a CRL only covers what its issuer issued — so the
	 * intermediate's status comes from a root-signed CRL, not from the one it
	 * publishes itself.
	 */
	const buildChain = async () => {
		const root = await mintCa("Root", 1);
		const int = await mintIntermediate("Intermediate", 2, root, {
			extensions: [
				basicConstraints(true),
				keyUsage(KEY_USAGE.keyCertSign | KEY_USAGE.cRLSign),
				crlDistributionPoints([ROOT_CRL_URL]),
			],
		});
		const leaf = await mintLeaf("client", 10, int, {
			extensions: [
				basicConstraints(false),
				keyUsage(KEY_USAGE.digitalSignature),
				clientAuthEku(),
				crlDistributionPoints([INT_CRL_URL]),
			],
		});
		return { root, int, leaf };
	};

	/** A root-signed CRL revoking nothing — the intermediate's clean status. */
	const cleanRootCrl = (root: Minted) => mintCrl({ issuer: root, revoked: [] });

	it("rejects a certificate listed on a valid CRL", async () => {
		const { root, int, leaf } = await buildChain();
		const crl = await mintCrl({ issuer: int, revoked: [leaf] });
		const { impl } = stubFetch({ [INT_CRL_URL]: crl, [ROOT_CRL_URL]: await cleanRootCrl(root) });

		const result = await validator([root], {
			revocation: crlPolicy("reject"),
			fetchImpl: impl,
		}).validate(leaf.x509, [int.x509], NOW);

		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.step).toBe("certificate revoked");
	});

	it("accepts a certificate absent from a valid CRL", async () => {
		const { root, int, leaf } = await buildChain();
		const crl = await mintCrl({ issuer: int, revoked: [] });
		const { impl } = stubFetch({ [INT_CRL_URL]: crl, [ROOT_CRL_URL]: await cleanRootCrl(root) });

		const result = await validator([root], {
			revocation: crlPolicy("reject"),
			fetchImpl: impl,
		}).validate(leaf.x509, [int.x509], NOW);

		expect(result).toEqual({ ok: true });
	});

	it("REJECTS when the CRL cannot be fetched and the policy is 'reject'", async () => {
		// The finding this whole arm turns on. pkijs, handed no CRLs, skips its
		// revocation block and returns `valid` — so "the CRL server is down" and
		// "not revoked" reach the engine as the same input. If this test ever
		// passes for the wrong reason, a revoked certificate goes on working
		// during exactly the outage an attacker would arrange.
		const { root, int, leaf } = await buildChain();
		const { impl, calls } = stubFetch({ [INT_CRL_URL]: 503, [ROOT_CRL_URL]: 503 });

		const result = await validator([root], {
			revocation: crlPolicy("reject"),
			fetchImpl: impl,
		}).validate(leaf.x509, [int.x509], NOW);

		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.step).toBe("revocation status unavailable");
		expect(calls).toContain(INT_CRL_URL);
	});

	it("allows the same unreachable CRL when the policy is 'allow', and logs it", async () => {
		const { root, int, leaf } = await buildChain();
		const { impl } = stubFetch({ [INT_CRL_URL]: 503, [ROOT_CRL_URL]: 503 });
		const logger = { warn: vi.fn(), debug: vi.fn() };

		const result = await validator([root], {
			revocation: crlPolicy("allow"),
			fetchImpl: impl,
			logger,
		}).validate(leaf.x509, [int.x509], NOW);

		expect(result).toEqual({ ok: true });
		// Soft-fail is a choice, not a silence: an operator who picked "allow"
		// must still be able to see how often it fires.
		expect(logger.warn).toHaveBeenCalledWith(
			expect.objectContaining({ reason: "fetch_failed" }),
			"mtls_revocation_unavailable_allowed",
		);
	});

	it("under 'allow', a forged CRL is soft-failed with the warn line, not accepted silently", async () => {
		// Before the signature was checked locally, a forged CRL reached the
		// engine, whose findCRL answered "no valid CRLs" — a status the
		// soft-fail flag suppressed — and the certificate passed with no
		// mtls_revocation_unavailable_allowed line at all. "allow" is a choice
		// the operator must be able to watch being exercised.
		const { root, int, leaf } = await buildChain();
		const impostor = await mintCa("Impostor", 900);
		const forged = await mintCrl({ issuer: int, revoked: [], signingKeys: impostor.keys });
		const { impl } = stubFetch({ [INT_CRL_URL]: forged, [ROOT_CRL_URL]: await cleanRootCrl(root) });
		const logger = { warn: vi.fn(), debug: vi.fn() };

		const result = await validator([root], {
			revocation: crlPolicy("allow"),
			fetchImpl: impl,
			logger,
		}).validate(leaf.x509, [int.x509], NOW);

		expect(result).toEqual({ ok: true });
		expect(logger.warn).toHaveBeenCalledTimes(1);
		expect(logger.warn).toHaveBeenCalledWith(
			expect.objectContaining({ subject: "CN=client", reason: "bad_signature" }),
			"mtls_revocation_unavailable_allowed",
		);
	});

	it("honours 'allow' in a partial outage: only the certificate whose CRL is down is waved through", async () => {
		// The common outage shape — the leaf's distribution point is down, the
		// intermediate's is up. Handing the engine the CRLs that *were* fetched
		// made it throw noRevocation for the leaf because its issuer carries a
		// CDP extension, so "allow" rejected. The lookup is now local, per
		// certificate, and the policy applies to each one on its own.
		const { root, int, leaf } = await buildChain();
		const { impl } = stubFetch({ [INT_CRL_URL]: 503, [ROOT_CRL_URL]: await cleanRootCrl(root) });
		const logger = { warn: vi.fn(), debug: vi.fn() };

		const result = await validator([root], {
			revocation: crlPolicy("allow"),
			fetchImpl: impl,
			logger,
		}).validate(leaf.x509, [int.x509], NOW);

		expect(result).toEqual({ ok: true });
		// Exactly one soft-fail — the leaf's. The intermediate was checked and
		// must not be reported as waved through.
		expect(logger.warn).toHaveBeenCalledTimes(1);
		expect(logger.warn).toHaveBeenCalledWith(
			expect.objectContaining({ subject: "CN=client", reason: "fetch_failed" }),
			"mtls_revocation_unavailable_allowed",
		);
	});

	it("refuses the same partial outage under 'reject'", async () => {
		const { root, int, leaf } = await buildChain();
		const { impl } = stubFetch({ [INT_CRL_URL]: 503, [ROOT_CRL_URL]: await cleanRootCrl(root) });
		const logger = { warn: vi.fn(), debug: vi.fn() };

		const result = await validator([root], {
			revocation: crlPolicy("reject"),
			fetchImpl: impl,
			logger,
		}).validate(leaf.x509, [int.x509], NOW);

		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.step).toBe("revocation status unavailable");
		expect(logger.warn).toHaveBeenCalledWith(
			expect.objectContaining({ subject: "CN=client", reason: "fetch_failed" }),
			"mtls_revocation_unavailable_rejected",
		);
		expect(logger.warn).not.toHaveBeenCalledWith(
			expect.anything(),
			"mtls_revocation_unavailable_allowed",
		);
	});

	it.each(["reject", "allow"] as const)(
		"refuses a revoked leaf under '%s'",
		async (onUnavailable) => {
			// Soft-fail covers a status that cannot be determined. A status that
			// *was* determined, and is "revoked", is not softened by the policy.
			const { root, int, leaf } = await buildChain();
			const { impl } = stubFetch({
				[INT_CRL_URL]: await mintCrl({ issuer: int, revoked: [leaf] }),
				[ROOT_CRL_URL]: await cleanRootCrl(root),
			});

			const result = await validator([root], {
				revocation: crlPolicy(onUnavailable),
				fetchImpl: impl,
			}).validate(leaf.x509, [int.x509], NOW);

			expect(result.ok).toBe(false);
			if (!result.ok) expect(result.step).toBe("certificate revoked");
		},
	);

	it.each(["reject", "allow"] as const)(
		"refuses a revoked intermediate under '%s'",
		async (onUnavailable) => {
			// The intermediate's status comes from the root-signed CRL, and a
			// revoked CA takes every certificate beneath it with it.
			const { root, int, leaf } = await buildChain();
			const { impl } = stubFetch({
				[INT_CRL_URL]: await mintCrl({ issuer: int, revoked: [] }),
				[ROOT_CRL_URL]: await mintCrl({ issuer: root, revoked: [int] }),
			});

			const result = await validator([root], {
				revocation: crlPolicy(onUnavailable),
				fetchImpl: impl,
			}).validate(leaf.x509, [int.x509], NOW);

			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.step).toBe("certificate revoked");
				expect(result.detail).toContain("CN=Intermediate");
			}
		},
	);

	it("refuses a revoked leaf under 'allow' even while the intermediate's CRL is down", async () => {
		// Two facts on one path: one certificate's status is unknown, the
		// other's is "revoked". Waving the first through must not wave the
		// second through with it.
		const { root, int, leaf } = await buildChain();
		const { impl } = stubFetch({
			[INT_CRL_URL]: await mintCrl({ issuer: int, revoked: [leaf] }),
			[ROOT_CRL_URL]: 503,
		});
		const logger = { warn: vi.fn(), debug: vi.fn() };

		const result = await validator([root], {
			revocation: crlPolicy("allow"),
			fetchImpl: impl,
			logger,
		}).validate(leaf.x509, [int.x509], NOW);

		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.step).toBe("certificate revoked");
	});

	it("treats a certificate with no distribution point as unavailable, not as clean", async () => {
		const root = await mintCa("Root", 1);
		const leaf = await mintLeaf("client", 10, root);
		const { impl, calls } = stubFetch({});

		const result = await validator([root], {
			revocation: crlPolicy("reject"),
			fetchImpl: impl,
		}).validate(leaf.x509, [], NOW);

		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.detail).toContain("no_distribution_point");
		expect(calls).toEqual([]);
	});

	it("treats an expired CRL as unavailable rather than authoritative", async () => {
		const { root, int, leaf } = await buildChain();
		const stale = await mintCrl({
			issuer: int,
			revoked: [],
			thisUpdate: new Date("2026-01-01T00:00:00Z"),
			nextUpdate: new Date("2026-02-01T00:00:00Z"),
		});
		const { impl } = stubFetch({ [INT_CRL_URL]: stale, [ROOT_CRL_URL]: await cleanRootCrl(root) });

		const result = await validator([root], {
			revocation: crlPolicy("reject"),
			fetchImpl: impl,
		}).validate(leaf.x509, [int.x509], NOW);

		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.detail).toContain("stale");
	});

	it("treats a CRL with no nextUpdate as unavailable", async () => {
		// Without nextUpdate there is no way to tell a current CRL from one
		// captured before a revocation and replayed.
		const { root, int, leaf } = await buildChain();
		const undated = await mintCrl({ issuer: int, revoked: [], nextUpdate: null });
		const { impl } = stubFetch({
			[INT_CRL_URL]: undated,
			[ROOT_CRL_URL]: await cleanRootCrl(root),
		});

		const result = await validator([root], {
			revocation: crlPolicy("reject"),
			fetchImpl: impl,
		}).validate(leaf.x509, [int.x509], NOW);

		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.detail).toContain("no_next_update");
	});

	it("treats a CRL signed by the wrong key as unavailable, and never caches it", async () => {
		// A forged CRL that omits a revoked serial would otherwise be a way to
		// un-revoke a certificate — and a forged CRL that is *cached* is a way
		// to refuse every client of that distribution point for up to an hour
		// from one injected response over plain http. The signature is checked
		// against the issuing CA before the CRL is stored, and the failure is
		// reported under its own name so the audit trail says what happened.
		const root = await mintCa("Root", 1);
		const leaf = await mintLeaf("client", 10, root, {
			extensions: [
				basicConstraints(false),
				keyUsage(KEY_USAGE.digitalSignature),
				clientAuthEku(),
				crlDistributionPoints([ROOT_CRL_URL]),
			],
		});
		const impostor = await mintCa("Impostor", 900);
		const forged = await mintCrl({ issuer: root, revoked: [], signingKeys: impostor.keys });
		const { impl, calls } = stubFetch({ [ROOT_CRL_URL]: forged });
		const v = validator([root], { revocation: crlPolicy("reject"), fetchImpl: impl });

		const result = await v.validate(leaf.x509, [], NOW);

		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.step).toBe("revocation status unavailable");
			expect(result.detail).toContain("bad_signature");
		}
		// The forged CRL is not cached, so the next request goes back to the
		// distribution point instead of being refused from memory.
		expect(v.crlCacheSize()).toBe(0);
		await v.validate(leaf.x509, [], NOW);
		expect(calls).toEqual([ROOT_CRL_URL, ROOT_CRL_URL]);
	});

	it("refuses a CRL whose issuer's keyUsage omits cRLSign, even though the signature verifies", async () => {
		// RFC 5280 §6.3.3 (f): a CRL issuer's keyUsage, when present, MUST
		// include cRLSign. Being entitled to sign certificates is not being
		// entitled to publish revocation lists; the bit is the CA's own
		// statement about which of the two this key does.
		const root = await mintCa("Root", 1);
		const int = await mintIntermediate("Intermediate", 2, root, {
			extensions: [
				basicConstraints(true),
				keyUsage(KEY_USAGE.keyCertSign),
				crlDistributionPoints([ROOT_CRL_URL]),
			],
		});
		const leaf = await mintLeaf("client", 10, int, {
			extensions: [
				basicConstraints(false),
				keyUsage(KEY_USAGE.digitalSignature),
				clientAuthEku(),
				crlDistributionPoints([INT_CRL_URL]),
			],
		});
		const { impl } = stubFetch({
			[INT_CRL_URL]: await mintCrl({ issuer: int, revoked: [] }),
			[ROOT_CRL_URL]: await cleanRootCrl(root),
		});

		const result = await validator([root], {
			revocation: crlPolicy("reject"),
			fetchImpl: impl,
		}).validate(leaf.x509, [int.x509], NOW);

		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.step).toBe("revocation status unavailable");
			expect(result.detail).toContain("bad_signature");
		}
	});

	it("makes no outbound request at all when revocation is disabled", async () => {
		const { root, int, leaf } = await buildChain();
		const { impl, calls } = stubFetch({});

		const result = await validator([root], {
			revocation: REVOCATION_OFF,
			fetchImpl: impl,
		}).validate(leaf.x509, [int.x509], NOW);

		expect(result).toEqual({ ok: true });
		expect(calls).toEqual([]);
	});

	it("caches a fetched CRL instead of re-fetching per request", async () => {
		const { root, int, leaf } = await buildChain();
		const crl = await mintCrl({ issuer: int, revoked: [] });
		const { impl, calls } = stubFetch({
			[INT_CRL_URL]: crl,
			[ROOT_CRL_URL]: await cleanRootCrl(root),
		});
		const v = validator([root], { revocation: crlPolicy("reject"), fetchImpl: impl });

		await v.validate(leaf.x509, [int.x509], NOW);
		const firstCallCount = calls.length;
		await v.validate(leaf.x509, [int.x509], NOW);

		expect(calls.length).toBe(firstCallCount);
		expect(v.crlCacheSize()).toBe(2);
	});

	it("resolves the path's CRLs concurrently rather than one after another", async () => {
		// Serial lookups put a fetch-timeout-ms latency floor *per certificate*
		// on the token endpoint during an outage. Both distribution points
		// must be in flight before either has answered.
		const { root, int, leaf } = await buildChain();
		const { impl, calls, release } = deferredFetch({
			[INT_CRL_URL]: await mintCrl({ issuer: int, revoked: [] }),
			[ROOT_CRL_URL]: await cleanRootCrl(root),
		});
		const pending = validator([root], {
			revocation: crlPolicy("reject"),
			fetchImpl: impl,
		}).validate(leaf.x509, [int.x509], NOW);

		await waitFor(() => calls.length >= 1);
		// Give a serial implementation every chance to issue its second request
		// — it cannot, because the first has not answered.
		await waitFor(() => calls.length >= 2, 20);
		expect(new Set(calls)).toEqual(new Set([INT_CRL_URL, ROOT_CRL_URL]));

		release();
		expect(await pending).toEqual({ ok: true });
	});

	it("never fetches a distribution point outside the host allowlist", async () => {
		// A URL inside a certificate is a destination someone else chose. The
		// allowlist is the layer that stops trusting a CA to issue certificates
		// from also meaning trusting it to name destinations inside this network.
		const root = await mintCa("Root", 1);
		const int = await mintIntermediate("Intermediate", 2, root, {
			extensions: [
				basicConstraints(true),
				keyUsage(KEY_USAGE.keyCertSign | KEY_USAGE.cRLSign),
				crlDistributionPoints(["http://169.254.169.254/latest/meta-data/"]),
			],
		});
		const leaf = await mintLeaf("client", 10, int, {
			extensions: [
				basicConstraints(false),
				keyUsage(KEY_USAGE.digitalSignature),
				clientAuthEku(),
				crlDistributionPoints(["http://169.254.169.254/latest/meta-data/"]),
			],
		});
		const { impl, calls } = stubFetch({});

		const result = await validator([root], {
			revocation: crlPolicy("reject"),
			fetchImpl: impl,
		}).validate(leaf.x509, [int.x509], NOW);

		expect(result.ok).toBe(false);
		expect(calls).toEqual([]);
	});
});

describe("full-pki revocation — distribution points and CRL shapes the resolver does not speak (#446, #447)", () => {
	const INT_CRL_MIRROR_URL = "http://crl.test/int-mirror.crl";

	/** root → intermediate → leaf, the leaf carrying `leafPoints` as its cRLDistributionPoints. */
	const chainWith = async (leafPoints: pkijs.Extension) => {
		const root = await mintCa("Root", 1);
		const int = await mintIntermediate("Intermediate", 2, root, {
			extensions: [
				basicConstraints(true),
				keyUsage(KEY_USAGE.keyCertSign | KEY_USAGE.cRLSign),
				crlDistributionPoints([ROOT_CRL_URL]),
			],
		});
		const leaf = await mintLeaf("client", 10, int, {
			extensions: [
				basicConstraints(false),
				keyUsage(KEY_USAGE.digitalSignature),
				clientAuthEku(),
				leafPoints,
			],
		});
		return { root, int, leaf };
	};

	it("under 'reject', refuses a certificate one of whose distribution points is down even though another produced a CRL", async () => {
		// "One point answered" used to be reported as ok, so a point that was
		// down was skipped silently under the policy whose whole meaning is
		// "do not guess". This process cannot tell from one fetched CRL that
		// the CA's other points were redundant — a CA that partitions its
		// list without saying so publishes exactly this shape — and "reject"
		// is the operator's instruction not to guess in the permissive
		// direction.
		const { root, int, leaf } = await chainWith(
			crlDistributionPoints([INT_CRL_URL, INT_CRL_MIRROR_URL]),
		);
		const { impl } = stubFetch({
			[INT_CRL_URL]: await mintCrl({ issuer: int, revoked: [] }),
			[INT_CRL_MIRROR_URL]: 503,
			[ROOT_CRL_URL]: await mintCrl({ issuer: root, revoked: [] }),
		});
		const logger = { warn: vi.fn(), debug: vi.fn() };

		const result = await validator([root], {
			revocation: crlPolicy("reject"),
			fetchImpl: impl,
			logger,
		}).validate(leaf.x509, [int.x509], NOW);

		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.step).toBe("revocation status unavailable");
			expect(result.detail).toContain(INT_CRL_MIRROR_URL);
		}
		expect(logger.warn).toHaveBeenCalledWith(
			expect.objectContaining({ subject: "CN=client", reason: "fetch_failed" }),
			"mtls_revocation_unavailable_rejected",
		);
	});

	it("under 'allow', checks the same certificate against the CRL it did obtain and logs the point it did not", async () => {
		// The permissive guess is what "allow" chose. It is still logged —
		// distinctly from a certificate that was not checked at all, because
		// the two are different facts on an operator's dashboard.
		const { root, int, leaf } = await chainWith(
			crlDistributionPoints([INT_CRL_URL, INT_CRL_MIRROR_URL]),
		);
		const { impl } = stubFetch({
			[INT_CRL_URL]: await mintCrl({ issuer: int, revoked: [] }),
			[INT_CRL_MIRROR_URL]: 503,
			[ROOT_CRL_URL]: await mintCrl({ issuer: root, revoked: [] }),
		});
		const logger = { warn: vi.fn(), debug: vi.fn() };

		const result = await validator([root], {
			revocation: crlPolicy("allow"),
			fetchImpl: impl,
			logger,
		}).validate(leaf.x509, [int.x509], NOW);

		expect(result).toEqual({ ok: true });
		expect(logger.warn).toHaveBeenCalledTimes(1);
		expect(logger.warn).toHaveBeenCalledWith(
			expect.objectContaining({ subject: "CN=client", reason: "fetch_failed" }),
			"mtls_revocation_partially_unavailable_allowed",
		);
	});

	it.each(["reject", "allow"] as const)(
		"under '%s', a certificate listed on the CRL one point produced is refused as revoked, not as unavailable, while another point is down",
		async (onUnavailable) => {
			// A status that *was* determined is not softened by a gap elsewhere
			// — nor renamed by it. Under "reject" the strict-unavailable refusal
			// must come *after* the CRLs that were obtained have been consulted:
			// reporting a certificate an issuer has already revoked as merely
			// "unavailable" tells the audit trail an outage where there was a
			// revocation.
			const { root, int, leaf } = await chainWith(
				crlDistributionPoints([INT_CRL_URL, INT_CRL_MIRROR_URL]),
			);
			const { impl } = stubFetch({
				[INT_CRL_URL]: await mintCrl({ issuer: int, revoked: [leaf] }),
				[INT_CRL_MIRROR_URL]: 503,
				[ROOT_CRL_URL]: await mintCrl({ issuer: root, revoked: [] }),
			});
			const logger = { warn: vi.fn(), debug: vi.fn() };

			const result = await validator([root], {
				revocation: crlPolicy(onUnavailable),
				fetchImpl: impl,
				logger,
			}).validate(leaf.x509, [int.x509], NOW);

			expect(result.ok).toBe(false);
			if (!result.ok) expect(result.step).toBe("certificate revoked");
			// Nothing was waved through and nothing was refused for being
			// unknown, so neither availability line is emitted.
			expect(logger.warn).not.toHaveBeenCalled();
		},
	);

	it("does not refuse a certificate whose distribution point lists one dead mirror among its URIs", async () => {
		// RFC 5280 §4.2.1.13: several names within one point are ways to
		// obtain the same CRL, so one of them answering is the point
		// answering. Strictness is per point, not per URI, or a redundant
		// mirror would make the certificate *less* available.
		const { root, int, leaf } = await chainWith(
			crlDistributionPoints([[INT_CRL_MIRROR_URL, INT_CRL_URL]]),
		);
		const { impl } = stubFetch({
			[INT_CRL_MIRROR_URL]: 503,
			[INT_CRL_URL]: await mintCrl({ issuer: int, revoked: [] }),
			[ROOT_CRL_URL]: await mintCrl({ issuer: root, revoked: [] }),
		});
		const logger = { warn: vi.fn(), debug: vi.fn() };

		const result = await validator([root], {
			revocation: crlPolicy("reject"),
			fetchImpl: impl,
			logger,
		}).validate(leaf.x509, [int.x509], NOW);

		expect(result).toEqual({ ok: true });
		expect(logger.warn).not.toHaveBeenCalled();
	});

	it("treats a certificate whose distribution point carries reasons as unavailable, without fetching it", async () => {
		const { root, int, leaf } = await chainWith(reasonPartitionedCrlDistributionPoint(INT_CRL_URL));
		const { impl, calls } = stubFetch({
			[INT_CRL_URL]: await mintCrl({ issuer: int, revoked: [] }),
			[ROOT_CRL_URL]: await mintCrl({ issuer: root, revoked: [] }),
		});

		const result = await validator([root], {
			revocation: crlPolicy("reject"),
			fetchImpl: impl,
		}).validate(leaf.x509, [int.x509], NOW);

		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.step).toBe("revocation status unavailable");
			expect(result.detail).toContain("unsupported_distribution_point");
		}
		expect(calls).not.toContain(INT_CRL_URL);
	});

	it("treats a CRL scoped by issuingDistributionPoint as unavailable rather than authoritative", async () => {
		// The root publishes a CRL scoped to user certificates at the point
		// the *intermediate* names. pkijs would have accepted it as the
		// intermediate's complete list; it is not, and the intermediate's
		// status is therefore unknown.
		const { root, int, leaf } = await chainWith(crlDistributionPoints([INT_CRL_URL]));
		const { impl } = stubFetch({
			[INT_CRL_URL]: await mintCrl({ issuer: int, revoked: [] }),
			[ROOT_CRL_URL]: await mintCrl({
				issuer: root,
				revoked: [],
				extensions: [issuingDistributionPoint({ onlyContainsUserCerts: true })],
			}),
		});

		const result = await validator([root], {
			revocation: crlPolicy("reject"),
			fetchImpl: impl,
		}).validate(leaf.x509, [int.x509], NOW);

		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.step).toBe("revocation status unavailable");
			expect(result.detail).toContain("CN=Intermediate");
			expect(result.detail).toContain("unsupported_crl_scope");
		}
	});

	it("names a CRL with an unsupported critical extension under its own reason, and does not re-fetch it within the negative window (#447)", async () => {
		// Reported as bad_signature, it was never remembered, and cost one
		// guarded fetch per request under both policies.
		const { root, int, leaf } = await chainWith(crlDistributionPoints([INT_CRL_URL]));
		const { impl, calls } = stubFetch({
			[INT_CRL_URL]: await mintCrl({
				issuer: int,
				revoked: [],
				extensions: [unknownCriticalExtension()],
			}),
			[ROOT_CRL_URL]: await mintCrl({ issuer: root, revoked: [] }),
		});
		const v = validator([root], { revocation: crlPolicy("reject"), fetchImpl: impl });

		const result = await v.validate(leaf.x509, [int.x509], NOW);

		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.step).toBe("revocation status unavailable");
			expect(result.detail).toContain("unsupported_critical_extension");
			expect(result.detail).not.toContain("bad_signature");
		}
		// One usable root CRL, one remembered-unavailable intermediate CRL.
		expect(v.crlCacheSize()).toBe(2);
		await v.validate(leaf.x509, [int.x509], NOW);
		expect(calls.filter((url) => url === INT_CRL_URL)).toHaveLength(1);
	});
});
