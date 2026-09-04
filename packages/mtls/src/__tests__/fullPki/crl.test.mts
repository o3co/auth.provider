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
 * The CRL resolver on its own: what it verifies before it stores, and how it
 * behaves when many callers miss the cache at once or a distribution point
 * is down. `validate.test.mts` covers the policy decisions built on top.
 */

import type * as pkijs from "pkijs";
import { describe, expect, it } from "vitest";
import { type AlgorithmPolicy, DEFAULT_SIGNATURE_ALGORITHMS } from "#/fullPki/algorithms.mjs";
import { CRL_NEGATIVE_CACHE_TTL_MS, createCrlResolver } from "#/fullPki/crl.mjs";
import { DEFAULT_ALGORITHM_POLICY, resolveFullPkiTuning } from "#/fullPki/defaults.mjs";
import type { GuardedFetch } from "#/fullPki/fetchGuard.mjs";
import type { IssuingDistributionPointOptions, Minted } from "./pkiFactory.mjs";
import {
	basicConstraints,
	certificateIssuerEntryExtension,
	clientAuthEku,
	crlDistributionPoints,
	deltaCrlIndicator,
	distributionPoint,
	distributionPointsExtension,
	indirectDistributionPoint,
	issuingDistributionPoint,
	KEY_USAGE,
	keyUsage,
	mintCa,
	mintCrl,
	mintIntermediate,
	mintLeaf,
	reasonPartitionedDistributionPoint,
	unknownCriticalExtension,
	unknownNonCriticalExtension,
} from "./pkiFactory.mjs";

const NOW = new Date("2027-01-01T00:00:00Z");
const INT_CRL_URL = "http://crl.test/int.crl";
const INT_CRL_MIRROR_URL = "http://crl.test/int-mirror.crl";
const ROOT_CRL_URL = "http://crl.test/root.crl";
/** The default algorithm policy — what `validate.mts` hands the resolver unless configured otherwise. */
const POLICY: AlgorithmPolicy = {
	signatureAlgorithms: DEFAULT_SIGNATURE_ALGORITHMS,
	minRsaKeyBits: 2048,
};

/** root → intermediate → leaf, each non-anchor naming its issuer's distribution point. */
const chain = async () => {
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

/** A leaf under `int` whose `cRLDistributionPoints` is exactly `extension`. */
const leafWithPoints = (int: Minted, extension: pkijs.Extension) =>
	mintLeaf("client", 11, int, {
		extensions: [
			basicConstraints(false),
			keyUsage(KEY_USAGE.digitalSignature),
			clientAuthEku(),
			extension,
		],
	});

/**
 * A `GuardedFetch` answering from a table. `"down"` answers as an HTTP error,
 * which is what the guard reports for an unreachable responder.
 */
const stubGuardedFetch = (table: Record<string, Uint8Array | "down">) => {
	const calls: string[] = [];
	const fetch: GuardedFetch = async (url) => {
		calls.push(url);
		const entry = table[url];
		if (entry === undefined || entry === "down") {
			return { ok: false, reason: "http_error", detail: "HTTP 503" };
		}
		return { ok: true, bytes: entry };
	};
	return { fetch, calls };
};

/**
 * A `GuardedFetch` that records the request immediately but does not answer
 * until `release()` — so a test can observe how many requests are in flight
 * while the first one is still unanswered.
 */
const deferredGuardedFetch = (table: Record<string, Uint8Array>) => {
	const calls: string[] = [];
	const gate = { release: (): void => {} };
	const opened = new Promise<void>((resolve) => {
		gate.release = resolve;
	});
	const fetch: GuardedFetch = async (url) => {
		calls.push(url);
		await opened;
		const entry = table[url];
		if (entry === undefined) return { ok: false, reason: "http_error", detail: "HTTP 404" };
		return { ok: true, bytes: entry };
	};
	return { fetch, calls, release: () => gate.release() };
};

/** Let every already-queued microtask and I/O callback run. */
const settle = () => new Promise<void>((resolve) => setImmediate(resolve));

describe("CRL resolver — signature verification before caching", () => {
	it("reports a CRL the issuer did not sign as bad_signature, and never caches it", async () => {
		// Caching a forged CRL would let one injected response over plain http
		// pin a refusal for every client of that distribution point until the
		// entry expires. Verification therefore happens before storage, and a
		// failure leaves nothing behind: the next lookup goes back to the
		// distribution point.
		const { int, leaf } = await chain();
		const impostor = await mintCa("Impostor", 900);
		const forged = await mintCrl({ issuer: int, revoked: [], signingKeys: impostor.keys });
		const { fetch, calls } = stubGuardedFetch({ [INT_CRL_URL]: forged });
		const resolver = createCrlResolver({ fetch, cacheTtlSeconds: 3_600, algorithms: POLICY });

		const first = await resolver.resolve(leaf.cert, int.cert, NOW);
		expect(first).toMatchObject({ ok: false, reason: "bad_signature" });
		expect(resolver.size()).toBe(0);

		const second = await resolver.resolve(leaf.cert, int.cert, NOW);
		expect(second).toMatchObject({ ok: false, reason: "bad_signature" });
		expect(calls).toEqual([INT_CRL_URL, INT_CRL_URL]);
	});

	it("does not honour a genuine CRL for a certificate whose issuer is a different CA", async () => {
		// The CRL is checked against the issuer of the certificate being
		// looked up — not against whichever CA happens to have signed it.
		const { root, int, leaf } = await chain();
		const genuine = await mintCrl({ issuer: int, revoked: [] });
		const { fetch } = stubGuardedFetch({ [INT_CRL_URL]: genuine });
		const resolver = createCrlResolver({ fetch, cacheTtlSeconds: 3_600, algorithms: POLICY });

		const wrongIssuer = await resolver.resolve(leaf.cert, root.cert, NOW);
		expect(wrongIssuer).toMatchObject({ ok: false, reason: "bad_signature" });
		expect(resolver.size()).toBe(0);

		const rightIssuer = await resolver.resolve(leaf.cert, int.cert, NOW);
		expect(rightIssuer.ok).toBe(true);
		expect(resolver.size()).toBe(1);
	});
});

describe("CRL resolver — one fetch per distribution point, not one per caller", () => {
	it("shares a single in-flight fetch among concurrent lookups of the same distribution point", async () => {
		// A cache miss under load is many requests missing at once. Without
		// dedup each of them issues its own guarded fetch — up to
		// max-response-bytes, for up to fetch-timeout-ms — and a cache expiry
		// on a busy token endpoint becomes a thundering herd at the CA.
		const { int, leaf } = await chain();
		const genuine = await mintCrl({ issuer: int, revoked: [] });
		const { fetch, calls, release } = deferredGuardedFetch({ [INT_CRL_URL]: genuine });
		const resolver = createCrlResolver({ fetch, cacheTtlSeconds: 3_600, algorithms: POLICY });

		const lookups = Array.from({ length: 5 }, () => resolver.resolve(leaf.cert, int.cert, NOW));
		await settle();
		expect(calls).toEqual([INT_CRL_URL]);

		release();
		const results = await Promise.all(lookups);
		expect(results.every((result) => result.ok)).toBe(true);
		expect(calls).toEqual([INT_CRL_URL]);
		expect(resolver.size()).toBe(1);
	});

	it("does not retry a failed fetch within the negative-cache window", async () => {
		// A distribution point that is down stays down for a while. Retrying
		// it on every request keeps the fetch-timeout-ms latency floor on the
		// token endpoint for the whole outage; remembering the failure briefly
		// bounds that to one probe per window.
		const { int, leaf } = await chain();
		const { fetch, calls } = stubGuardedFetch({ [INT_CRL_URL]: "down" });
		const resolver = createCrlResolver({ fetch, cacheTtlSeconds: 3_600, algorithms: POLICY });

		expect(await resolver.resolve(leaf.cert, int.cert, NOW)).toMatchObject({
			ok: false,
			reason: "fetch_failed",
		});
		expect(calls).toHaveLength(1);
		// The negative entry occupies the same bounded cache as a positive one.
		expect(resolver.size()).toBe(1);

		const withinWindow = new Date(NOW.getTime() + CRL_NEGATIVE_CACHE_TTL_MS - 1);
		expect(await resolver.resolve(leaf.cert, int.cert, withinWindow)).toMatchObject({
			ok: false,
			reason: "fetch_failed",
		});
		expect(calls).toHaveLength(1);

		const afterWindow = new Date(NOW.getTime() + CRL_NEGATIVE_CACHE_TTL_MS);
		await resolver.resolve(leaf.cert, int.cert, afterWindow);
		expect(calls).toHaveLength(2);
	});

	it("bounds the negative window well below the positive one", () => {
		// The failure window exists to absorb a burst, not to remember an
		// outage: a CA that comes back must be noticed in seconds, not hours.
		expect(CRL_NEGATIVE_CACHE_TTL_MS).toBeGreaterThan(0);
		expect(CRL_NEGATIVE_CACHE_TTL_MS).toBeLessThanOrEqual(60_000);
	});
});

describe("CRL resolver — extensions it does not process (#447, #446)", () => {
	it("remembers a CRL carrying an unsupported critical extension for the negative window, under its own name", async () => {
		// pkijs's `verify` answers `false` for a critical extension outside its
		// known list — the same answer as a forged signature — and that used to
		// surface as bad_signature, the one outcome deliberately never
		// remembered. A CA publishing such a CRL therefore cost one guarded
		// fetch per request under both policies, the exact pattern the
		// negative window exists to bound. The extensions are inspected
		// first, so the outcome has its own name and is remembered like any
		// other unusable response.
		const { int, leaf } = await chain();
		const crl = await mintCrl({
			issuer: int,
			revoked: [],
			extensions: [unknownCriticalExtension()],
		});
		const { fetch, calls } = stubGuardedFetch({ [INT_CRL_URL]: crl });
		const resolver = createCrlResolver({ fetch, cacheTtlSeconds: 3_600, algorithms: POLICY });

		const first = await resolver.resolve(leaf.cert, int.cert, NOW);
		expect(first).toMatchObject({ ok: false, reason: "unsupported_critical_extension" });
		if (!first.ok) expect(first.detail).toContain("1.3.6.1.4.1.99999.1.1");
		expect(resolver.size()).toBe(1);

		const withinWindow = new Date(NOW.getTime() + CRL_NEGATIVE_CACHE_TTL_MS - 1);
		expect(await resolver.resolve(leaf.cert, int.cert, withinWindow)).toMatchObject({
			ok: false,
			reason: "unsupported_critical_extension",
		});
		expect(calls).toEqual([INT_CRL_URL]);

		const afterWindow = new Date(NOW.getTime() + CRL_NEGATIVE_CACHE_TTL_MS);
		await resolver.resolve(leaf.cert, int.cert, afterWindow);
		expect(calls).toEqual([INT_CRL_URL, INT_CRL_URL]);
	});

	it("still uses a CRL whose unrecognised extension is non-critical", async () => {
		// RFC 5280 §5.2 lets a validator ignore a non-critical extension it does
		// not recognise, and pkijs does. The inspection must not be stricter
		// than the engine here, or a harmless extension becomes a refusal.
		const { int, leaf } = await chain();
		const crl = await mintCrl({
			issuer: int,
			revoked: [],
			extensions: [unknownNonCriticalExtension()],
		});
		const { fetch } = stubGuardedFetch({ [INT_CRL_URL]: crl });
		const resolver = createCrlResolver({ fetch, cacheTtlSeconds: 3_600, algorithms: POLICY });

		expect(await resolver.resolve(leaf.cert, int.cert, NOW)).toMatchObject({
			ok: true,
			unavailable: [],
		});
	});

	it("applies the same rule to a critical extension on a CRL entry (RFC 5280 §5.3)", async () => {
		// pkijs's `verify` never looks at entry extensions. A critical
		// certificateIssuer — the marker that an indirect CRL's entries were
		// issued by someone else — would otherwise be ignored, and the serial
		// matched against the wrong issuer.
		const { int, leaf } = await chain();
		const crl = await mintCrl({
			issuer: int,
			revoked: [leaf],
			entryExtensions: [certificateIssuerEntryExtension("Someone Else")],
		});
		const { fetch, calls } = stubGuardedFetch({ [INT_CRL_URL]: crl });
		const resolver = createCrlResolver({ fetch, cacheTtlSeconds: 3_600, algorithms: POLICY });

		expect(await resolver.resolve(leaf.cert, int.cert, NOW)).toMatchObject({
			ok: false,
			reason: "unsupported_critical_extension",
		});
		expect(resolver.size()).toBe(1);
		await resolver.resolve(leaf.cert, int.cert, NOW);
		expect(calls).toEqual([INT_CRL_URL]);
	});

	it("reports a delta CRL as unsupported_crl_scope, and remembers it", async () => {
		// A delta lists only what changed since a base CRL this resolver has
		// not fetched. pkijs accepts deltaCRLIndicator as well-known and then
		// ignores it, so the delta would otherwise have read as the complete
		// list — with every revocation on the base silently missing.
		const { int, leaf } = await chain();
		const crl = await mintCrl({ issuer: int, revoked: [], extensions: [deltaCrlIndicator(7)] });
		const { fetch, calls } = stubGuardedFetch({ [INT_CRL_URL]: crl });
		const resolver = createCrlResolver({ fetch, cacheTtlSeconds: 3_600, algorithms: POLICY });

		const result = await resolver.resolve(leaf.cert, int.cert, NOW);
		expect(result).toMatchObject({ ok: false, reason: "unsupported_crl_scope" });
		if (!result.ok) expect(result.detail).toContain("delta");
		expect(resolver.size()).toBe(1);
		await resolver.resolve(leaf.cert, int.cert, NOW);
		expect(calls).toEqual([INT_CRL_URL]);
	});

	it.each<[string, IssuingDistributionPointOptions]>([
		["onlyContainsUserCerts", { onlyContainsUserCerts: true }],
		["onlyContainsCACerts", { onlyContainsCACerts: true }],
		["onlySomeReasons", { onlySomeReasons: 0x40 }],
		["indirectCRL", { indirectCRL: true }],
		["a distribution-point name", { distributionPointUrl: INT_CRL_URL }],
	])(
		"reports a CRL whose issuingDistributionPoint carries %s as unsupported_crl_scope",
		async (_label, scope) => {
			// pkijs accepts issuingDistributionPoint as well-known and ignores
			// it, so a CRL scoped to user certificates would have been read as
			// authoritative for an intermediate. The scope is recognised and
			// refused rather than half-honoured.
			const { int, leaf } = await chain();
			const crl = await mintCrl({
				issuer: int,
				revoked: [],
				extensions: [issuingDistributionPoint(scope)],
			});
			const { fetch } = stubGuardedFetch({ [INT_CRL_URL]: crl });
			const resolver = createCrlResolver({ fetch, cacheTtlSeconds: 3_600, algorithms: POLICY });

			const result = await resolver.resolve(leaf.cert, int.cert, NOW);
			expect(result).toMatchObject({ ok: false, reason: "unsupported_crl_scope" });
			if (!result.ok) expect(result.detail).toContain("issuingDistributionPoint");
			expect(resolver.size()).toBe(1);
		},
	);

	it("still uses a CRL whose issuingDistributionPoint states no scope at all", async () => {
		// The extension is on the processed list because its *contents* are
		// read; an empty one restricts nothing, and refusing it would be
		// stricter than the engine for no gain.
		const { int, leaf } = await chain();
		const crl = await mintCrl({
			issuer: int,
			revoked: [],
			extensions: [issuingDistributionPoint({})],
		});
		const { fetch } = stubGuardedFetch({ [INT_CRL_URL]: crl });
		const resolver = createCrlResolver({ fetch, cacheTtlSeconds: 3_600, algorithms: POLICY });

		expect(await resolver.resolve(leaf.cert, int.cert, NOW)).toMatchObject({ ok: true });
	});
});

describe("CRL resolver — several distribution points on one certificate (#446, #469)", () => {
	it("skips a distribution point carrying reasons without fetching it, and still consults the plain point beside it", async () => {
		// With reasons, no single CRL is the complete answer, and the
		// reasons-mask bookkeeping of RFC 5280 §6.3.3 is not implemented. But
		// a point *without* reasons covers every reason code (§4.2.1.13), so
		// the plain point's CRL is a complete answer on its own. Giving up on
		// the whole extension at the partitioned point threw that answer
		// away (#469); now the point is reported, unfetched, beside the CRL
		// the other point yielded, and the caller's policy decides.
		const { int } = await chain();
		const leaf = await leafWithPoints(
			int,
			distributionPointsExtension([
				reasonPartitionedDistributionPoint(INT_CRL_MIRROR_URL),
				distributionPoint(INT_CRL_URL),
			]),
		);
		const { fetch, calls } = stubGuardedFetch({
			[INT_CRL_URL]: await mintCrl({ issuer: int, revoked: [] }),
			[INT_CRL_MIRROR_URL]: await mintCrl({ issuer: int, revoked: [] }),
		});
		const resolver = createCrlResolver({ fetch, cacheTtlSeconds: 3_600, algorithms: POLICY });

		const result = await resolver.resolve(leaf.cert, int.cert, NOW);
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.crls).toHaveLength(1);
			expect(result.unavailable).toEqual([
				expect.objectContaining({
					url: INT_CRL_MIRROR_URL,
					reason: "unsupported_distribution_point",
				}),
			]);
			expect(result.unavailable[0]?.detail).toContain("reasons");
		}
		expect(calls).toEqual([INT_CRL_URL]);
		expect(resolver.size()).toBe(1);
	});

	it("skips a distribution point naming a cRLIssuer without fetching it, and still consults the plain point beside it", async () => {
		// The CRL there is signed by someone other than the certificate's
		// issuer, and this resolver verifies against the issuer only.
		const { int } = await chain();
		const leaf = await leafWithPoints(
			int,
			distributionPointsExtension([
				distributionPoint(INT_CRL_URL),
				indirectDistributionPoint(INT_CRL_MIRROR_URL, "Someone Else"),
			]),
		);
		const { fetch, calls } = stubGuardedFetch({
			[INT_CRL_URL]: await mintCrl({ issuer: int, revoked: [] }),
			[INT_CRL_MIRROR_URL]: await mintCrl({ issuer: int, revoked: [] }),
		});
		const resolver = createCrlResolver({ fetch, cacheTtlSeconds: 3_600, algorithms: POLICY });

		const result = await resolver.resolve(leaf.cert, int.cert, NOW);
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.crls).toHaveLength(1);
			expect(result.unavailable).toEqual([
				expect.objectContaining({
					url: INT_CRL_MIRROR_URL,
					reason: "unsupported_distribution_point",
				}),
			]);
			expect(result.unavailable[0]?.detail).toContain("cRLIssuer");
		}
		expect(calls).toEqual([INT_CRL_URL]);
	});

	it("is unavailable as unsupported_distribution_point when every point is unsupported, without fetching", async () => {
		// No usable point remains, so there is nothing to consult: the
		// certificate's status is unknown, under the reason that says why,
		// and every point's detail is in the audit line.
		const { int } = await chain();
		const leaf = await leafWithPoints(
			int,
			distributionPointsExtension([
				reasonPartitionedDistributionPoint(INT_CRL_URL),
				indirectDistributionPoint(INT_CRL_MIRROR_URL, "Someone Else"),
			]),
		);
		const { fetch, calls } = stubGuardedFetch({
			[INT_CRL_URL]: await mintCrl({ issuer: int, revoked: [] }),
			[INT_CRL_MIRROR_URL]: await mintCrl({ issuer: int, revoked: [] }),
		});
		const resolver = createCrlResolver({ fetch, cacheTtlSeconds: 3_600, algorithms: POLICY });

		const result = await resolver.resolve(leaf.cert, int.cert, NOW);
		expect(result).toMatchObject({ ok: false, reason: "unsupported_distribution_point" });
		if (!result.ok) {
			expect(result.detail).toContain("reasons");
			expect(result.detail).toContain("cRLIssuer");
		}
		expect(calls).toEqual([]);
		expect(resolver.size()).toBe(0);
	});

	it("reports a distribution point that yielded no CRL alongside the CRLs the others did", async () => {
		// "One of them answered" and "all of them answered" are different
		// facts, and which one is enough is the caller's on-unavailable
		// decision. The lookup therefore keeps both: the CRLs it obtained and
		// the points it could not use.
		const { int } = await chain();
		const leaf = await leafWithPoints(
			int,
			crlDistributionPoints([INT_CRL_URL, INT_CRL_MIRROR_URL]),
		);
		const { fetch } = stubGuardedFetch({
			[INT_CRL_URL]: await mintCrl({ issuer: int, revoked: [] }),
			[INT_CRL_MIRROR_URL]: "down",
		});
		const resolver = createCrlResolver({ fetch, cacheTtlSeconds: 3_600, algorithms: POLICY });

		const result = await resolver.resolve(leaf.cert, int.cert, NOW);
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.crls).toHaveLength(1);
			expect(result.unavailable).toEqual([
				expect.objectContaining({ url: INT_CRL_MIRROR_URL, reason: "fetch_failed" }),
			]);
		}
	});

	it("treats the URIs within one distribution point as alternatives for the same CRL", async () => {
		// RFC 5280 §4.2.1.13: several names in one point are ways to obtain
		// the same CRL. The first that yields one answers for the point; a
		// dead mirror is not a gap in the certificate's status, and is not
		// fetched again within the negative window.
		const { int } = await chain();
		const leaf = await leafWithPoints(
			int,
			crlDistributionPoints([[INT_CRL_MIRROR_URL, INT_CRL_URL]]),
		);
		const { fetch, calls } = stubGuardedFetch({
			[INT_CRL_MIRROR_URL]: "down",
			[INT_CRL_URL]: await mintCrl({ issuer: int, revoked: [] }),
		});
		const resolver = createCrlResolver({ fetch, cacheTtlSeconds: 3_600, algorithms: POLICY });

		const result = await resolver.resolve(leaf.cert, int.cert, NOW);
		expect(result).toMatchObject({ ok: true, unavailable: [] });
		if (result.ok) expect(result.crls).toHaveLength(1);
		expect(calls).toEqual([INT_CRL_MIRROR_URL, INT_CRL_URL]);

		await resolver.resolve(leaf.cert, int.cert, NOW);
		expect(calls).toEqual([INT_CRL_MIRROR_URL, INT_CRL_URL]);
	});

	it("does not fetch a second URI of a point whose first already answered", async () => {
		const { int } = await chain();
		const leaf = await leafWithPoints(
			int,
			crlDistributionPoints([[INT_CRL_URL, INT_CRL_MIRROR_URL]]),
		);
		const { fetch, calls } = stubGuardedFetch({
			[INT_CRL_URL]: await mintCrl({ issuer: int, revoked: [] }),
			[INT_CRL_MIRROR_URL]: await mintCrl({ issuer: int, revoked: [] }),
		});
		const resolver = createCrlResolver({ fetch, cacheTtlSeconds: 3_600, algorithms: POLICY });

		expect(await resolver.resolve(leaf.cert, int.cert, NOW)).toMatchObject({ ok: true });
		expect(calls).toEqual([INT_CRL_URL]);
	});

	it("ignores a distribution point that names no HTTP(S) URI rather than counting it as failed", async () => {
		// An LDAP point beside an HTTP one is the shape a directory-backed CA
		// publishes. This resolver does not speak LDAP; a point it cannot
		// consult at all is outside its remit, not a failed lookup, and must
		// not make every such certificate unavailable under "reject".
		const { int } = await chain();
		const leaf = await leafWithPoints(
			int,
			crlDistributionPoints([
				"ldap://directory.test/cn=int?certificateRevocationList",
				INT_CRL_URL,
			]),
		);
		const { fetch, calls } = stubGuardedFetch({
			[INT_CRL_URL]: await mintCrl({ issuer: int, revoked: [] }),
		});
		const resolver = createCrlResolver({ fetch, cacheTtlSeconds: 3_600, algorithms: POLICY });

		expect(await resolver.resolve(leaf.cert, int.cert, NOW)).toMatchObject({
			ok: true,
			unavailable: [],
		});
		expect(calls).toEqual([INT_CRL_URL]);
	});
});

describe("CRL resolver — the signature-algorithm policy applies to the CRL too (#470)", () => {
	it("refuses a CRL signed with SHA-1 as algorithm_not_permitted, and remembers it for the negative window", async () => {
		// pkijs verifies ecdsa-with-SHA1 and sha1WithRSAEncryption without
		// complaint, so a SHA-1-signed CRL was believed while a SHA-1-signed
		// certificate on the path was refused. The decision is on the CRL's
		// shape — the OID in its signatureAlgorithm — and is made before the
		// signature is checked, so it is remembered the way an unsupported
		// critical extension is (#447): nothing injected can pin an
		// acceptance, a pinned refusal is bounded by the window, and a CA
		// that signs with SHA-1 costs one probe per window rather than one
		// fetch per request.
		const { int, leaf } = await chain();
		const crl = await mintCrl({ issuer: int, revoked: [], hash: "SHA-1" });
		const { fetch, calls } = stubGuardedFetch({ [INT_CRL_URL]: crl });
		const resolver = createCrlResolver({ fetch, cacheTtlSeconds: 3_600, algorithms: POLICY });

		const first = await resolver.resolve(leaf.cert, int.cert, NOW);
		expect(first).toMatchObject({ ok: false, reason: "algorithm_not_permitted" });
		if (!first.ok) {
			expect(first.detail).toContain("1.2.840.10045.4.1");
			expect(first.detail).toContain("signature-algorithms");
		}
		expect(resolver.size()).toBe(1);

		const withinWindow = new Date(NOW.getTime() + CRL_NEGATIVE_CACHE_TTL_MS - 1);
		expect(await resolver.resolve(leaf.cert, int.cert, withinWindow)).toMatchObject({
			ok: false,
			reason: "algorithm_not_permitted",
		});
		expect(calls).toEqual([INT_CRL_URL]);
	});

	it("does not let a SHA-1-signed CRL determine anything, not even a revocation", async () => {
		// The point of the policy is that nothing signed below it is
		// evidence. A CRL the policy refuses is not consulted for the
		// serial either way — the caller sees an unavailable status and
		// applies on-unavailable, as for any other CRL it could not use.
		const { int, leaf } = await chain();
		const crl = await mintCrl({ issuer: int, revoked: [leaf], hash: "SHA-1" });
		const { fetch } = stubGuardedFetch({ [INT_CRL_URL]: crl });
		const resolver = createCrlResolver({ fetch, cacheTtlSeconds: 3_600, algorithms: POLICY });

		expect(await resolver.resolve(leaf.cert, int.cert, NOW)).toMatchObject({
			ok: false,
			reason: "algorithm_not_permitted",
		});
	});

	it("holds a resolver built without an algorithms policy to the strict default, refusing SHA-1", async () => {
		// `algorithms` is optional so that this security fix reaches a
		// consumer who upgrades without touching their code — the resolver
		// options are public surface (#470 review). Omitting it must mean the
		// strict default, never "no policy": absent a default, `undefined`
		// here would have thrown, or worse, waved everything through.
		const { int, leaf } = await chain();
		const crl = await mintCrl({ issuer: int, revoked: [], hash: "SHA-1" });
		const { fetch } = stubGuardedFetch({ [INT_CRL_URL]: crl });
		const resolver = createCrlResolver({ fetch, cacheTtlSeconds: 3_600 });

		const result = await resolver.resolve(leaf.cert, int.cert, NOW);
		expect(result).toMatchObject({ ok: false, reason: "algorithm_not_permitted" });
		if (!result.ok) expect(result.detail).toContain("1.2.840.10045.4.1");
	});

	it("still accepts a SHA-256 CRL with no algorithms policy given, so the default is not 'permit nothing'", async () => {
		const { int, leaf } = await chain();
		const crl = await mintCrl({ issuer: int, revoked: [] });
		const { fetch } = stubGuardedFetch({ [INT_CRL_URL]: crl });
		const resolver = createCrlResolver({ fetch, cacheTtlSeconds: 3_600 });

		expect(await resolver.resolve(leaf.cert, int.cert, NOW)).toMatchObject({ ok: true });
	});

	it("defaults to the very policy the config resolves to when the operator sets nothing", async () => {
		// Two defaults that drift apart would mean a resolver built directly
		// is held to a different bar than one the config builds — the failure
		// mode `defaults.mts` exists to prevent.
		const fromConfig = resolveFullPkiTuning(undefined);
		expect(DEFAULT_ALGORITHM_POLICY).toEqual({
			signatureAlgorithms: fromConfig.signatureAlgorithms,
			minRsaKeyBits: fromConfig.minRsaKeyBits,
		});
	});

	it("applies the configured allowlist, not a fixed one: ed25519 alone refuses a SHA-256 ECDSA CRL", async () => {
		const { int, leaf } = await chain();
		const crl = await mintCrl({ issuer: int, revoked: [] });
		const { fetch } = stubGuardedFetch({ [INT_CRL_URL]: crl });
		const resolver = createCrlResolver({
			fetch,
			cacheTtlSeconds: 3_600,
			algorithms: { signatureAlgorithms: ["ed25519"], minRsaKeyBits: 2048 },
		});

		const result = await resolver.resolve(leaf.cert, int.cert, NOW);
		expect(result).toMatchObject({ ok: false, reason: "algorithm_not_permitted" });
		if (!result.ok) expect(result.detail).toContain("ecdsaWithSHA256");
	});
});
