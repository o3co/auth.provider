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
 * The OCSP resolver on its own (#431): what it asks, what it verifies before
 * it believes an answer, and how it behaves when the responder is down or
 * lying. `validate.test.mts` covers the policy decisions built on top.
 */

import { createHash } from "node:crypto";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { describe, expect, it, vi } from "vitest";
import { type AlgorithmPolicy, DEFAULT_SIGNATURE_ALGORITHMS } from "#/fullPki/algorithms.mjs";
import { CRL_NEGATIVE_CACHE_TTL_MS } from "#/fullPki/crl.mjs";
import type { GuardedFetch, GuardedRequest } from "#/fullPki/fetchGuard.mjs";
import { createGuardedFetch } from "#/fullPki/fetchGuard.mjs";
import {
	createOcspResolver,
	OCSP_CLOCK_SKEW_MS,
	OCSP_NEGATIVE_CACHE_TTL_MS,
	OCSP_UNDATED_RESPONSE_MAX_AGE_MS,
	ocspResponders,
} from "#/fullPki/ocsp.mjs";
import type { Minted, MintOcspResponseOptions } from "./pkiFactory.mjs";
import {
	basicConstraints,
	caIssuersAia,
	clientAuthEku,
	KEY_USAGE,
	keyUsage,
	mintCa,
	mintIntermediate,
	mintLeaf,
	mintOcspResponder,
	mintOcspResponse,
	nonceOf,
	OCSP_RESPONSE_STATUS,
	ocspAia,
	ocspNoCheck,
	ocspSigningEku,
	unknownCriticalExtension,
	unknownNonCriticalExtension,
} from "./pkiFactory.mjs";

const NOW = new Date("2027-01-01T00:00:00Z");
const RESPONDER_URL = "http://ocsp.test/int";
const MIRROR_URL = "http://ocsp.test/int-mirror";
const OID_SHA1 = "1.3.14.3.2.26";
const OID_NONCE = "1.3.6.1.5.5.7.48.1.2";
/** The default algorithm policy — what `validate.mts` hands the resolver unless configured otherwise. */
const POLICY: AlgorithmPolicy = {
	signatureAlgorithms: DEFAULT_SIGNATURE_ALGORITHMS,
	minRsaKeyBits: 2048,
};

/** root → intermediate → leaf, the leaf naming `responders` in its AIA. */
const chain = async (responders: string | readonly string[] = RESPONDER_URL) => {
	const root = await mintCa("Root", 1);
	const int = await mintIntermediate("Intermediate", 2, root);
	const leaf = await mintLeaf("client", 10, int, {
		extensions: [
			basicConstraints(false),
			keyUsage(KEY_USAGE.digitalSignature),
			clientAuthEku(),
			ocspAia(responders),
		],
	});
	return { root, int, leaf };
};

type Answer = Uint8Array | "down" | ((request: GuardedRequest | undefined) => Promise<Uint8Array>);

/**
 * A `GuardedFetch` standing in for one or more responders. A function entry
 * sees the request (to echo its nonce); bytes are served verbatim; `"down"`
 * answers as the guard does for an unreachable host.
 */
const stubResponders = (table: Record<string, Answer>) => {
	const calls: { url: string; request: GuardedRequest | undefined }[] = [];
	const fetch: GuardedFetch = async (url, request) => {
		calls.push({ url, request });
		const entry = table[url];
		if (entry === undefined || entry === "down") {
			return { ok: false, reason: "http_error", detail: "HTTP 503" };
		}
		const bytes = typeof entry === "function" ? await entry(request) : entry;
		return { ok: true, bytes };
	};
	return { fetch, calls, urls: () => calls.map((call) => call.url) };
};

/** A responder minting a response from `options`, echoing the request's nonce. */
const answering =
	(options: Omit<MintOcspResponseOptions, "nonce">): Answer =>
	async (request) => {
		const nonce = request?.body === undefined ? undefined : nonceOf(request.body);
		return mintOcspResponse({ ...options, ...(nonce === undefined ? {} : { nonce }) });
	};

/** The same, but the response carries no nonce whatever the request said. */
const answeringWithoutNonce =
	(options: Omit<MintOcspResponseOptions, "nonce">): Answer =>
	async () =>
		mintOcspResponse(options);

const resolver = (
	fetch: GuardedFetch,
	extra: { requireNonce?: boolean; cacheTtlSeconds?: number; algorithms?: AlgorithmPolicy } = {},
) =>
	createOcspResolver({
		fetch,
		cacheTtlSeconds: extra.cacheTtlSeconds ?? 3_600,
		algorithms: extra.algorithms ?? POLICY,
		...(extra.requireNonce === undefined ? {} : { requireNonce: extra.requireNonce }),
	});

const sha1 = (bytes: Uint8Array): Buffer => createHash("sha1").update(bytes).digest();

/** Let every already-queued microtask and I/O callback run. */
/**
 * Wait until `done()` holds, bounded by the clock rather than by event-loop
 * turns: building a CertID hashes the issuer's name and key through WebCrypto,
 * which runs on the threadpool, so a fixed number of `setImmediate` turns
 * can elapse before the resolver has even issued its request (the same
 * lesson `validate.test.mts` learned for the CRL concurrency case).
 */
const settle = async (done: () => boolean, timeoutMs = 3_000): Promise<void> => {
	const deadline = Date.now() + timeoutMs;
	while (!done()) {
		if (Date.now() > deadline) throw new Error("settle: condition not met before the deadline");
		await new Promise<void>((resolve) => setTimeout(resolve, 5));
	}
};

describe("OCSP resolver — the request (RFC 6960 §4.1, §4.4.1)", () => {
	it("POSTs a DER OCSPRequest with a SHA-1 CertID for the certificate and a 16-byte nonce", async () => {
		// SHA-1 here is a lookup identifier, not a signature: it names the
		// issuer's name and key so the responder can find the certificate's
		// record, and RFC 6960 §4.1.1 responders universally support it where
		// a SHA-256 CertID is often answered `unauthorized`. Nothing about it
		// touches the algorithm policy, which governs what may *sign*.
		const { int, leaf } = await chain();
		const { fetch, calls } = stubResponders({
			[RESPONDER_URL]: answering({ issuer: int, subject: leaf }),
		});

		const result = await resolver(fetch).resolve(leaf.cert, int.cert, NOW);
		expect(result).toMatchObject({
			ok: true,
			responder: RESPONDER_URL,
			status: { status: "good" },
		});

		const call = calls[0];
		expect(call?.url).toBe(RESPONDER_URL);
		expect(call?.request).toMatchObject({
			method: "POST",
			contentType: "application/ocsp-request",
			accept: "application/ocsp-response",
			expectContentType: "application/ocsp-response",
		});
		const body = call?.request?.body;
		expect(body).toBeInstanceOf(Uint8Array);
		const request = pkijs.OCSPRequest.fromBER(body as Uint8Array);
		expect(request.tbsRequest.requestList).toHaveLength(1);
		const certId = request.tbsRequest.requestList[0]?.reqCert as pkijs.CertID;
		expect(certId.hashAlgorithm.algorithmId).toBe(OID_SHA1);
		expect(certId.serialNumber.valueBlock.valueDec).toBe(leaf.serial);
		expect(Buffer.from(certId.issuerNameHash.valueBlock.valueHexView)).toEqual(
			sha1(new Uint8Array(int.cert.subject.toSchema().toBER(false))),
		);
		expect(Buffer.from(certId.issuerKeyHash.valueBlock.valueHexView)).toEqual(
			sha1(int.cert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView),
		);

		const nonce = request.tbsRequest.requestExtensions?.find((ext) => ext.extnID === OID_NONCE);
		expect(nonce).toBeDefined();
		expect(nonce?.critical).toBe(false);
		// RFC 8954 §2.1: the extension value is the DER of an OCTET STRING of
		// 1..32 bytes — a bare OCTET STRING, not one wrapped a second time.
		const inner = asn1js.fromBER(nonce?.extnValue.valueBlock.valueHexView as Uint8Array);
		expect(inner.result).toBeInstanceOf(asn1js.OctetString);
		expect((inner.result as asn1js.OctetString).valueBlock.valueHexView).toHaveLength(16);
	});

	it("uses a fresh nonce for every request", async () => {
		const { int, leaf } = await chain();
		const other = await mintLeaf("other", 11, int, {
			extensions: [
				basicConstraints(false),
				keyUsage(KEY_USAGE.digitalSignature),
				clientAuthEku(),
				ocspAia(RESPONDER_URL),
			],
		});
		const { fetch, calls } = stubResponders({
			[RESPONDER_URL]: async (request) => {
				const body = request?.body as Uint8Array;
				const serial =
					pkijs.OCSPRequest.fromBER(body).tbsRequest.requestList[0]?.reqCert.serialNumber.valueBlock
						.valueDec;
				return mintOcspResponse({
					issuer: int,
					subject: serial === leaf.serial ? leaf : other,
					nonce: nonceOf(body) as Uint8Array,
				});
			},
		});
		const r = resolver(fetch);

		await r.resolve(leaf.cert, int.cert, NOW);
		await r.resolve(other.cert, int.cert, NOW);
		const nonces = calls.map((call) =>
			Buffer.from(nonceOf(call.request?.body as Uint8Array) as Uint8Array).toString("hex"),
		);
		expect(nonces).toHaveLength(2);
		expect(nonces[0]).not.toBe(nonces[1]);
	});
});

describe("OCSP resolver — certificate status (RFC 6960 §2.2)", () => {
	it("reports good", async () => {
		const { int, leaf } = await chain();
		const { fetch } = stubResponders({
			[RESPONDER_URL]: answering({ issuer: int, subject: leaf, status: "good" }),
		});
		expect(await resolver(fetch).resolve(leaf.cert, int.cert, NOW)).toMatchObject({
			ok: true,
			status: { status: "good" },
		});
	});

	it("reports revoked with the revocation time and reason", async () => {
		const { int, leaf } = await chain();
		const revokedAt = new Date("2026-06-01T00:00:00Z");
		const { fetch } = stubResponders({
			[RESPONDER_URL]: answering({
				issuer: int,
				subject: leaf,
				status: "revoked",
				revokedAt,
				revocationReason: 1,
			}),
		});
		expect(await resolver(fetch).resolve(leaf.cert, int.cert, NOW)).toMatchObject({
			ok: true,
			status: { status: "revoked", revokedAt, reason: "keyCompromise" },
		});
	});

	it("reports revoked with no reason when the responder gives none", async () => {
		const { int, leaf } = await chain();
		const { fetch } = stubResponders({
			[RESPONDER_URL]: answering({ issuer: int, subject: leaf, status: "revoked" }),
		});
		const result = await resolver(fetch).resolve(leaf.cert, int.cert, NOW);
		expect(result).toMatchObject({ ok: true, status: { status: "revoked" } });
		if (result.ok && result.status.status === "revoked")
			expect(result.status.reason).toBeUndefined();
	});

	it("treats unknown as unavailable, not as good, and remembers it for the negative window", async () => {
		// RFC 6960 §2.2: `unknown` means the responder does not know about the
		// certificate. It is the one answer that looks like a status and is
		// not one; reading it as "not revoked" would let a responder that
		// lost its database un-revoke everything.
		const { int, leaf } = await chain();
		const { fetch, urls } = stubResponders({
			[RESPONDER_URL]: answering({ issuer: int, subject: leaf, status: "unknown" }),
		});
		const r = resolver(fetch);

		expect(await r.resolve(leaf.cert, int.cert, NOW)).toMatchObject({
			ok: false,
			reason: "unknown",
		});
		expect(r.size()).toBe(1);
		await r.resolve(leaf.cert, int.cert, new Date(NOW.getTime() + OCSP_NEGATIVE_CACHE_TTL_MS - 1));
		expect(urls()).toEqual([RESPONDER_URL]);
		await r.resolve(leaf.cert, int.cert, new Date(NOW.getTime() + OCSP_NEGATIVE_CACHE_TTL_MS));
		expect(urls()).toEqual([RESPONDER_URL, RESPONDER_URL]);
	});
});

describe("OCSP resolver — who may sign a response (RFC 6960 §4.2.2.2)", () => {
	it("accepts a response signed by the issuing CA itself", async () => {
		const { int, leaf } = await chain();
		const { fetch } = stubResponders({
			[RESPONDER_URL]: answering({ issuer: int, subject: leaf }),
		});
		expect(await resolver(fetch).resolve(leaf.cert, int.cert, NOW)).toMatchObject({ ok: true });
	});

	it("accepts a delegated responder the CA issued with id-kp-OCSPSigning", async () => {
		const { int, leaf } = await chain();
		const responder = await mintOcspResponder("OCSP Responder", 50, int);
		const { fetch } = stubResponders({
			[RESPONDER_URL]: answering({ issuer: int, subject: leaf, signer: responder }),
		});
		expect(await resolver(fetch).resolve(leaf.cert, int.cert, NOW)).toMatchObject({ ok: true });
	});

	it("accepts a delegated responder that identifies itself by key hash", async () => {
		const { int, leaf } = await chain();
		const responder = await mintOcspResponder("OCSP Responder", 50, int);
		const { fetch } = stubResponders({
			[RESPONDER_URL]: answering({
				issuer: int,
				subject: leaf,
				signer: responder,
				responderIdByKey: true,
			}),
		});
		expect(await resolver(fetch).resolve(leaf.cert, int.cert, NOW)).toMatchObject({ ok: true });
	});

	it("accepts the CA itself identified by key hash", async () => {
		const { int, leaf } = await chain();
		const { fetch } = stubResponders({
			[RESPONDER_URL]: answering({ issuer: int, subject: leaf, responderIdByKey: true }),
		});
		expect(await resolver(fetch).resolve(leaf.cert, int.cert, NOW)).toMatchObject({ ok: true });
	});

	it("refuses a delegated responder whose certificate lacks id-kp-OCSPSigning, and never caches it", async () => {
		// The EKU is the CA's statement that this key may speak for it about
		// revocation. Without it, any end-entity certificate the CA ever
		// issued — a client certificate, say — could un-revoke itself.
		const { int, leaf } = await chain();
		const impostor = await mintLeaf("Some Client", 51, int, {
			extensions: [
				basicConstraints(false),
				keyUsage(KEY_USAGE.digitalSignature),
				clientAuthEku(),
				ocspNoCheck(),
			],
		});
		const { fetch, urls } = stubResponders({
			[RESPONDER_URL]: answering({ issuer: int, subject: leaf, signer: impostor }),
		});
		const r = resolver(fetch);

		const result = await r.resolve(leaf.cert, int.cert, NOW);
		expect(result).toMatchObject({ ok: false, reason: "bad_signature" });
		if (!result.ok) expect(result.detail).toContain("OCSPSigning");
		expect(r.size()).toBe(0);
		await r.resolve(leaf.cert, int.cert, NOW);
		expect(urls()).toEqual([RESPONDER_URL, RESPONDER_URL]);
	});

	it("refuses a stranger carrying id-kp-OCSPSigning that the CA did not issue", async () => {
		const { int, leaf } = await chain();
		const stranger = await mintCa("Stranger", 900, {
			extensions: [basicConstraints(false), ocspSigningEku(), ocspNoCheck()],
		});
		const { fetch } = stubResponders({
			[RESPONDER_URL]: answering({ issuer: int, subject: leaf, signer: stranger }),
		});
		expect(await resolver(fetch).resolve(leaf.cert, int.cert, NOW)).toMatchObject({
			ok: false,
			reason: "bad_signature",
		});
	});

	it("refuses a responder certificate issued by a different CA in the same PKI", async () => {
		// Delegation is per issuer (§4.2.2.2): the responder must be certified
		// by the CA that issued the certificate in question, not by any CA.
		const { root, int, leaf } = await chain();
		const rootsResponder = await mintOcspResponder("Root Responder", 52, root);
		const { fetch } = stubResponders({
			[RESPONDER_URL]: answering({ issuer: int, subject: leaf, signer: rootsResponder }),
		});
		expect(await resolver(fetch).resolve(leaf.cert, int.cert, NOW)).toMatchObject({
			ok: false,
			reason: "bad_signature",
		});
	});

	it("refuses a delegated responder whose certificate is not attached to the response", async () => {
		const { int, leaf } = await chain();
		const responder = await mintOcspResponder("OCSP Responder", 50, int);
		const { fetch } = stubResponders({
			[RESPONDER_URL]: answering({
				issuer: int,
				subject: leaf,
				signer: responder,
				attachSignerCertificate: false,
			}),
		});
		const result = await resolver(fetch).resolve(leaf.cert, int.cert, NOW);
		expect(result).toMatchObject({ ok: false, reason: "bad_signature" });
		if (!result.ok) expect(result.detail).toMatch(/responder/i);
	});

	it("refuses a delegated responder whose certificate has expired", async () => {
		const { int, leaf } = await chain();
		const responder = await mintOcspResponder("OCSP Responder", 50, int, {
			notBefore: new Date("2025-01-01T00:00:00Z"),
			notAfter: new Date("2026-01-01T00:00:00Z"),
		});
		const { fetch } = stubResponders({
			[RESPONDER_URL]: answering({ issuer: int, subject: leaf, signer: responder }),
		});
		expect(await resolver(fetch).resolve(leaf.cert, int.cert, NOW)).toMatchObject({
			ok: false,
			reason: "bad_signature",
		});
	});

	it("refuses a response naming the CA as responder but signed with another key", async () => {
		const { int, leaf } = await chain();
		const impostor = await mintCa("Impostor", 901);
		const { fetch, urls } = stubResponders({
			[RESPONDER_URL]: answering({ issuer: int, subject: leaf, signingKeys: impostor.keys }),
		});
		const r = resolver(fetch);
		expect(await r.resolve(leaf.cert, int.cert, NOW)).toMatchObject({
			ok: false,
			reason: "bad_signature",
		});
		expect(r.size()).toBe(0);
		await r.resolve(leaf.cert, int.cert, NOW);
		expect(urls()).toHaveLength(2);
	});
});

describe("OCSP resolver — the signature-algorithm policy applies to the answer too (#470)", () => {
	it("refuses a response signed with SHA-1 as algorithm_not_permitted, and remembers it for the negative window", async () => {
		// pkijs verifies ecdsa-with-SHA1 and sha1WithRSAEncryption without
		// complaint, so a SHA-1-signed answer *about* a certificate was
		// believed while a SHA-1-signed certificate *on the path* was
		// refused. The refusal is on the response's shape — the OID in its
		// signatureAlgorithm — not on whether the signature verifies, so it
		// is remembered the way an unsupported critical extension is:
		// nothing injected can pin an acceptance this way, and a responder
		// that signs with SHA-1 costs one probe per window, not one per
		// request.
		const { int, leaf } = await chain();
		const { fetch, urls } = stubResponders({
			[RESPONDER_URL]: answering({ issuer: int, subject: leaf, hash: "SHA-1" }),
		});
		const r = resolver(fetch);

		const result = await r.resolve(leaf.cert, int.cert, NOW);
		expect(result).toMatchObject({ ok: false, reason: "algorithm_not_permitted" });
		if (!result.ok) {
			expect(result.detail).toContain("1.2.840.10045.4.1");
			expect(result.detail).toContain("signature-algorithms");
		}
		expect(r.size()).toBe(1);
		await r.resolve(leaf.cert, int.cert, NOW);
		expect(urls()).toEqual([RESPONDER_URL]);
	});

	it("refuses a delegated responder whose certificate the CA signed with SHA-1", async () => {
		// The responder certificate is not on the validated path, so the
		// path pass never saw it. It is the one new key an answer can
		// introduce, and it is held to the same policy as the path.
		const { int, leaf } = await chain();
		const responder = await mintOcspResponder("OCSP Responder", 50, int, { hash: "SHA-1" });
		const { fetch } = stubResponders({
			[RESPONDER_URL]: answering({ issuer: int, subject: leaf, signer: responder }),
		});

		const result = await resolver(fetch).resolve(leaf.cert, int.cert, NOW);
		expect(result).toMatchObject({ ok: false, reason: "algorithm_not_permitted" });
		if (!result.ok) {
			expect(result.detail).toContain("responder certificate");
			expect(result.detail).toContain("1.2.840.10045.4.1");
		}
	});

	it("refuses a delegated responder whose RSA key is below the configured minimum", async () => {
		const { int, leaf } = await chain();
		const responder = await mintOcspResponder("OCSP Responder", 50, int, {
			algorithm: "rsa-1024",
		});
		const { fetch } = stubResponders({
			[RESPONDER_URL]: answering({ issuer: int, subject: leaf, signer: responder }),
		});

		const result = await resolver(fetch).resolve(leaf.cert, int.cert, NOW);
		expect(result).toMatchObject({ ok: false, reason: "algorithm_not_permitted" });
		if (!result.ok) expect(result.detail).toContain("1024-bit RSA key");
	});

	it("applies the configured allowlist, not a fixed one: ed25519 alone refuses a SHA-256 ECDSA answer", async () => {
		const { int, leaf } = await chain();
		const { fetch } = stubResponders({
			[RESPONDER_URL]: answering({ issuer: int, subject: leaf }),
		});

		const result = await resolver(fetch, {
			algorithms: { signatureAlgorithms: ["ed25519"], minRsaKeyBits: 2048 },
		}).resolve(leaf.cert, int.cert, NOW);
		expect(result).toMatchObject({ ok: false, reason: "algorithm_not_permitted" });
		if (!result.ok) expect(result.detail).toContain("ecdsaWithSHA256");
	});

	it("still accepts a SHA-256 answer from a SHA-256-certified delegated responder", async () => {
		const { int, leaf } = await chain();
		const responder = await mintOcspResponder("OCSP Responder", 50, int);
		const { fetch } = stubResponders({
			[RESPONDER_URL]: answering({ issuer: int, subject: leaf, signer: responder }),
		});
		expect(await resolver(fetch).resolve(leaf.cert, int.cert, NOW)).toMatchObject({ ok: true });
	});
});

describe("OCSP resolver — nonce (RFC 6960 §4.4.1, RFC 8954)", () => {
	it("refuses a response echoing a different nonce, and never caches it", async () => {
		const { int, leaf } = await chain();
		const { fetch, urls } = stubResponders({
			[RESPONDER_URL]: async () =>
				mintOcspResponse({
					issuer: int,
					subject: leaf,
					nonce: new Uint8Array(
						new asn1js.OctetString({ valueHex: new Uint8Array(16).fill(7).buffer }).toBER(false),
					),
				}),
		});
		const r = resolver(fetch);
		expect(await r.resolve(leaf.cert, int.cert, NOW)).toMatchObject({
			ok: false,
			reason: "nonce_mismatch",
		});
		expect(r.size()).toBe(0);
		await r.resolve(leaf.cert, int.cert, NOW);
		expect(urls()).toHaveLength(2);
	});

	it("refuses a response with no nonce by default, and remembers it", async () => {
		// Without the nonce, nothing binds the response to this request: a
		// captured "good" from before a revocation replays until nextUpdate.
		// The strict reading is the default; a responder that pre-produces
		// answers needs `requireNonce: false` stated.
		const { int, leaf } = await chain();
		const { fetch, urls } = stubResponders({
			[RESPONDER_URL]: answeringWithoutNonce({ issuer: int, subject: leaf }),
		});
		const r = resolver(fetch);
		expect(await r.resolve(leaf.cert, int.cert, NOW)).toMatchObject({
			ok: false,
			reason: "nonce_missing",
		});
		expect(r.size()).toBe(1);
		await r.resolve(leaf.cert, int.cert, NOW);
		expect(urls()).toEqual([RESPONDER_URL]);
	});

	it("accepts a nonce-less response when told to, provided it is fresh", async () => {
		const { int, leaf } = await chain();
		const { fetch } = stubResponders({
			[RESPONDER_URL]: answeringWithoutNonce({ issuer: int, subject: leaf }),
		});
		expect(
			await resolver(fetch, { requireNonce: false }).resolve(leaf.cert, int.cert, NOW),
		).toMatchObject({ ok: true, status: { status: "good" } });
	});

	it("still refuses a nonce-less response that is stale", async () => {
		const { int, leaf } = await chain();
		const { fetch } = stubResponders({
			[RESPONDER_URL]: answeringWithoutNonce({
				issuer: int,
				subject: leaf,
				thisUpdate: new Date("2026-06-01T00:00:00Z"),
				nextUpdate: new Date("2026-07-01T00:00:00Z"),
			}),
		});
		expect(
			await resolver(fetch, { requireNonce: false }).resolve(leaf.cert, int.cert, NOW),
		).toMatchObject({ ok: false, reason: "stale" });
	});
});

describe("OCSP resolver — freshness (RFC 6960 §4.2.2.1)", () => {
	it("refuses a response whose nextUpdate has passed, and remembers it", async () => {
		const { int, leaf } = await chain();
		const { fetch, urls } = stubResponders({
			[RESPONDER_URL]: answering({
				issuer: int,
				subject: leaf,
				thisUpdate: new Date("2026-06-01T00:00:00Z"),
				nextUpdate: new Date("2026-07-01T00:00:00Z"),
			}),
		});
		const r = resolver(fetch);
		expect(await r.resolve(leaf.cert, int.cert, NOW)).toMatchObject({ ok: false, reason: "stale" });
		expect(r.size()).toBe(1);
		await r.resolve(leaf.cert, int.cert, NOW);
		expect(urls()).toEqual([RESPONDER_URL]);
	});

	it("refuses a response whose thisUpdate is further in the future than the skew allowance", async () => {
		const { int, leaf } = await chain();
		const { fetch } = stubResponders({
			[RESPONDER_URL]: answering({
				issuer: int,
				subject: leaf,
				thisUpdate: new Date(NOW.getTime() + OCSP_CLOCK_SKEW_MS + 1),
				nextUpdate: new Date(NOW.getTime() + 86_400_000),
			}),
		});
		expect(await resolver(fetch).resolve(leaf.cert, int.cert, NOW)).toMatchObject({
			ok: false,
			reason: "not_yet_valid",
		});
	});

	it("tolerates a thisUpdate within the skew allowance", async () => {
		const { int, leaf } = await chain();
		const { fetch } = stubResponders({
			[RESPONDER_URL]: answering({
				issuer: int,
				subject: leaf,
				thisUpdate: new Date(NOW.getTime() + OCSP_CLOCK_SKEW_MS - 1),
				nextUpdate: new Date(NOW.getTime() + 86_400_000),
			}),
		});
		expect(await resolver(fetch).resolve(leaf.cert, int.cert, NOW)).toMatchObject({ ok: true });
	});

	it("uses a response with no nextUpdate for a short bounded window from thisUpdate", async () => {
		// §4.2.2.1: no nextUpdate means newer information is available all the
		// time. It is not "valid forever"; it is "ask again soon".
		const { int, leaf } = await chain();
		const thisUpdate = new Date(NOW.getTime() - 60_000);
		const { fetch, urls } = stubResponders({
			[RESPONDER_URL]: answering({ issuer: int, subject: leaf, thisUpdate, nextUpdate: null }),
		});
		const r = resolver(fetch);

		expect(await r.resolve(leaf.cert, int.cert, NOW)).toMatchObject({ ok: true });
		const stillCached = new Date(thisUpdate.getTime() + OCSP_UNDATED_RESPONSE_MAX_AGE_MS - 1);
		expect(await r.resolve(leaf.cert, int.cert, stillCached)).toMatchObject({ ok: true });
		expect(urls()).toEqual([RESPONDER_URL]);

		const expired = new Date(thisUpdate.getTime() + OCSP_UNDATED_RESPONSE_MAX_AGE_MS);
		await r.resolve(leaf.cert, int.cert, expired);
		expect(urls()).toEqual([RESPONDER_URL, RESPONDER_URL]);
	});

	it("refuses a response with no nextUpdate whose thisUpdate is older than that window", async () => {
		const { int, leaf } = await chain();
		const { fetch } = stubResponders({
			[RESPONDER_URL]: answering({
				issuer: int,
				subject: leaf,
				thisUpdate: new Date(NOW.getTime() - OCSP_UNDATED_RESPONSE_MAX_AGE_MS),
				nextUpdate: null,
			}),
		});
		expect(await resolver(fetch).resolve(leaf.cert, int.cert, NOW)).toMatchObject({
			ok: false,
			reason: "stale",
		});
	});

	it("bounds the undated window and the skew allowance to minutes, not hours", () => {
		expect(OCSP_UNDATED_RESPONSE_MAX_AGE_MS).toBeGreaterThan(0);
		expect(OCSP_UNDATED_RESPONSE_MAX_AGE_MS).toBeLessThanOrEqual(15 * 60_000);
		expect(OCSP_CLOCK_SKEW_MS).toBeGreaterThan(0);
		expect(OCSP_CLOCK_SKEW_MS).toBeLessThanOrEqual(10 * 60_000);
	});

	it("caps the positive cache at cache-ttl-seconds even when nextUpdate is later", async () => {
		const { int, leaf } = await chain();
		const { fetch, urls } = stubResponders({
			[RESPONDER_URL]: answering({
				issuer: int,
				subject: leaf,
				nextUpdate: new Date(NOW.getTime() + 30 * 86_400_000),
			}),
		});
		const r = resolver(fetch, { cacheTtlSeconds: 60 });

		await r.resolve(leaf.cert, int.cert, NOW);
		await r.resolve(leaf.cert, int.cert, new Date(NOW.getTime() + 59_000));
		expect(urls()).toHaveLength(1);
		await r.resolve(leaf.cert, int.cert, new Date(NOW.getTime() + 60_000));
		expect(urls()).toHaveLength(2);
	});
});

describe("OCSP resolver — matching and shape", () => {
	it("refuses a response about a different certificate", async () => {
		const { int, leaf } = await chain();
		const other = await mintLeaf("other", 11, int);
		const { fetch } = stubResponders({
			[RESPONDER_URL]: answering({ issuer: int, subject: leaf, certIdFor: other }),
		});
		expect(await resolver(fetch).resolve(leaf.cert, int.cert, NOW)).toMatchObject({
			ok: false,
			reason: "no_matching_response",
		});
	});

	it("accepts a response that identifies the certificate by a SHA-256 CertID", async () => {
		// A responder may normalise the CertID to its own hash. Both hashes
		// name the same issuer and serial, so the match is recomputed with the
		// algorithm the responder chose rather than refused on the OID.
		const { int, leaf } = await chain();
		const { fetch } = stubResponders({
			[RESPONDER_URL]: answering({ issuer: int, subject: leaf, certIdHash: "SHA-256" }),
		});
		expect(await resolver(fetch).resolve(leaf.cert, int.cert, NOW)).toMatchObject({ ok: true });
	});

	it("reports a non-successful responseStatus as responder_error and remembers it per responder", async () => {
		// tryLater is the responder saying it cannot answer now; the whole
		// responder is down for the window, not only this certificate.
		const { int, leaf } = await chain();
		const other = await mintLeaf("other", 11, int, {
			extensions: [
				basicConstraints(false),
				keyUsage(KEY_USAGE.digitalSignature),
				clientAuthEku(),
				ocspAia(RESPONDER_URL),
			],
		});
		const { fetch, urls } = stubResponders({
			[RESPONDER_URL]: await mintOcspResponse({
				issuer: int,
				subject: leaf,
				responseStatus: OCSP_RESPONSE_STATUS.tryLater,
			}),
		});
		const r = resolver(fetch);

		const result = await r.resolve(leaf.cert, int.cert, NOW);
		expect(result).toMatchObject({ ok: false, reason: "responder_error" });
		if (!result.ok) expect(result.detail).toContain("tryLater");
		expect(await r.resolve(other.cert, int.cert, NOW)).toMatchObject({
			ok: false,
			reason: "responder_error",
		});
		expect(urls()).toEqual([RESPONDER_URL]);
	});

	it("reports bytes that are not an OCSPResponse as unparseable", async () => {
		const { int, leaf } = await chain();
		const { fetch, urls } = stubResponders({
			[RESPONDER_URL]: new Uint8Array([0x30, 0x03, 0x02, 0x01, 0xff]),
		});
		const r = resolver(fetch);
		expect(await r.resolve(leaf.cert, int.cert, NOW)).toMatchObject({
			ok: false,
			reason: "unparseable",
		});
		await r.resolve(leaf.cert, int.cert, NOW);
		expect(urls()).toEqual([RESPONDER_URL]);
	});

	it("refuses a response carrying a critical extension it does not process (RFC 6960 §4.4)", async () => {
		const { int, leaf } = await chain();
		const { fetch } = stubResponders({
			[RESPONDER_URL]: answering({
				issuer: int,
				subject: leaf,
				responseExtensions: [unknownCriticalExtension()],
			}),
		});
		const result = await resolver(fetch).resolve(leaf.cert, int.cert, NOW);
		expect(result).toMatchObject({ ok: false, reason: "unsupported_critical_extension" });
		if (!result.ok) expect(result.detail).toContain("1.3.6.1.4.1.99999.1.1");
	});

	it("applies the same rule to a critical single-response extension", async () => {
		const { int, leaf } = await chain();
		const { fetch } = stubResponders({
			[RESPONDER_URL]: answering({
				issuer: int,
				subject: leaf,
				singleExtensions: [unknownCriticalExtension()],
			}),
		});
		expect(await resolver(fetch).resolve(leaf.cert, int.cert, NOW)).toMatchObject({
			ok: false,
			reason: "unsupported_critical_extension",
		});
	});

	it("ignores a non-critical extension it does not recognise", async () => {
		const { int, leaf } = await chain();
		const { fetch } = stubResponders({
			[RESPONDER_URL]: answering({
				issuer: int,
				subject: leaf,
				responseExtensions: [unknownNonCriticalExtension()],
				singleExtensions: [unknownNonCriticalExtension()],
			}),
		});
		expect(await resolver(fetch).resolve(leaf.cert, int.cert, NOW)).toMatchObject({ ok: true });
	});
});

describe("OCSP resolver — responder discovery (RFC 5280 §4.2.2.1)", () => {
	it("reports a certificate with no authorityInfoAccess as no_responder, without a request", async () => {
		const root = await mintCa("Root", 1);
		const leaf = await mintLeaf("client", 10, root);
		const { fetch, urls } = stubResponders({});
		expect(await resolver(fetch).resolve(leaf.cert, root.cert, NOW)).toMatchObject({
			ok: false,
			reason: "no_responder",
		});
		expect(urls()).toEqual([]);
		expect(ocspResponders(leaf.cert)).toMatchObject({ ok: false, reason: "no_responder" });
	});

	it("reports an AIA naming only caIssuers as no_responder", async () => {
		const root = await mintCa("Root", 1);
		const leaf = await mintLeaf("client", 10, root, {
			extensions: [
				basicConstraints(false),
				keyUsage(KEY_USAGE.digitalSignature),
				clientAuthEku(),
				caIssuersAia("http://ca.test/root.crt"),
			],
		});
		expect(ocspResponders(leaf.cert)).toMatchObject({ ok: false, reason: "no_responder" });
	});

	it("keeps only HTTP(S) responders, in the order the certificate lists them", async () => {
		const { leaf } = await chain(["ldap://directory.test/ocsp", MIRROR_URL, RESPONDER_URL]);
		expect(ocspResponders(leaf.cert)).toEqual({ ok: true, urls: [MIRROR_URL, RESPONDER_URL] });
	});

	it("tries the next responder when the first cannot be used, and names the one that answered", async () => {
		const { int, leaf } = await chain([MIRROR_URL, RESPONDER_URL]);
		const { fetch, urls } = stubResponders({
			[MIRROR_URL]: "down",
			[RESPONDER_URL]: answering({ issuer: int, subject: leaf }),
		});
		expect(await resolver(fetch).resolve(leaf.cert, int.cert, NOW)).toMatchObject({
			ok: true,
			responder: RESPONDER_URL,
		});
		expect(urls()).toEqual([MIRROR_URL, RESPONDER_URL]);
	});

	it("does not ask a second responder once the first has answered", async () => {
		const { int, leaf } = await chain([RESPONDER_URL, MIRROR_URL]);
		const { fetch, urls } = stubResponders({
			[RESPONDER_URL]: answering({ issuer: int, subject: leaf }),
			[MIRROR_URL]: answering({ issuer: int, subject: leaf }),
		});
		expect(await resolver(fetch).resolve(leaf.cert, int.cert, NOW)).toMatchObject({ ok: true });
		expect(urls()).toEqual([RESPONDER_URL]);
	});

	it("reports every responder's failure when none answered", async () => {
		const { int, leaf } = await chain([MIRROR_URL, RESPONDER_URL]);
		const { fetch } = stubResponders({ [MIRROR_URL]: "down", [RESPONDER_URL]: "down" });
		const result = await resolver(fetch).resolve(leaf.cert, int.cert, NOW);
		expect(result).toMatchObject({ ok: false, reason: "fetch_failed" });
		if (!result.ok) {
			expect(result.detail).toContain(MIRROR_URL);
			expect(result.detail).toContain(RESPONDER_URL);
		}
	});
});

describe("OCSP resolver — one request per certificate, not one per caller", () => {
	it("answers a second lookup from the cache", async () => {
		const { int, leaf } = await chain();
		const { fetch, urls } = stubResponders({
			[RESPONDER_URL]: answering({ issuer: int, subject: leaf }),
		});
		const r = resolver(fetch);
		await r.resolve(leaf.cert, int.cert, NOW);
		expect(await r.resolve(leaf.cert, int.cert, NOW)).toMatchObject({ ok: true });
		expect(urls()).toEqual([RESPONDER_URL]);
		expect(r.size()).toBe(1);
	});

	it("shares one in-flight request among concurrent lookups of the same certificate", async () => {
		const { int, leaf } = await chain();
		const gate = { release: (): void => {} };
		const opened = new Promise<void>((resolve) => {
			gate.release = resolve;
		});
		const answer = answering({ issuer: int, subject: leaf });
		const { fetch, urls } = stubResponders({
			[RESPONDER_URL]: async (request) => {
				await opened;
				return (answer as (r: GuardedRequest | undefined) => Promise<Uint8Array>)(request);
			},
		});
		const r = resolver(fetch);

		const lookups = Array.from({ length: 5 }, () => r.resolve(leaf.cert, int.cert, NOW));
		await settle(() => urls().length > 0);
		expect(urls()).toEqual([RESPONDER_URL]);
		gate.release();
		const results = await Promise.all(lookups);
		expect(results.every((result) => result.ok)).toBe(true);
		expect(urls()).toEqual([RESPONDER_URL]);
		expect(r.size()).toBe(1);
	});

	it("does not retry a responder that is down within the negative window", async () => {
		const { int, leaf } = await chain();
		const { fetch, urls } = stubResponders({ [RESPONDER_URL]: "down" });
		const r = resolver(fetch);

		expect(await r.resolve(leaf.cert, int.cert, NOW)).toMatchObject({
			ok: false,
			reason: "fetch_failed",
		});
		expect(r.size()).toBe(1);
		await r.resolve(leaf.cert, int.cert, new Date(NOW.getTime() + OCSP_NEGATIVE_CACHE_TTL_MS - 1));
		expect(urls()).toHaveLength(1);
		await r.resolve(leaf.cert, int.cert, new Date(NOW.getTime() + OCSP_NEGATIVE_CACHE_TTL_MS));
		expect(urls()).toHaveLength(2);
	});

	it("shares the CRL resolver's negative window", () => {
		expect(OCSP_NEGATIVE_CACHE_TTL_MS).toBe(CRL_NEGATIVE_CACHE_TTL_MS);
	});

	it("bounds the cache", async () => {
		const { int } = await chain();
		const leaves = await Promise.all(
			Array.from({ length: 4 }, (_unused, i) =>
				mintLeaf(`client-${i}`, 100 + i, int, {
					extensions: [
						basicConstraints(false),
						keyUsage(KEY_USAGE.digitalSignature),
						clientAuthEku(),
						ocspAia(RESPONDER_URL),
					],
				}),
			),
		);
		const { fetch } = stubResponders({
			[RESPONDER_URL]: async (request) => {
				const body = request?.body as Uint8Array;
				const serial =
					pkijs.OCSPRequest.fromBER(body).tbsRequest.requestList[0]?.reqCert.serialNumber.valueBlock
						.valueDec;
				const subject = leaves.find((entry) => entry.serial === serial) as Minted;
				return mintOcspResponse({ issuer: int, subject, nonce: nonceOf(body) as Uint8Array });
			},
		});
		const r = createOcspResolver({
			fetch,
			cacheTtlSeconds: 3_600,
			maxCacheEntries: 2,
			algorithms: POLICY,
		});
		for (const leaf of leaves)
			expect(await r.resolve(leaf.cert, int.cert, NOW)).toMatchObject({ ok: true });
		expect(r.size()).toBe(2);
	});
});

describe("OCSP resolver — through the guarded fetch", () => {
	const guarded = (fetchImpl: unknown, allowedHosts = ["ocsp.test"]) =>
		createGuardedFetch({
			allowedHosts,
			timeoutMs: 1_000,
			maxBytes: 1_024,
			fetchImpl: fetchImpl as typeof fetch,
		});

	it("refuses a redirect", async () => {
		const { int, leaf } = await chain();
		const fetchImpl = vi.fn(async () => {
			throw new TypeError("fetch failed", { cause: new Error("unexpected redirect") });
		});
		const result = await resolver(guarded(fetchImpl)).resolve(leaf.cert, int.cert, NOW);
		expect(result).toMatchObject({ ok: false, reason: "fetch_failed" });
		if (!result.ok) expect(result.detail).toContain("redirect_refused");
	});

	it("refuses an oversized response", async () => {
		const { int, leaf } = await chain();
		const fetchImpl = vi.fn(
			async () =>
				new Response(new Uint8Array(4_096) as unknown as BodyInit, {
					status: 200,
					headers: { "content-type": "application/ocsp-response" },
				}),
		);
		const result = await resolver(guarded(fetchImpl)).resolve(leaf.cert, int.cert, NOW);
		expect(result).toMatchObject({ ok: false, reason: "fetch_failed" });
		if (!result.ok) expect(result.detail).toContain("response_too_large");
	});

	it("refuses a response that is not application/ocsp-response", async () => {
		const { int, leaf } = await chain();
		const bytes = await mintOcspResponse({ issuer: int, subject: leaf });
		const fetchImpl = vi.fn(
			async () =>
				new Response(bytes as unknown as BodyInit, {
					status: 200,
					headers: { "content-type": "text/html" },
				}),
		);
		const result = await resolver(guarded(fetchImpl)).resolve(leaf.cert, int.cert, NOW);
		expect(result).toMatchObject({ ok: false, reason: "fetch_failed" });
		if (!result.ok) expect(result.detail).toContain("unexpected_content_type");
	});

	it("never contacts a responder outside the host allowlist", async () => {
		const { int, leaf } = await chain("http://169.254.169.254/latest/meta-data/");
		const fetchImpl = vi.fn();
		const result = await resolver(guarded(fetchImpl)).resolve(leaf.cert, int.cert, NOW);
		expect(result).toMatchObject({ ok: false, reason: "fetch_failed" });
		if (!result.ok) expect(result.detail).toContain("host_not_allowed");
		expect(fetchImpl).not.toHaveBeenCalled();
	});

	it("sends the request as an OCSP POST and reads a well-typed answer", async () => {
		const { int, leaf } = await chain();
		const fetchImpl = vi.fn(async (_url: URL, init: RequestInit) => {
			expect(init.method).toBe("POST");
			expect(init.redirect).toBe("error");
			expect((init.headers as Record<string, string>)["content-type"]).toBe(
				"application/ocsp-request",
			);
			const body = init.body as Uint8Array;
			const bytes = await mintOcspResponse({
				issuer: int,
				subject: leaf,
				nonce: nonceOf(body) as Uint8Array,
			});
			return new Response(bytes as unknown as BodyInit, {
				status: 200,
				headers: { "content-type": "application/ocsp-response" },
			});
		});
		expect(await resolver(guarded(fetchImpl)).resolve(leaf.cert, int.cert, NOW)).toMatchObject({
			ok: true,
			status: { status: "good" },
		});
	});
});
