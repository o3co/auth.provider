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
 * What `full-pki` writes when a library refuses revocation material — pkijs
 * parsing a CRL or an OCSP response, WebCrypto checking a signature, the
 * platform fetch reaching a responder — against the real libraries.
 *
 * A refusal's `detail` is this package's own fixed text, which the operator's
 * log line and the refusal carry; the library's error travels beside it as
 * `err`, core's `loggableError` projection, on the result and on the one line
 * that reports it. The library's message is its reading of bytes a CA, a
 * responder or a network path handed over, and it used to be copied into
 * `detail`. Which limit fired is read from what the library says in a
 * structured way — a status, an error code — never from its message.
 */

import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import type { Logger } from "@o3co/auth-provider-core";
import * as asn1js from "asn1js";
import type { Request } from "express";
import * as pkijs from "pkijs";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createMtlsMechanism } from "#/extractor.mjs";
import { DEFAULT_SIGNATURE_ALGORITHMS } from "#/fullPki/algorithms.mjs";
import { createGuardedFetch } from "#/fullPki/fetchGuard.mjs";
import { createFullPkiValidator, type RevocationPolicy } from "#/fullPki/validate.mjs";
import type { Minted } from "./pkiFactory.mjs";
import {
	basicConstraints,
	clientAuthEku,
	crlDistributionPoints,
	KEY_USAGE,
	keyUsage,
	mintCa,
	mintCrl,
	mintIntermediate,
	mintLeaf,
	mintOcspResponse,
	nonceOf,
	ocspAia,
} from "./pkiFactory.mjs";

const NOW = new Date("2027-01-01T00:00:00Z");
const INT_CRL_URL = "http://crl.test/int.crl";
const ROOT_CRL_URL = "http://crl.test/root.crl";
const INT_OCSP_URL = "http://ocsp.test/int";
const ROOT_OCSP_URL = "http://ocsp.test/root";
const OCSP_BASIC = "1.3.6.1.5.5.7.48.1.1";

const policy = (
	mode: "crl" | "ocsp" | "both",
	onUnavailable: "reject" | "allow",
): RevocationPolicy => ({
	mode,
	onUnavailable,
	allowedHosts: ["crl.test", "ocsp.test"],
	fetchTimeoutMs: 1_000,
	cacheTtlSeconds: 3_600,
	maxResponseBytes: 1_000_000,
});

type Answer = Uint8Array | ((init: RequestInit | undefined) => Promise<Response>);

/** A platform `fetch` answering from a table; anything else is a 404. */
const tableFetch = (table: Record<string, Answer>) =>
	(async (input: URL | RequestInfo, init?: RequestInit) => {
		const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
		const entry = table[url];
		if (entry === undefined) return new Response(null, { status: 404 });
		if (typeof entry === "function") return entry(init);
		return new Response(entry as unknown as BodyInit, { status: 200 });
	}) as unknown as typeof globalThis.fetch;

const ocspResponse = (bytes: Uint8Array): Response =>
	new Response(bytes as unknown as BodyInit, {
		status: 200,
		headers: { "content-type": "application/ocsp-response" },
	});

/** A responder answering for `subject`, the nonce echoed, the response passed through `alter`. */
const ocspAnswer =
	(issuer: Minted, subject: Minted, alter: (der: Uint8Array) => Uint8Array = (der) => der) =>
	async (init: RequestInit | undefined): Promise<Response> => {
		const body = init?.body;
		const nonce = body instanceof Uint8Array ? nonceOf(body) : undefined;
		const der = await mintOcspResponse({
			issuer,
			subject,
			...(nonce === undefined ? {} : { nonce }),
		});
		return ocspResponse(alter(der));
	};

/** Bytes no ASN.1 parser takes for a CRL, a response or a signature. */
const GARBAGE = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);

/** The CRL, its signature value replaced by bytes that are not an ECDSA signature's DER. */
const withUnreadableSignature = (der: Uint8Array): Uint8Array => {
	const crl = pkijs.CertificateRevocationList.fromBER(der);
	crl.signatureValue = new asn1js.BitString({ valueHex: GARBAGE.slice().buffer });
	return new Uint8Array(crl.toSchema().toBER(false));
};

/** The OCSP response, its BasicOCSPResponse's signature value replaced the same way. */
const withUnreadableOcspSignature = (der: Uint8Array): Uint8Array => {
	const response = pkijs.OCSPResponse.fromBER(der);
	const basic = pkijs.BasicOCSPResponse.fromBER(
		response.responseBytes?.response.valueBlock.valueHexView ?? new Uint8Array(),
	);
	basic.signature = new asn1js.BitString({ valueHex: GARBAGE.slice().buffer });
	return ocspWrapping(new Uint8Array(basic.toSchema().toBER(false)));
};

/** A successful OCSPResponse whose `responseBytes` carry `basic` as they are. */
const ocspWrapping = (basic: Uint8Array): Uint8Array =>
	new Uint8Array(
		new pkijs.OCSPResponse({
			responseStatus: new asn1js.Enumerated({ value: 0 }),
			responseBytes: new pkijs.ResponseBytes({
				responseType: OCSP_BASIC,
				response: new asn1js.OctetString({ valueHex: basic.slice().buffer }),
			}),
		})
			.toSchema()
			.toBER(false),
	);

/** root → intermediate → leaf, each non-anchor pointing at its issuer's CRL and responder. */
const chain = async () => {
	const root = await mintCa("Root", 1);
	const int = await mintIntermediate("Intermediate", 2, root, {
		extensions: [
			basicConstraints(true),
			keyUsage(KEY_USAGE.keyCertSign | KEY_USAGE.cRLSign),
			crlDistributionPoints([ROOT_CRL_URL]),
			ocspAia(ROOT_OCSP_URL),
		],
	});
	const leaf = await mintLeaf("client", 10, int, {
		extensions: [
			basicConstraints(false),
			keyUsage(KEY_USAGE.digitalSignature),
			clientAuthEku(),
			crlDistributionPoints([INT_CRL_URL]),
			ocspAia(INT_OCSP_URL),
		],
	});
	return { root, int, leaf };
};

const recordingLogger = () => ({ warn: vi.fn(), debug: vi.fn() });

const validator = (
	root: Minted,
	revocation: RevocationPolicy,
	fetchImpl: typeof globalThis.fetch,
	logger: ReturnType<typeof recordingLogger>,
) =>
	createFullPkiValidator({
		trustedCas: [root.x509],
		algorithms: { signatureAlgorithms: DEFAULT_SIGNATURE_ALGORITHMS, minRsaKeyBits: 2048 },
		maxChainDepth: 6,
		revocation,
		fetchImpl,
		logger,
	});

/** A projection, as `loggableError` makes one: plain data, the library's error name kept. */
const projectionOf = (name: string) =>
	expect.objectContaining({ name, detail: expect.any(String) });

/** The one warn line, its `detail` free of the projected library text. */
const expectOneLine = (
	logger: ReturnType<typeof recordingLogger>,
	fields: Record<string, unknown>,
	event: string,
) => {
	expect(logger.warn.mock.calls).toEqual([[fields, event]]);
	const [line] = logger.warn.mock.calls[0] as [{ detail: string; err: { detail: string } }];
	expect(line.err).not.toBeInstanceOf(Error);
	expect(line.detail).not.toContain(line.err.detail);
};

describe("a CRL pkijs cannot use", () => {
	it("one that is not DER: 'unparseable', fixed detail, pkijs's error as the projection", async () => {
		const { root, int, leaf } = await chain();
		const logger = recordingLogger();
		const result = await validator(
			root,
			policy("crl", "allow"),
			tableFetch({ [INT_CRL_URL]: GARBAGE, [ROOT_CRL_URL]: await mintCrl({ issuer: root }) }),
			logger,
		).validate(leaf.x509, [int.x509], NOW);

		expect(result).toEqual({ ok: true });
		expectOneLine(
			logger,
			{
				subject: "CN=client",
				reason: "unparseable",
				detail: `${INT_CRL_URL}: unparseable (not a DER CRL)`,
				err: projectionOf("AsnError"),
			},
			"mtls_revocation_unavailable_allowed",
		);
	});

	it("the same under 'reject': the refusal carries the fixed detail, pkijs's error as its cause", async () => {
		const { root, int, leaf } = await chain();
		const logger = recordingLogger();
		const result = await validator(
			root,
			policy("crl", "reject"),
			tableFetch({ [INT_CRL_URL]: GARBAGE, [ROOT_CRL_URL]: await mintCrl({ issuer: root }) }),
			logger,
		).validate(leaf.x509, [int.x509], NOW);

		expect(result).toEqual({
			ok: false,
			step: "revocation status unavailable",
			detail: `CN=client: unparseable — ${INT_CRL_URL}: unparseable (not a DER CRL)`,
			cause: expect.objectContaining({ name: "AsnError" }),
		});
	});

	it("one whose signature value WebCrypto cannot read: 'bad_signature', fixed detail, the projection", async () => {
		const { root, int, leaf } = await chain();
		const logger = recordingLogger();
		const result = await validator(
			root,
			policy("crl", "allow"),
			tableFetch({
				[INT_CRL_URL]: withUnreadableSignature(await mintCrl({ issuer: int })),
				[ROOT_CRL_URL]: await mintCrl({ issuer: root }),
			}),
			logger,
		).validate(leaf.x509, [int.x509], NOW);

		expect(result).toEqual({ ok: true });
		expectOneLine(
			logger,
			{
				subject: "CN=client",
				reason: "bad_signature",
				detail: `${INT_CRL_URL}: bad_signature (signature check failed)`,
				err: projectionOf("AsnError"),
			},
			"mtls_revocation_unavailable_allowed",
		);
	});
});

describe("an OCSP response pkijs cannot use", () => {
	const answered = async (alter: (der: Uint8Array) => Uint8Array) => {
		const { root, int, leaf } = await chain();
		const logger = recordingLogger();
		const result = await validator(
			root,
			policy("ocsp", "allow"),
			tableFetch({
				[INT_OCSP_URL]: ocspAnswer(int, leaf, alter),
				[ROOT_OCSP_URL]: ocspAnswer(root, int),
			}),
			logger,
		).validate(leaf.x509, [int.x509], NOW);
		expect(result).toEqual({ ok: true });
		return logger;
	};

	it("an OCSPResponse that is not DER", async () => {
		const logger = await answered(() => GARBAGE);
		expectOneLine(
			logger,
			{
				subject: "CN=client",
				reason: "unparseable",
				detail: `${INT_OCSP_URL}: unparseable (not a DER OCSPResponse)`,
				err: projectionOf("AsnError"),
			},
			"mtls_revocation_unavailable_allowed",
		);
	});

	it("a BasicOCSPResponse that is not DER", async () => {
		const logger = await answered(() => ocspWrapping(GARBAGE));
		expectOneLine(
			logger,
			{
				subject: "CN=client",
				reason: "unparseable",
				detail: `${INT_OCSP_URL}: unparseable (not a DER BasicOCSPResponse)`,
				err: projectionOf("AsnError"),
			},
			"mtls_revocation_unavailable_allowed",
		);
	});

	it("a signature value WebCrypto cannot read", async () => {
		const logger = await answered(withUnreadableOcspSignature);
		expectOneLine(
			logger,
			{
				subject: "CN=client",
				reason: "bad_signature",
				detail: `${INT_OCSP_URL}: bad_signature (signature check failed)`,
				err: projectionOf("AsnError"),
			},
			"mtls_revocation_unavailable_allowed",
		);
	});

	it("under 'both', the fallback line carries the OCSP failure's projection", async () => {
		const { root, int, leaf } = await chain();
		const logger = recordingLogger();
		const result = await validator(
			root,
			policy("both", "reject"),
			tableFetch({
				[INT_OCSP_URL]: async () => ocspResponse(GARBAGE),
				[ROOT_OCSP_URL]: ocspAnswer(root, int),
				[INT_CRL_URL]: await mintCrl({ issuer: int }),
			}),
			logger,
		).validate(leaf.x509, [int.x509], NOW);

		expect(result).toEqual({ ok: true });
		expectOneLine(
			logger,
			{
				subject: "CN=client",
				reason: "unparseable",
				detail: `${INT_OCSP_URL}: unparseable (not a DER OCSPResponse)`,
				err: projectionOf("AsnError"),
			},
			"mtls_revocation_ocsp_fallback",
		);
	});
});

// ---------------------------------------------------------------------------
// The platform fetch, against real sockets
// ---------------------------------------------------------------------------

const servers: Server[] = [];

afterEach(async () => {
	await Promise.all(
		servers
			.splice(0)
			.map((server) => new Promise<void>((resolve) => server.close(() => resolve()))),
	);
});

/** A loopback HTTP server answering every request with `handle`; its origin. */
const serve = async (handle: Parameters<typeof createServer>[1]): Promise<string> => {
	const server = createServer(handle);
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	servers.push(server);
	return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
};

/** A loopback port nothing listens on. */
const closedPort = async (): Promise<number> => {
	const server = createServer();
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const { port } = server.address() as AddressInfo;
	await new Promise<void>((resolve) => server.close(() => resolve()));
	return port;
};

const guarded = () =>
	createGuardedFetch({ allowedHosts: ["127.0.0.1"], timeoutMs: 2_000, maxBytes: 1_024 });

describe("the guarded fetch, against the platform fetch", () => {
	it("a refused connection is 'network_error' named by its code, the fetch error as the cause", async () => {
		const outcome = await guarded()(`http://127.0.0.1:${await closedPort()}/int.crl`);
		expect(outcome).toEqual({
			ok: false,
			reason: "network_error",
			detail: "ECONNREFUSED",
			cause: expect.objectContaining({
				name: "TypeError",
				cause: expect.objectContaining({ code: "ECONNREFUSED" }),
			}),
		});
	});

	it("a redirect is 'redirect_refused' by its status, never followed", async () => {
		let hits = 0;
		const origin = await serve((_req, res) => {
			hits++;
			res.writeHead(302, { location: "http://169.254.169.254/latest/meta-data/" });
			res.end();
		});
		expect(await guarded()(`${origin}/int.crl`)).toEqual({
			ok: false,
			reason: "redirect_refused",
			detail: "HTTP 302",
		});
		expect(hits).toBe(1);
	});
});

describe("createMtlsMechanism — the refusal line carries the projection", () => {
	it("mtls_full_pki_validation_failed has the revocation failure's err", async () => {
		// The root's CRL, for the intermediate, is served clean; the
		// intermediate's, for the leaf, is not DER.
		let rootCrl = new Uint8Array();
		const origin = await serve((req, res) => {
			res.writeHead(200, { "content-type": "application/pkix-crl" });
			res.end(Buffer.from(req.url === "/int.crl" ? GARBAGE : rootCrl));
		});
		const root = await mintCa("Root", 1);
		rootCrl = await mintCrl({ issuer: root });
		const int = await mintIntermediate("Intermediate", 2, root, {
			extensions: [
				basicConstraints(true),
				keyUsage(KEY_USAGE.keyCertSign | KEY_USAGE.cRLSign),
				crlDistributionPoints([`${origin}/root.crl`]),
			],
		});
		const leaf = await mintLeaf("client", 10, int, {
			extensions: [
				basicConstraints(false),
				keyUsage(KEY_USAGE.digitalSignature),
				clientAuthEku(),
				crlDistributionPoints([`${origin}/int.crl`]),
			],
		});
		const warn = vi.fn();
		const logger = {
			warn,
			error: vi.fn(),
			info: vi.fn(),
			debug: vi.fn(),
			trace: vi.fn(),
			fatal: vi.fn(),
		};
		(logger as unknown as { child: () => unknown }).child = () => logger;
		const mech = createMtlsMechanism({
			source: "tls-layer",
			mode: "full-pki",
			trustedCas: [root.pem],
			fullPki: {
				revocation: {
					mode: "crl",
					"on-unavailable": "reject",
					"allowed-hosts": ["127.0.0.1"],
					"fetch-timeout-ms": 2_000,
					"cache-ttl-seconds": 60,
					"max-response-bytes": 1_024,
				},
			},
			logger: logger as unknown as Logger,
		});
		const req = {
			get: () => undefined,
			socket: {
				getPeerCertificate: () => {
					const rootNode: Record<string, unknown> = { raw: Buffer.from(root.der) };
					rootNode.issuerCertificate = rootNode;
					return {
						raw: Buffer.from(leaf.der),
						issuerCertificate: { raw: Buffer.from(int.der), issuerCertificate: rootNode },
					};
				},
			},
		} as unknown as Request;

		await expect(mech.extract(req)).rejects.toMatchObject({ reason: "chain_validation_failed" });
		const refusal = warn.mock.calls.filter(
			([, event]) => event === "mtls_full_pki_validation_failed",
		);
		expect(refusal).toEqual([
			[
				{
					step: "revocation status unavailable",
					detail: `CN=client: unparseable — ${origin}/int.crl: unparseable (not a DER CRL)`,
					err: projectionOf("AsnError"),
				},
				"mtls_full_pki_validation_failed",
			],
		]);
	});
});
