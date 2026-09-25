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
 * What the mechanism throws when a parser refuses its input — a trust anchor
 * at boot, a forwarded header, a PEM block, a DER certificate, a peer chain:
 * the failure in fixed words, the parser's own error as `cause`.
 *
 * The parser's message is its reading of what it was handed, and what it was
 * handed here is a client's certificate or header, or an operator's file. It
 * used to be cast `(err as Error)` and copied into the message, with nothing
 * kept as `cause`; the message goes wherever the refusal goes.
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { loggableError } from "@o3co/auth-provider-core";
import type { Request } from "express";
import { describe, expect, it } from "vitest";
import { MtlsError } from "#/errors.mjs";
import { createMtlsMechanism } from "#/extractor.mjs";
import { mintCa, mintIntermediate, mintLeaf } from "./fullPki/pkiFactory.mjs";

const fixturesDir = join(dirname(fileURLToPath(import.meta.url)), "fixtures");
const LEAF_PEM = readFileSync(join(fixturesDir, "leaf.pem"), "utf8");
const ROOT_PEM = readFileSync(join(fixturesDir, "root.pem"), "utf8");

const TRUSTED_PEER = "10.0.0.7";

const headerReq = (value: string): Request =>
	({
		get: (name: string) => (name.toLowerCase() === "x-forwarded-client-cert" ? value : undefined),
		socket: { remoteAddress: TRUSTED_PEER },
	}) as unknown as Request;

/** A PEM block whose base64 decodes to bytes no certificate parser accepts. */
const NOT_A_CERTIFICATE = `-----BEGIN CERTIFICATE-----\n${Buffer.from("not a certificate").toString("base64")}\n-----END CERTIFICATE-----\n`;

/** The error `run` throws or rejects with. */
const failureOf = async (run: () => unknown): Promise<Error & { cause: Error }> => {
	try {
		await run();
	} catch (err) {
		return err as Error & { cause: Error };
	}
	throw new Error("expected a failure");
};

/** Fixed text in the message, the parser's error on `cause` and nowhere else. */
const expectCarried = (err: Error & { cause: unknown }, message: string): void => {
	expect(err.message).toBe(message);
	expect(err.cause).toBeInstanceOf(Error);
	expect(err.message).not.toContain((err.cause as Error).message);
	expect(loggableError(err).cause).toMatchObject({ name: (err.cause as Error).name });
};

describe("a parser's refusal: fixed text, the parser's error on the cause", () => {
	it("a trust anchor that is not an X.509 certificate refuses boot", async () => {
		const err = await failureOf(() =>
			createMtlsMechanism({
				source: "header",
				trustedProxies: [TRUSTED_PEER],
				mode: "pki",
				trustedCas: [NOT_A_CERTIFICATE],
			}),
		);
		expectCarried(err, "createMtlsMechanism: trustedCas[0] is not a parseable X.509 certificate");
	});

	it("a trust-anchor file that cannot be read refuses boot, the errno on the cause", async () => {
		const path = "/nonexistent/o3co-mtls-test/ca.pem";
		const err = await failureOf(() =>
			createMtlsMechanism({
				source: "header",
				trustedProxies: [TRUSTED_PEER],
				mode: "pki",
				trustedCas: [`file:${path}`],
			}),
		);
		expectCarried(
			err,
			`createMtlsMechanism: trustedCas[0] = "file:${path}": failed to read file at ${path}`,
		);
		expect(err.cause).toMatchObject({ code: "ENOENT" });
	});

	it("a forwarded header the dialect's parser refuses", async () => {
		const mech = createMtlsMechanism({
			source: "header",
			trustedProxies: [TRUSTED_PEER],
			certHeaderDialect: "envoy",
			mode: "self-signed",
		});
		const err = await failureOf(() => mech.extract(headerReq("By=foo;Hash=bar")));
		expect(err).toBeInstanceOf(MtlsError);
		expect(err).toMatchObject({ reason: "malformed_header", detail: { dialect: "envoy" } });
		expectCarried(err, "envoy header parse failure");
	});

	it("a PEM block whose body is not base64", async () => {
		const mech = createMtlsMechanism({
			source: "header",
			trustedProxies: [TRUSTED_PEER],
			certHeaderDialect: "plain-pem",
			mode: "self-signed",
		});
		const err = await failureOf(() =>
			mech.extract(headerReq("-----BEGIN CERTIFICATE-----\nGAR*BAGE\n-----END CERTIFICATE-----")),
		);
		expect(err).toMatchObject({ reason: "cert_decode_failed" });
		expectCarried(err, "PEM decode failed");
	});

	it("a PEM block whose DER is not a certificate", async () => {
		const mech = createMtlsMechanism({
			source: "header",
			trustedProxies: [TRUSTED_PEER],
			certHeaderDialect: "plain-pem",
			mode: "self-signed",
		});
		const err = await failureOf(() => mech.extract(headerReq(NOT_A_CERTIFICATE)));
		expect(err).toMatchObject({ reason: "cert_decode_failed" });
		expectCarried(err, "DER parse failed");
	});

	it("an XFCC Chain= entry that is not a certificate", async () => {
		const mech = createMtlsMechanism({
			source: "header",
			trustedProxies: [TRUSTED_PEER],
			certHeaderDialect: "envoy",
			mode: "pki",
			trustedCas: [ROOT_PEM],
		});
		const xfcc = `Cert=${encodeURIComponent(LEAF_PEM)};Chain=${encodeURIComponent(NOT_A_CERTIFICATE)}`;
		const err = await failureOf(() => mech.extract(headerReq(xfcc)));
		expect(err).toMatchObject({ reason: "cert_decode_failed" });
		expectCarried(err, "Chain= entry DER parse failed");
	});

	it("a TLS peer chain whose intermediate is not a certificate", async () => {
		const root = await mintCa("Root", 1);
		const int = await mintIntermediate("Intermediate", 2, root);
		const leaf = await mintLeaf("client", 10, int);
		const mech = createMtlsMechanism({
			source: "tls-layer",
			mode: "full-pki",
			trustedCas: [root.pem],
			fullPki: {
				revocation: {
					mode: "disabled",
					"on-unavailable": "reject",
					"allowed-hosts": [],
					"fetch-timeout-ms": 3000,
					"cache-ttl-seconds": 3600,
					"max-response-bytes": 1_048_576,
				},
			},
		});
		const req = {
			get: () => undefined,
			socket: {
				getPeerCertificate: () => ({
					raw: Buffer.from(leaf.der),
					issuerCertificate: { raw: Buffer.from("not a certificate") },
				}),
			},
		} as unknown as Request;
		const err = await failureOf(() => mech.extract(req));
		expect(err).toMatchObject({ reason: "cert_decode_failed" });
		expectCarried(err, "TLS peer chain DER parse failed");
	});
});
