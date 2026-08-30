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
 * `mode = "full-pki"` end-to-end through `createMtlsMechanism` — the wiring
 * between the config slice and the validator.
 *
 * The unit tests cover what each check does. These cover that the mechanism
 * actually reaches them with the values it should, which is a separate
 * failure and one that reads as working code: a bound that was never passed
 * through does not throw, it just stops applying.
 */

import type { Request } from "express";
import { describe, expect, it } from "vitest";
import { createMtlsMechanism } from "#/extractor.mjs";
import { FULL_PKI_DEFAULTS } from "#/fullPki/defaults.mjs";
import {
	basicConstraints,
	clientAuthEku,
	mint,
	mintCa,
	mintIntermediate,
	mintLeaf,
} from "./pkiFactory.mjs";

const TRUSTED_PEER = "10.0.0.7";

/** A `tls-layer` request whose peer chain is the given certificates, leaf first. */
const makeTlsReq = (chain: readonly { der: Uint8Array }[]): Partial<Request> => {
	const link = (index: number): unknown => {
		const entry = chain[index];
		if (entry === undefined) return undefined;
		const node: Record<string, unknown> = { raw: Buffer.from(entry.der) };
		// A self-signed root points at itself, exactly as Node reports it.
		node.issuerCertificate = index + 1 < chain.length ? link(index + 1) : node;
		return node;
	};
	return {
		get: () => undefined,
		socket: {
			getPeerCertificate: () => link(0),
		} as unknown as Request["socket"],
	};
};

const REVOCATION_OFF = {
	mode: "disabled" as const,
	"on-unavailable": "reject" as const,
	"allowed-hosts": [] as readonly string[],
	"fetch-timeout-ms": 3000,
	"cache-ttl-seconds": 3600,
	"max-response-bytes": 1_048_576,
};

describe("createMtlsMechanism — mode = full-pki", () => {
	it("binds a certificate that validates against the configured anchor", async () => {
		const root = await mintCa("Root", 1);
		const int = await mintIntermediate("Intermediate", 2, root);
		const leaf = await mintLeaf("client", 10, int);

		const mech = createMtlsMechanism({
			source: "tls-layer",
			mode: "full-pki",
			trustedCas: [root.pem],
			fullPki: { ...FULL_PKI_DEFAULTS_CONFIG, revocation: REVOCATION_OFF },
		});

		const binding = await mech.extract(makeTlsReq([leaf, int, root]) as Request);
		expect(binding?.kind).toBe("mtls");
		expect(binding?.confirmation["x5t#S256"]).toBeTypeOf("string");
	});

	it("refuses a certificate whose anchor is not configured", async () => {
		const root = await mintCa("Root", 1);
		const rogue = await mintCa("Rogue", 100);
		const leaf = await mintLeaf("client", 10, rogue);

		const mech = createMtlsMechanism({
			source: "tls-layer",
			mode: "full-pki",
			trustedCas: [root.pem],
			fullPki: { ...FULL_PKI_DEFAULTS_CONFIG, revocation: REVOCATION_OFF },
		});

		await expect(mech.extract(makeTlsReq([leaf, rogue]) as Request)).rejects.toThrow(
			/path validation/,
		);
	});

	it("still bounds the chain when the tuning keys never reach the mechanism", async () => {
		// The regression this guards: a composition root that supplies only the
		// revocation block bypasses `mtlsConfigSchema` and its defaults. Reading
		// `max-chain-depth` straight through then makes `presented > undefined`
		// evaluate to `false` — the depth guard stops existing, silently, with
		// nothing raised at boot. Reverting `resolveFullPkiTuning` in
		// `buildFullPkiValidator` makes this test pass a chain it should refuse.
		const root = await mintCa("Root", 1);
		const leaf = await mintLeaf("client", 10, root);
		// Distinct certificates: `peerChainFrom` de-duplicates by fingerprint to
		// terminate the self-referential root, so repeating one certificate
		// would collapse to a single hop and never reach the bound. The walk
		// admits one more than the bound precisely so the validator is what
		// refuses, which is what this asserts.
		const filler = await Promise.all(
			Array.from({ length: FULL_PKI_DEFAULTS.maxChainDepth }, (_unused, i) =>
				mintCa(`Filler ${i}`, 200 + i),
			),
		);
		const overLimit = [leaf, ...filler];

		const mech = createMtlsMechanism({
			source: "tls-layer",
			mode: "full-pki",
			trustedCas: [root.pem],
			// Deliberately no max-chain-depth / signature-algorithms /
			// min-rsa-key-bits.
			fullPki: { revocation: REVOCATION_OFF },
		});

		await expect(mech.extract(makeTlsReq(overLimit) as Request)).rejects.toThrow(/chain too long/);
	});

	it("still applies the RSA floor when min-rsa-key-bits never reaches the mechanism", async () => {
		const root = await mintCa("Root", 1);
		const leaf = await mintLeaf("client", 10, root, { algorithm: "rsa-1024" });

		const mech = createMtlsMechanism({
			source: "tls-layer",
			mode: "full-pki",
			trustedCas: [root.pem],
			fullPki: { revocation: REVOCATION_OFF },
		});

		await expect(mech.extract(makeTlsReq([leaf, root]) as Request)).rejects.toThrow(
			/rsa key too small/,
		);
	});

	it("keeps the narrow mode's leaf profile through the mechanism", async () => {
		const root = await mintCa("Root", 1);
		// No `keyUsage`: Node's `X509Certificate.ca` is OpenSSL's
		// `X509_check_ca`, which reports *false* for a certificate that claims
		// `CA:TRUE` while its keyUsage omits `keyCertSign` — such a certificate
		// is self-contradictory rather than a CA. Adding keyUsage here would
		// make the fixture pass the leaf-profile check for the wrong reason.
		const leaf = await mint({
			cn: "client",
			serial: 10,
			issuer: root,
			extensions: [basicConstraints(true), clientAuthEku()],
		});

		const mech = createMtlsMechanism({
			source: "tls-layer",
			mode: "full-pki",
			trustedCas: [root.pem],
			fullPki: { ...FULL_PKI_DEFAULTS_CONFIG, revocation: REVOCATION_OFF },
		});

		await expect(mech.extract(makeTlsReq([leaf, root]) as Request)).rejects.toThrow(
			/path validation/,
		);
	});

	it("returns null — not an error — when no client certificate was presented", async () => {
		const root = await mintCa("Root", 1);
		const mech = createMtlsMechanism({
			source: "tls-layer",
			mode: "full-pki",
			trustedCas: [root.pem],
			fullPki: { ...FULL_PKI_DEFAULTS_CONFIG, revocation: REVOCATION_OFF },
		});

		const req = {
			get: () => undefined,
			socket: { getPeerCertificate: () => ({}) } as unknown as Request["socket"],
		} as Partial<Request>;
		expect(await mech.extract(req as Request)).toBeNull();
	});

	it("is unavailable to the narrow mode: pki + tls-layer still refuses at construction", () => {
		expect(() =>
			createMtlsMechanism({
				source: "tls-layer",
				mode: "pki",
				trustedCas: ["-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----"],
			}),
		).toThrow(/tls-layer/);
	});
});

const FULL_PKI_DEFAULTS_CONFIG = {
	"max-chain-depth": FULL_PKI_DEFAULTS.maxChainDepth,
	"signature-algorithms": FULL_PKI_DEFAULTS.signatureAlgorithms,
	"min-rsa-key-bits": FULL_PKI_DEFAULTS.minRsaKeyBits,
};

void TRUSTED_PEER;
