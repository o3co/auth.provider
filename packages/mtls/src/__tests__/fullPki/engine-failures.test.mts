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
 * What `full-pki` says when pkijs's path-validation engine refuses a chain,
 * against the real engine.
 *
 * The refusal's `detail` is this package's own words for what the engine
 * found, chosen by the engine's result code — never the engine's message.
 * When the engine caught an Error on the way (a plain `Error` from its path
 * builder, its own `ChainValidationError`), that error is the refusal's
 * `cause`. Whether a path reached no trust anchor is read from the code and
 * from the issuer lookup coming back empty, never from the message.
 */

import type { X509Certificate } from "node:crypto";
import { describe, expect, it } from "vitest";
import { DEFAULT_SIGNATURE_ALGORITHMS } from "#/fullPki/algorithms.mjs";
import { createFullPkiValidator, type FullPkiResult } from "#/fullPki/validate.mjs";
import type { Minted } from "./pkiFactory.mjs";
import {
	basicConstraints,
	clientAuthEku,
	dnsSan,
	KEY_USAGE,
	keyUsage,
	mint,
	mintCa,
	mintIntermediate,
	mintLeaf,
	nameConstraints,
} from "./pkiFactory.mjs";

const NOW = new Date("2027-01-01T00:00:00Z");

const validate = (
	anchors: readonly Minted[],
	leaf: Minted,
	chain: readonly Minted[],
): Promise<FullPkiResult> =>
	createFullPkiValidator({
		trustedCas: anchors.map((ca) => ca.x509),
		algorithms: { signatureAlgorithms: DEFAULT_SIGNATURE_ALGORITHMS, minRsaKeyBits: 2048 },
		maxChainDepth: 6,
		revocation: { mode: "disabled" },
	}).validate(
		leaf.x509,
		chain.map((certificate): X509Certificate => certificate.x509),
		NOW,
	);

/** Neither of the engine's own phrasings for a missing path reaches `detail`. */
const ENGINE_WORDS = /certificate paths? found|Unable to find certificate path/;

describe("the path-validation engine's refusal", () => {
	it("a chain whose issuer nothing trusted matches: no path, the builder's Error as the cause", async () => {
		const root = await mintCa("Root", 1);
		const rogue = await mintCa("Rogue Root", 100);
		const int = await mintIntermediate("Intermediate", 2, rogue);
		const leaf = await mintLeaf("client", 10, int);

		const result = await validate([root], leaf, [int]);

		expect(result).toEqual({
			ok: false,
			step: "no path to trust anchor",
			detail: "no certificate path reaches a configured trust anchor",
			cause: expect.any(Error),
		});
		if (!result.ok) expect(result.detail).not.toMatch(ENGINE_WORDS);
	});

	it("a chain that ends in a root nobody configured: no path, pkijs's ChainValidationError as the cause", async () => {
		const root = await mintCa("Root", 1);
		const rogue = await mintCa("Rogue Root", 100);
		const leaf = await mintLeaf("client", 10, rogue);

		const result = await validate([root], leaf, [rogue]);

		expect(result).toEqual({
			ok: false,
			step: "no path to trust anchor",
			detail: "no certificate path reaches a configured trust anchor",
			cause: expect.objectContaining({ name: "ChainValidationError" }),
		});
	});

	it("an intermediate that is not a CA: pkijs's code 14, in the package's words", async () => {
		// pkijs checks basicConstraints / keyUsage on each certificate above
		// the leaf and answers any failure there as code 14; the finer codes
		// its check computes (3–7) never reach the result.
		const root = await mintCa("Root", 1);
		const int = await mintIntermediate("Intermediate", 2, root, {
			extensions: [basicConstraints(false), keyUsage(KEY_USAGE.keyCertSign | KEY_USAGE.cRLSign)],
		});
		const leaf = await mintLeaf("client", 10, int);

		const result = await validate([root], leaf, [int]);

		expect(result).toEqual({
			ok: false,
			step: "path validation failed",
			detail: "a certificate on the path above the leaf is not a CA certificate",
		});
	});

	it("a name inside an excluded subtree: the package's words, and no cause (the engine threw no Error)", async () => {
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

		const result = await validate([root], leaf, [int]);

		expect(result).toEqual({
			ok: false,
			step: "path validation failed",
			detail: "a name on the path is inside an excluded subtree of a name constraint",
		});
	});
});
