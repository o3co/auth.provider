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
 * The contract suite of the `csrfTokenSigner` slot (#728) and its test
 * double.
 *
 * `csrfTokenSignerContract(input)` holds a signer to what the `csrfGuard`
 * provider relies on: `sign` answers a non-empty base64url signature (it sits
 * between a token's `.` separators), the same one for the same payload;
 * `verify` accepts it, and refuses a signature changed in its middle or at
 * its end, shortened or lengthened, one signed for another payload, and one
 * another signer — `input.other`, built with another key — signed, the two
 * signers answering differently; `verify` never throws, an empty,
 * non-base64url or wrong-length signature, or a value that is not a string,
 * being `false`; the signer carries `sign` and `verify` alone — no key, no
 * secret — and is frozen. Given `sessionSecret`, the secret the signer was
 * built from, the suite also checks that the key was derived for this
 * purpose: a signature is not an HMAC-SHA256 of the payload under the secret
 * itself, in any encoding a cookie signature is written in, and the secret
 * does not show when the signer is printed.
 *
 * That `verify` compares in constant time is the contract too, and is not
 * checked: a timing difference is not something a unit suite can measure
 * reliably.
 *
 * `createTestCsrfTokenSigner` keeps these rules with a random key drawn when
 * it is built. Published on `@o3co/auth-provider-core/testing`.
 */

import assert from "node:assert/strict";
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { inspect } from "node:util";
import type { CsrfTokenSigner } from "../../browser-session/types.mjs";
import type { ContractCase } from "../../session-admission/testing/requirement.contract.mjs";
import { unfrozenPath } from "./shared.mjs";

export interface CsrfTokenSignerContractInput {
	/** The signer under test, built afresh for each case. */
	readonly build: () => CsrfTokenSigner;
	/** A signer of the same kind built with another key (another session secret): its signatures must not pass. */
	readonly other: () => CsrfTokenSigner;
	/**
	 * The session secret `build` derives its key from, when the provider takes
	 * one: the signature must not be an HMAC of the payload under the secret
	 * itself, and the secret must not show when the signer is printed. Absent,
	 * the separation is not checked.
	 */
	readonly sessionSecret?: string;
}

/** A signature's alphabet: base64url, no padding. */
const BASE64URL = /^[A-Za-z0-9_-]+$/;

/** Payloads of the shapes a token signs, and the edges: empty, and beyond ASCII. */
const PAYLOADS: readonly string[] = [
	"1767225600.dG9rZW4tbm9uY2UtY29udHJhY3Q",
	"",
	"payload with spaces · and ünïcödé ✓",
];

/** `signature` with the character at `index` replaced by another base64url character. */
const changedAt = (signature: string, index: number): string => {
	const current = signature[index];
	const replacement = current === "A" ? "B" : "A";
	return `${signature.slice(0, index)}${replacement}${signature.slice(index + 1)}`;
};

/** What `verify` answered, and whether it threw. */
const verdict = (signer: CsrfTokenSigner, payload: unknown, signature: unknown) => {
	try {
		return { threw: false as const, value: signer.verify(payload as string, signature as string) };
	} catch (thrown) {
		return { threw: true as const, thrown };
	}
};

/** The cases of the `csrfTokenSigner` contract over the signers `input` builds. */
export function csrfTokenSignerContract(
	input: CsrfTokenSignerContractInput,
): readonly ContractCase[] {
	const { build, other, sessionSecret } = input;
	const cases: ContractCase[] = [
		{
			name: "sign answers a non-empty base64url signature, the same one for the same payload",
			run: async () => {
				const signer = build();
				for (const payload of PAYLOADS) {
					const signature = signer.sign(payload);
					assert.ok(
						typeof signature === "string" && BASE64URL.test(signature),
						`sign(${JSON.stringify(payload)}) answered ${JSON.stringify(signature)}, not a non-empty base64url signature`,
					);
					assert.equal(
						signer.sign(payload),
						signature,
						`sign(${JSON.stringify(payload)}) answered differently the second time`,
					);
				}
			},
		},
		{
			name: "verify accepts the signature sign answered for the payload",
			run: async () => {
				const signer = build();
				for (const payload of PAYLOADS) {
					assert.equal(
						signer.verify(payload, signer.sign(payload)),
						true,
						`verify refused sign's own signature for ${JSON.stringify(payload)}`,
					);
				}
			},
		},
		{
			name: "verify refuses a changed, shortened or lengthened signature",
			run: async () => {
				const signer = build();
				const payload = PAYLOADS[0] as string;
				const signature = signer.sign(payload);
				const variants: readonly [string, string][] = [
					["changed in its middle", changedAt(signature, Math.floor(signature.length / 2))],
					["changed at its end", changedAt(signature, signature.length - 1)],
					["changed at its start", changedAt(signature, 0)],
					["shortened", signature.slice(0, -1)],
					["lengthened", `${signature}A`],
				];
				for (const [what, variant] of variants) {
					assert.equal(
						signer.verify(payload, variant),
						false,
						`verify accepted a signature ${what}`,
					);
				}
			},
		},
		{
			name: "verify refuses a signature for another payload",
			run: async () => {
				const signer = build();
				const payload = PAYLOADS[0] as string;
				const signature = signer.sign(payload);
				for (const another of [`${payload}x`, payload.slice(0, -1), "", `x${payload}`]) {
					assert.equal(
						signer.verify(another, signature),
						false,
						`verify accepted the signature of ${JSON.stringify(payload)} for ${JSON.stringify(another)}`,
					);
				}
			},
		},
		{
			name: "verify refuses another signer's signature, and the two sign differently",
			run: async () => {
				const signer = build();
				const another = other();
				for (const payload of PAYLOADS) {
					const ours = signer.sign(payload);
					const theirs = another.sign(payload);
					assert.notEqual(
						ours,
						theirs,
						"two signers built with different keys signed a payload alike: the key does not depend on what the signer was built from",
					);
					assert.equal(
						signer.verify(payload, theirs),
						false,
						"verify accepted another signer's signature",
					);
					assert.equal(
						another.verify(payload, ours),
						false,
						"another signer accepted this one's signature",
					);
				}
			},
		},
		{
			name: "verify never throws: an empty, non-base64url or wrong-length signature, or a value that is not a string, is refused",
			run: async () => {
				const signer = build();
				const payload = PAYLOADS[0] as string;
				const signature = signer.sign(payload);
				const malformed: readonly [string, unknown, unknown][] = [
					["an empty signature", payload, ""],
					["a signature with characters outside base64url", payload, "!!!!"],
					["a signature with a dot", payload, `${signature.slice(0, 4)}.${signature.slice(5)}`],
					["a padded signature", payload, `${signature}=`],
					[
						"a signature of a tenth the length",
						payload,
						signature.slice(0, Math.ceil(signature.length / 10)),
					],
					["a signature a thousand characters long", payload, "A".repeat(1000)],
					["a signature that is undefined", payload, undefined],
					["a signature that is null", payload, null],
					["a signature that is a number", payload, 42],
					["a signature that is an object", payload, { toString: () => signature }],
					["a payload that is undefined", undefined, signature],
					["a payload that is a number", 42, signature],
				];
				for (const [what, p, s] of malformed) {
					const result = verdict(signer, p, s);
					assert.equal(result.threw, false, `verify threw on ${what}`);
					assert.equal(result.threw ? undefined : result.value, false, `verify accepted ${what}`);
				}
			},
		},
		{
			name: "the signer carries sign and verify alone: no key and no secret",
			run: async () => {
				const signer = build();
				assert.equal(typeof signer.sign, "function", "sign is not a function");
				assert.equal(typeof signer.verify, "function", "verify is not a function");
				for (const key of Reflect.ownKeys(signer)) {
					assert.ok(
						key === "sign" || key === "verify",
						`the signer carries ${String(key)} beside sign and verify: a key or a secret has no business on it`,
					);
				}
				if (sessionSecret !== undefined) {
					assert.ok(
						!inspect(signer, { showHidden: true, depth: 10 }).includes(sessionSecret),
						"the session secret shows when the signer is printed",
					);
				}
			},
		},
		{
			name: "the signer is frozen",
			run: async () => {
				const found = unfrozenPath(build(), "the signer");
				assert.equal(
					found,
					undefined,
					`${found} is not frozen: a module that reads the signer could replace what the guard signs with`,
				);
			},
		},
	];
	if (sessionSecret !== undefined) {
		cases.push({
			name: "the signature is not the session cookie's: not an HMAC of the payload under the session secret itself",
			run: async () => {
				const signer = build();
				for (const payload of PAYLOADS) {
					const signature = signer.sign(payload);
					const digest: Buffer = createHmac("sha256", sessionSecret)
						.update(payload, "utf8")
						.digest();
					const cookieLike: readonly string[] = [
						digest.toString("base64url"),
						digest.toString("base64"),
						digest.toString("base64").replace(/=+$/, ""),
						digest.toString("hex"),
					];
					assert.ok(
						!cookieLike.includes(signature),
						"the signature is an HMAC of the payload under the session secret itself: the key was not derived for this purpose",
					);
					for (const forged of cookieLike) {
						assert.equal(
							signer.verify(payload, forged),
							false,
							"verify accepted an HMAC of the payload under the session secret itself",
						);
					}
				}
			},
		});
	}
	return cases;
}

/** A fixed-length digest of `value`, so two values of any lengths compare in constant time. */
const digestOf = (value: string): Buffer => createHash("sha256").update(value, "utf8").digest();

/**
 * A signer over a random 32-byte key drawn when it is built: HMAC-SHA256 of
 * the payload, base64url; `verify` compares fixed-length digests of the two
 * signatures with `timingSafeEqual` and answers `false` for anything that is
 * not a string. Frozen. Two doubles sign alike never.
 */
export function createTestCsrfTokenSigner(): CsrfTokenSigner {
	const key = randomBytes(32);
	const sign = (payload: string): string =>
		createHmac("sha256", key).update(payload, "utf8").digest("base64url");
	return Object.freeze({
		sign,
		verify: (payload: string, signature: string): boolean => {
			if (typeof payload !== "string" || typeof signature !== "string") return false;
			try {
				return timingSafeEqual(digestOf(sign(payload)), digestOf(signature));
			} catch {
				return false;
			}
		},
	});
}
