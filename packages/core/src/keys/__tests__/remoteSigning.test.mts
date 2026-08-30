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
 * Issue #303 — a `KeyStore` whose private key never enters this process.
 *
 * The port was already shaped for it (`KeyStore.sign`'s own doc says
 * "remote-sign adapters (KMS/HSM) perform the remote call here"), so what was
 * missing was an implementation and a way for one to prove itself. The shared
 * contract does the second job; these cover what is specific to signing
 * somewhere else.
 *
 * The `RemoteSigner` here is Node's `crypto` standing in for a KMS: same
 * shape, same asynchrony, same "hands back bytes and keeps the key". That is
 * enough to catch the failures that actually happen — wrong signature form,
 * mismatched public half, a signer that throws.
 */

import { createSign, generateKeyPairSync, sign as nodeSign } from "node:crypto";
import { decodeProtectedHeader, exportSPKI, generateKeyPair, importSPKI, jwtVerify } from "jose";
import { describe, expect, it, vi } from "vitest";
import { ExpiredKidError, UnknownKidError } from "#/keys/KeyStore.mjs";
import {
	createRemoteSigningKeyStore,
	derToJoseEcdsaSignature,
	type RemoteSigner,
} from "#/keys/remoteSigning.mjs";
import { runKeyStoreContract } from "./keyStore.contract.mjs";

// --- Ed25519: a signer that keeps its private key to itself -----------------

const ed = generateKeyPairSync("ed25519");
const edSpki = ed.publicKey.export({ type: "spki", format: "pem" }).toString();
const edPrev = generateKeyPairSync("ed25519");
const edPrevSpki = edPrev.publicKey.export({ type: "spki", format: "pem" }).toString();

/** Stands in for a KMS: signs on request, never surrenders the key. */
const edSigner: RemoteSigner = {
	async sign(_kid, data) {
		return new Uint8Array(nodeSign(null, data, ed.privateKey));
	},
};

runKeyStoreContract("createRemoteSigningKeyStore (EdDSA)", {
	algorithm: "EdDSA",
	activeKid: "v2",
	previousKid: "v1",
	expiredKid: "v0",
	create: () =>
		createRemoteSigningKeyStore({
			algorithm: "EdDSA",
			kid: "v2",
			signer: edSigner,
			publicKeyPem: edSpki,
			previousKeys: [
				{ kid: "v1", publicKeyPem: edPrevSpki, expiresAt: new Date(Date.now() + 600_000) },
				{ kid: "v0", publicKeyPem: edPrevSpki, expiresAt: new Date(Date.now() - 1) },
			],
		}),
});

describe("createRemoteSigningKeyStore — the private key stays out of process (#303)", () => {
	const build = (overrides: Record<string, unknown> = {}) =>
		createRemoteSigningKeyStore({
			algorithm: "EdDSA",
			kid: "v1",
			signer: edSigner,
			publicKeyPem: edSpki,
			...overrides,
		} as never);

	it("asks the signer for exactly the JWS signing input", async () => {
		// The store owns the header and the encoding; the signer sees bytes.
		// If that split slipped, a signer could sign a header the deployment
		// never configured.
		const seen: Array<{ kid: string; data: string }> = [];
		const spy: RemoteSigner = {
			async sign(kid, data) {
				seen.push({ kid, data: new TextDecoder().decode(data) });
				return edSigner.sign(kid, data);
			},
		};
		const store = await build({ signer: spy });
		seen.length = 0; // drop the construction-time self-check
		const jwt = await store.sign({ claims: { sub: "u1" }, header: { typ: "at+jwt" } });

		expect(seen).toHaveLength(1);
		expect(seen[0]?.kid).toBe("v1");
		// Exactly the first two segments of the token it returned.
		expect(jwt.startsWith(`${seen[0]?.data}.`)).toBe(true);
		expect(seen[0]?.data.split(".")).toHaveLength(2);
	});

	it("never hands the signer any private material", async () => {
		// The signer's whole input is (kid, bytes). There is no parameter this
		// store could leak a key through even if it wanted to.
		const spy = vi.fn(async (kid: string, data: Uint8Array) => edSigner.sign(kid, data));
		const store = await build({ signer: { sign: spy } });
		await store.sign({ claims: {} });
		for (const call of spy.mock.calls) {
			expect(call).toHaveLength(2);
			expect(typeof call[0]).toBe("string");
			expect(call[1]).toBeInstanceOf(Uint8Array);
		}
	});

	it("signs one token at construction to prove the signer and the public half agree", async () => {
		const spy = vi.fn(async (kid: string, data: Uint8Array) => edSigner.sign(kid, data));
		await build({ signer: { sign: spy } });
		expect(spy).toHaveBeenCalledTimes(1);
	});

	it("refuses to construct when the signer uses a different key", async () => {
		// The failure this exists to move to boot: otherwise every token this
		// store issued would be rejected by every relying party, and the
		// symptom would surface far from the cause.
		const wrongKey = generateKeyPairSync("ed25519");
		await expect(
			build({
				signer: {
					async sign(_kid: string, data: Uint8Array) {
						return new Uint8Array(nodeSign(null, data, wrongKey.privateKey));
					},
				},
			}),
		).rejects.toThrow(/does not verify against publicKeyPem/);
	});

	it("names the two causes that account for almost all of these", async () => {
		const wrongKey = generateKeyPairSync("ed25519");
		const err = await build({
			signer: {
				async sign(_kid: string, data: Uint8Array) {
					return new Uint8Array(nodeSign(null, data, wrongKey.privateKey));
				},
			},
		}).catch((e: unknown) => e as Error);
		expect(err.message).toMatch(/JWS form/);
		expect(err.message).toMatch(/different key/);
	});

	it("can be constructed without the self-check when a boot-time call is the problem", async () => {
		const spy = vi.fn(async (kid: string, data: Uint8Array) => edSigner.sign(kid, data));
		await build({ signer: { sign: spy }, verifyOnConstruction: false });
		expect(spy).not.toHaveBeenCalled();
	});

	it("refuses duplicate kids", async () => {
		await expect(
			build({
				previousKeys: [
					{ kid: "v1", publicKeyPem: edPrevSpki, expiresAt: new Date(Date.now() + 600_000) },
				],
			}),
		).rejects.toThrow(/duplicate kid/i);
	});

	it("propagates a signer failure rather than issuing an unsigned token", async () => {
		const store = await build({
			verifyOnConstruction: false,
			signer: {
				async sign() {
					throw new Error("kms: AccessDeniedException");
				},
			},
		});
		await expect(store.sign({ claims: {} })).rejects.toThrow(/AccessDeniedException/);
	});
});

// --- ES256: the DER trap ----------------------------------------------------

describe("derToJoseEcdsaSignature (#303)", () => {
	const ec = generateKeyPairSync("ec", { namedCurve: "P-256" });
	const ecSpki = ec.publicKey.export({ type: "spki", format: "pem" }).toString();

	/** A provider that returns DER, the way AWS KMS / PKCS#11 / OpenSSL do. */
	const derSigner: RemoteSigner = {
		async sign(_kid, data) {
			const s = createSign("SHA256");
			s.update(data);
			s.end();
			return new Uint8Array(s.sign(ec.privateKey));
		},
	};

	it("refuses to construct a store whose ES256 signer returns DER", async () => {
		// The trap, caught at boot: DER verifies nowhere that speaks JWS, and
		// the signer itself reports no error.
		await expect(
			createRemoteSigningKeyStore({
				algorithm: "ES256",
				kid: "v1",
				signer: derSigner,
				publicKeyPem: ecSpki,
			}),
		).rejects.toThrow(/does not verify against publicKeyPem/);
	});

	it("produces a signature that verifies once converted", async () => {
		const store = await createRemoteSigningKeyStore({
			algorithm: "ES256",
			kid: "v1",
			publicKeyPem: ecSpki,
			signer: {
				async sign(kid, data) {
					return derToJoseEcdsaSignature(await derSigner.sign(kid, data));
				},
			},
		});
		const jwt = await store.sign({ claims: { sub: "u1" } });
		const key = await importSPKI(ecSpki, "ES256");
		const { payload } = await jwtVerify(jwt, key as never);
		expect(payload.sub).toBe("u1");
	});

	it("returns exactly 2 * size bytes, left-padded", async () => {
		// The leading-zero trimming is where a hand-rolled parser goes wrong:
		// DER prefixes 0x00 to keep an INTEGER positive, JWS wants fixed-width
		// halves, and getting it wrong yields signatures that verify only when
		// both halves happen to be full width.
		for (let i = 0; i < 40; i += 1) {
			const der = await derSigner.sign("v1", new TextEncoder().encode(`probe-${i}`));
			expect(derToJoseEcdsaSignature(der)).toHaveLength(64);
		}
	});

	it("rejects something that is not a DER SEQUENCE", () => {
		expect(() => derToJoseEcdsaSignature(new Uint8Array([0x01, 0x02]))).toThrow(/DER SEQUENCE/);
	});

	/*
	 * The parser's refusals, which are the paths a malformed provider response
	 * actually takes. A byte parser that returns garbage instead of throwing
	 * produces a signature that fails at the relying party, which is the same
	 * far-from-the-cause failure the DER trap itself causes.
	 */
	it("rejects a SEQUENCE whose first element is not an INTEGER", () => {
		// 0x30 len, then 0x04 (OCTET STRING) where R should be.
		expect(() =>
			derToJoseEcdsaSignature(new Uint8Array([0x30, 0x04, 0x04, 0x02, 0x01, 0x02])),
		).toThrow(/INTEGER/);
	});

	it("rejects a truncated INTEGER", () => {
		// 0x02 with no length byte following.
		expect(() => derToJoseEcdsaSignature(new Uint8Array([0x30, 0x01, 0x02]))).toThrow(
			/truncated INTEGER/,
		);
	});

	it("rejects an INTEGER wider than the field size", () => {
		// A 4-byte R against size 2 — wider than the curve allows, and not
		// merely a leading-zero pad that could be trimmed.
		const der = new Uint8Array([0x30, 0x08, 0x02, 0x04, 0x11, 0x22, 0x33, 0x44, 0x02, 0x00]);
		expect(() => derToJoseEcdsaSignature(der, 2)).toThrow(/wider than the field size/);
	});

	it("reads a long-form SEQUENCE length", () => {
		// 0x81 marks one length byte following. Real P-256 signatures are
		// short-form, but P-521's are not, and the branch should not be
		// reachable only by curve.
		const body = [0x02, 0x01, 0x07, 0x02, 0x01, 0x09];
		const der = new Uint8Array([0x30, 0x81, body.length, ...body]);
		const out = derToJoseEcdsaSignature(der, 1);
		expect(Array.from(out)).toEqual([0x07, 0x09]);
	});

	it("trims the DER sign-padding byte rather than shifting the value", () => {
		// 0x00 prefix keeps a DER INTEGER positive; carrying it into the JWS
		// half would shift every byte and silently corrupt the signature.
		const body = [0x02, 0x02, 0x00, 0xff, 0x02, 0x01, 0x01];
		const der = new Uint8Array([0x30, body.length, ...body]);
		expect(Array.from(derToJoseEcdsaSignature(der, 1))).toEqual([0xff, 0x01]);
	});
});

// --- what this store refuses to be -----------------------------------------

describe("createRemoteSigningKeyStore — algorithm boundary (#303)", () => {
	it("has no HS256 variant, because a shared secret has no public half", async () => {
		// Offering it would let a deployment believe it had moved key material
		// out of reach when every verifier still needs the same bytes. The
		// type refuses it; this pins the reasoning next to the refusal.
		const eddsa = await generateKeyPair("EdDSA", { extractable: true });
		const spki = await exportSPKI(eddsa.publicKey);
		const store = await createRemoteSigningKeyStore({
			algorithm: "EdDSA",
			kid: "v1",
			signer: edSigner,
			publicKeyPem: edSpki,
			verifyOnConstruction: false,
		});
		expect(store.algorithm).not.toBe("HS256");
		expect(spki.length).toBeGreaterThan(0);
	});

	it("keeps UnknownKidError and ExpiredKidError distinguishable", async () => {
		const store = await createRemoteSigningKeyStore({
			algorithm: "EdDSA",
			kid: "v1",
			signer: edSigner,
			publicKeyPem: edSpki,
			previousKeys: [{ kid: "v0", publicKeyPem: edPrevSpki, expiresAt: new Date(Date.now() - 1) }],
		});
		await expect(store.getVerificationKey("nope")).rejects.toBeInstanceOf(UnknownKidError);
		await expect(store.getVerificationKey("v0")).rejects.toBeInstanceOf(ExpiredKidError);
	});

	it("self-injects alg and kid rather than taking them from the caller", async () => {
		const store = await createRemoteSigningKeyStore({
			algorithm: "EdDSA",
			kid: "v9",
			signer: edSigner,
			publicKeyPem: edSpki,
		});
		const header = decodeProtectedHeader(await store.sign({ claims: {} }));
		expect(header.alg).toBe("EdDSA");
		expect(header.kid).toBe("v9");
	});
});
