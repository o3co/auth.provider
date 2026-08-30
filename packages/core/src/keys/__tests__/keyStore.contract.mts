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
 * What every {@link KeyStore} owes its callers (#303).
 *
 * The port was already shaped for remote signing — its doc comments name
 * KMS/HSM adapters at `sign`, `getSigningKidFallback` and
 * `getVerificationKeys` — but nothing checked that a *new* implementation
 * satisfies it. For a surface the project treats as its differentiator (#305),
 * "typed and swappable" has to mean an implementer can prove they got it right,
 * not that they read the interface carefully.
 *
 * So this runs against every implementation in the repository: the two
 * in-config stores that already existed, and the remote-signing one #303 adds.
 * Adapters outside this repository — an AWS KMS or PKCS#11 binding — import it
 * and run it too, which is the point.
 *
 * Deliberately expressed in terms an implementation cannot fake: a token is
 * verified with the public key the store itself hands back, so an
 * implementation that signs with one key and publishes another fails here
 * rather than in production.
 */

import { decodeProtectedHeader, jwtVerify } from "jose";
import { describe, expect, it } from "vitest";
import type { Algorithm, KeyStore, ManagedKey } from "#/keys/KeyStore.mjs";
import { ExpiredKidError, UnknownKidError } from "#/keys/KeyStore.mjs";

export interface KeyStoreContractSetup {
	/** A store with `activeKid` signing and, if given, `previousKid` rotated out. */
	readonly create: () => Promise<KeyStore> | KeyStore;
	readonly algorithm: Algorithm;
	readonly activeKid: string;
	/**
	 * A kid the store still verifies but no longer signs with. Omit when the
	 * implementation under test has no rotation fixture.
	 */
	readonly previousKid?: string;
	/** A kid whose `expiresAt` has passed. Omit when not exercised. */
	readonly expiredKid?: string;
}

export function runKeyStoreContract(name: string, setup: KeyStoreContractSetup): void {
	const store = async (): Promise<KeyStore> => setup.create();

	describe(`KeyStore contract — ${name}`, () => {
		it("reports the algorithm it signs with", async () => {
			expect((await store()).algorithm).toBe(setup.algorithm);
		});

		it("signs a compact JWT that verifies with the key it publishes", async () => {
			// The claim an implementation cannot fake by inspection: sign with
			// one key and publish another and this is where it shows.
			const s = await store();
			const jwt = await s.sign({ claims: { sub: "u1", iss: "https://issuer.example" } });
			const key = await s.getVerificationKey(setup.activeKid);
			const { payload } = await jwtVerify(jwt, key as never, {
				issuer: "https://issuer.example",
			});
			expect(payload.sub).toBe("u1");
		});

		it("self-injects alg and kid into the protected header", async () => {
			// Callers pass claims and at most `typ`; getting `alg`/`kid` from the
			// caller is how a store ends up signing under a header it did not
			// choose.
			const s = await store();
			const header = decodeProtectedHeader(await s.sign({ claims: { sub: "u1" } }));
			expect(header.alg).toBe(setup.algorithm);
			expect(header.kid).toBe(setup.activeKid);
		});

		it("carries the caller's typ through, and omits it when unset", async () => {
			const s = await store();
			expect(
				decodeProtectedHeader(await s.sign({ claims: {}, header: { typ: "at+jwt" } })).typ,
			).toBe("at+jwt");
			expect(decodeProtectedHeader(await s.sign({ claims: {} })).typ).toBeUndefined();
		});

		it("answers the signing kid synchronously, without awaiting anything", () => {
			// Stated as MUST on the port: a remote adapter caches the kid rather
			// than reaching for it, because this runs on the verify path for
			// every token that arrives without a `kid` header.
			const s = setup.create();
			const resolved = s instanceof Promise ? undefined : s;
			if (resolved === undefined) return; // async factory; covered below
			const kid = resolved.getSigningKidFallback();
			expect(kid).toBe(setup.activeKid);
		});

		it("returns the signing kid as the fallback", async () => {
			expect((await store()).getSigningKidFallback()).toBe(setup.activeKid);
		});

		it("publishes the active kid among its verification keys", async () => {
			const keys: ManagedKey[] = await (await store()).getVerificationKeys();
			expect(keys.map((k) => k.kid)).toContain(setup.activeKid);
		});

		it("publishes no private material — every entry is a public key only", async () => {
			const keys = await (await store()).getVerificationKeys();
			for (const k of keys) {
				expect(k.publicKey).toBeDefined();
				expect(Object.keys(k)).toEqual(expect.arrayContaining(["kid", "publicKey"]));
				expect(Object.keys(k)).not.toContain("privateKey");
				expect(Object.keys(k)).not.toContain("secret");
			}
		});

		it("throws UnknownKidError for a kid it was never given", async () => {
			// Typed rather than generic: the central verifier `instanceof`-checks
			// this so a SIEM can tell an attacker-fabricated kid from operator
			// rotation.
			await expect((await store()).getVerificationKey("no-such-kid")).rejects.toBeInstanceOf(
				UnknownKidError,
			);
		});

		if (setup.previousKid !== undefined) {
			const previousKid = setup.previousKid;

			it("still verifies a rotated-out kid", async () => {
				// Rotation is the reason `previousKeys` exists: tokens minted
				// before the switch have to keep verifying until they expire.
				await expect((await store()).getVerificationKey(previousKid)).resolves.toBeDefined();
			});

			it("does not sign with a rotated-out kid", async () => {
				const header = decodeProtectedHeader(await (await store()).sign({ claims: {} }));
				expect(header.kid).not.toBe(previousKid);
			});

			it("publishes the rotated-out kid too, so JWKS still covers it", async () => {
				const keys = await (await store()).getVerificationKeys();
				expect(keys.map((k) => k.kid)).toContain(previousKid);
			});
		}

		if (setup.expiredKid !== undefined) {
			const expiredKid = setup.expiredKid;

			it("throws ExpiredKidError once a rotated key's expiry has passed", async () => {
				// Distinct from UnknownKidError on purpose — an expired kid is an
				// operator-rotation signal, an unknown one is an attacker signal.
				await expect((await store()).getVerificationKey(expiredKid)).rejects.toBeInstanceOf(
					ExpiredKidError,
				);
			});
		}
	});
}
