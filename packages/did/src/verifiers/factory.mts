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
import type { SignatureVerifier } from "./types.mjs";
import { JwsVerifier } from "./jws.mjs";

export type Algorithm = "ed25519_raw" | "ed25519_jws" | "es256_jws" | "es256k_jws";

const JWS_ALG_MAP = {
	ed25519_jws: "EdDSA",
	es256_jws: "ES256",
	es256k_jws: "ES256K",
} as const;

export async function createVerifier(algorithm: Algorithm): Promise<SignatureVerifier> {
	if (algorithm === "ed25519_raw") {
		try {
			const { Ed25519RawVerifier } = await import("./ed25519Raw.mjs");
			return new Ed25519RawVerifier();
		} catch {
			throw new Error(
				"ed25519_raw algorithm requires @noble/ed25519 package. " +
				"Install it with: pnpm add @noble/ed25519 — or switch to a JWS algorithm (ed25519_jws, es256_jws, es256k_jws).",
			);
		}
	}

	const jwsAlg = JWS_ALG_MAP[algorithm];
	return new JwsVerifier(jwsAlg);
}
