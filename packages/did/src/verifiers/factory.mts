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
import type { PathResolver } from "@o3co/auth-provider-core";

import { JwsVerifier } from "./jws.mjs";
import { type VerifierFactory, VerifierRegistry } from "./registry.mjs";
import type { SignatureVerifier } from "./types.mjs";

// Algorithm is now an open string type — any registered algorithm name is valid
export type Algorithm = string;

const JWS_ALG_MAP = {
	ed25519_jws: "EdDSA",
	es256_jws: "ES256",
	es256k_jws: "ES256K",
} as const;

export function createDefaultVerifierRegistry(): VerifierRegistry {
	const registry = new VerifierRegistry();

	registry.register("ed25519_raw", async (pathResolver?: PathResolver) => {
		try {
			const { Ed25519RawVerifier } = await import("./ed25519Raw.mjs");
			return new Ed25519RawVerifier(pathResolver);
		} catch (err) {
			const code =
				typeof err === "object" && err !== null && "code" in err
					? (err as { code: unknown }).code
					: undefined;
			const message = err instanceof Error ? err.message : String(err);
			if (
				(code === "ERR_MODULE_NOT_FOUND" || code === "MODULE_NOT_FOUND") &&
				message.includes("@noble/ed25519")
			) {
				throw new Error(
					"ed25519_raw algorithm requires @noble/ed25519 package. " +
						"Install it with: pnpm add @noble/ed25519 — or switch to a JWS algorithm (ed25519_jws, es256_jws, es256k_jws).",
				);
			}
			throw err;
		}
	});

	registry.register("ed25519_prehash", async (pathResolver?: PathResolver) => {
		try {
			const { Ed25519PrehashVerifier } = await import("./ed25519Prehash.mjs");
			return new Ed25519PrehashVerifier(pathResolver);
		} catch (err) {
			const code =
				typeof err === "object" && err !== null && "code" in err
					? (err as { code: unknown }).code
					: undefined;
			const message = err instanceof Error ? err.message : String(err);
			if (
				(code === "ERR_MODULE_NOT_FOUND" || code === "MODULE_NOT_FOUND") &&
				message.includes("@noble/ed25519")
			) {
				throw new Error(
					"ed25519_prehash algorithm requires @noble/ed25519 package. " +
						"Install it with: pnpm add @noble/ed25519 — or switch to a JWS algorithm (ed25519_jws, es256_jws, es256k_jws).",
				);
			}
			throw err;
		}
	});

	registry.register("ed25519_jws", async () => new JwsVerifier(JWS_ALG_MAP.ed25519_jws));
	registry.register("es256_jws", async () => new JwsVerifier(JWS_ALG_MAP.es256_jws));
	registry.register("es256k_jws", async () => new JwsVerifier(JWS_ALG_MAP.es256k_jws));

	return registry;
}

export async function createVerifier(
	algorithm: Algorithm,
	pathResolver?: PathResolver,
): Promise<SignatureVerifier> {
	const registry = createDefaultVerifierRegistry();
	const factory = registry.get(algorithm);
	if (!factory) {
		throw new Error(
			`Unsupported algorithm: "${algorithm}". Supported: ${registry.algorithms().join(", ")}`,
		);
	}
	return factory(pathResolver);
}

export type { VerifierFactory };
