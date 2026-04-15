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
import { decodeProtectedHeader } from "jose";

/**
 * Detect which DID signature algorithm was used based on the request body.
 *
 * Detection order:
 * 1. `body.algorithm` is a non-empty string → return it directly (explicit override,
 *    enables custom algorithms registered via `verifierRegistry`)
 * 2. `body.signature` + `body.message` + `body.prehash === "sha256"` → `"ed25519_prehash"`
 * 3. `body.signature` + `body.message` (no prehash) → `"ed25519_raw"`
 * 4. `body.jws` present → inspect the JWS protected header's `alg` field:
 *    - EdDSA  → `"ed25519_jws"`
 *    - ES256  → `"es256_jws"`
 *    - ES256K → `"es256k_jws"`
 * 5. otherwise → `null`
 *
 * Returns `null` if detection fails (e.g. invalid JWS, unknown alg).
 */
export function detectAlgorithm(body: Record<string, unknown>): string | null {
	// Explicit algorithm field takes precedence over shape-based detection
	if (typeof body.algorithm === "string" && body.algorithm) return body.algorithm;

	if (body.signature && body.message) {
		if (body.prehash === "sha256") return "ed25519_prehash";
		return "ed25519_raw";
	}

	if (body.jws) {
		try {
			const header = decodeProtectedHeader(body.jws as string);
			switch (header.alg) {
				case "EdDSA":
					return "ed25519_jws";
				case "ES256":
					return "es256_jws";
				case "ES256K":
					return "es256k_jws";
				default:
					return null;
			}
		} catch {
			return null;
		}
	}

	return null;
}
