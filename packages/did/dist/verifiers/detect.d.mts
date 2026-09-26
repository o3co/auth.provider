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
export declare function detectAlgorithm(body: Record<string, unknown>): string | null;
//# sourceMappingURL=detect.d.mts.map