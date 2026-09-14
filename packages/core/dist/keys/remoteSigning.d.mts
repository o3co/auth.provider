import { type KeyStore } from "./KeyStore.mjs";
/**
 * The one thing a KMS, an HSM or a Vault-style provider has to do (#303):
 * produce a signature over bytes it is handed, using a key it never surrenders.
 *
 * This is the whole seam. Everything else a `KeyStore` owes — building the
 * protected header, base64url encoding, assembling the compact JWT, rotation
 * bookkeeping, publishing JWKS — is the same regardless of where the private
 * key lives, and is done by {@link createRemoteSigningKeyStore} so an
 * integrator does not reimplement it per vendor and get it subtly wrong.
 *
 * ## The signature format, stated because it is the trap
 *
 * `signature` MUST be in **JWS form** (RFC 7515 §3.3, RFC 7518 §3.4):
 *
 * - `RS256` — PKCS#1 v1.5, which is what every provider returns for RSASSA.
 * - `EdDSA` — the raw 64-byte Ed25519 signature.
 * - `ES256` — the **raw `R || S` concatenation, 64 bytes**, *not* the DER
 *   `SEQUENCE` that AWS KMS, PKCS#11 and OpenSSL hand back. This is the one
 *   that bites: DER is accepted by nothing that verifies JWS, and the failure
 *   is a signature mismatch at the relying party rather than an error at the
 *   signer. Use {@link derToJoseEcdsaSignature} on the way out.
 *
 * The store cannot detect the wrong form for you — a DER blob is bytes like
 * any other — so it verifies its own output once at construction
 * (`verifyOnConstruction`, default on). A misconfigured signer then fails at
 * boot rather than issuing tokens nothing can verify.
 */
export interface RemoteSigner {
    /**
     * Sign `data` with the private key named `kid` and return the signature in
     * JWS form. Called once per token issued, so a provider round-trip here is
     * on the token endpoint's hot path.
     */
    sign(kid: string, data: Uint8Array): Promise<Uint8Array>;
}
/** A key this store publishes but no longer signs with. */
export interface RemoteSigningPreviousKey {
    readonly kid: string;
    /** SPKI PEM. Public material only — that is the point of this store. */
    readonly publicKeyPem: string;
    readonly expiresAt: Date;
}
export interface RemoteSigningKeyStoreOptions {
    /** `HS256` is deliberately absent — see the module comment. */
    readonly algorithm: "RS256" | "ES256" | "EdDSA";
    readonly kid: string;
    readonly signer: RemoteSigner;
    /** SPKI PEM for `kid`. Public material only. */
    readonly publicKeyPem: string;
    readonly previousKeys?: readonly RemoteSigningPreviousKey[];
    /**
     * Verify one self-signed token at construction, so a signer returning the
     * wrong signature form fails boot instead of issuing unverifiable tokens.
     * Costs one provider call per process start. Default `true`; turn it off
     * only where a boot-time provider call is itself the problem.
     */
    readonly verifyOnConstruction?: boolean;
}
/**
 * Convert a DER-encoded ECDSA signature to the raw `R || S` form JWS requires.
 *
 * AWS KMS, PKCS#11 and OpenSSL all return DER; JWS wants the concatenation.
 * Exported because every integrator building an `ES256` {@link RemoteSigner}
 * needs it, and the alternative is each of them writing this parser from the
 * ASN.1 spec — which is how one of them gets the leading-zero trimming wrong
 * and produces signatures that verify only sometimes.
 *
 * `size` is the field size in bytes (32 for P-256), so each half is
 * left-padded to exactly that width.
 */
export declare function derToJoseEcdsaSignature(der: Uint8Array, size?: number): Uint8Array;
/**
 * A {@link KeyStore} whose private key never enters this process (#303).
 *
 * ## Why this is vendor-neutral
 *
 * The issue asks for "the port + one reference, e.g. AWS KMS". Shipping an AWS
 * SDK dependency in `core` would put a vendor in the dependency closure of
 * every deployment, including the ones signing with a PKCS#11 token or a
 * Vault transit key — the same reason the delivery port (#302) is specified as
 * "no bundled vendor". So the reference is the shape, not the vendor: an
 * integrator supplies `sign(kid, data)` and this does the rest.
 *
 * ## Why `HS256` is not accepted
 *
 * A shared secret has no public half, so "the key never leaves the boundary"
 * cannot be true of it — every verifier needs the same bytes the signer has.
 * Offering it here would let a deployment believe it had moved key material
 * out of reach when it had not. HS256 stays on `createSymmetricKeyStore`,
 * where the trade-off is visible.
 *
 * ## Rotation
 *
 * Identical to `createAsymmetricKeyStore`: `previousKeys` keep verifying (and
 * keep appearing in JWKS) until `expiresAt`, after which `getVerificationKey`
 * throws {@link ExpiredKidError} rather than {@link UnknownKidError}, so the
 * two stay distinguishable to a SIEM.
 */
export declare function createRemoteSigningKeyStore(options: RemoteSigningKeyStoreOptions): Promise<KeyStore>;
//# sourceMappingURL=remoteSigning.d.mts.map