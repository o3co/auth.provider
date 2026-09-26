import { type KeyObject } from "node:crypto";
/**
 * JWT claims per RFC 7519. Standard claims are typed; custom claims are
 * allowed via index signature. Defined here to keep the KeyStore interface
 * jose-independent — implementations may use jose, node-jose, fast-jwt, or
 * direct KMS SDK calls.
 */
export interface JWTPayload {
    iss?: string;
    sub?: string;
    aud?: string | string[];
    jti?: string;
    nbf?: number;
    exp?: number;
    iat?: number;
    [propName: string]: unknown;
}
/**
 * Input to `KeyStore.sign()`. The KeyStore self-injects `alg` and `kid` into
 * the protected header; callers may only set `typ`. This keeps adapter
 * contracts stable under alg / kid rotation and remote-sign (KMS/HSM) backends.
 */
export interface SignJwtOptions {
    claims: JWTPayload;
    header?: {
        typ?: string;
    };
}
export type KeyLike = CryptoKey | KeyObject | Uint8Array;
export interface ManagedKey {
    kid: string;
    publicKey: KeyLike;
    expiresAt?: Date;
}
export type Algorithm = "HS256" | "RS256" | "ES256" | "EdDSA";
export interface KeyStore {
    readonly algorithm: Algorithm;
    /**
     * Sign claims and return a compact JWT. The KeyStore self-injects `alg`
     * and `kid` into the protected header; callers may set only `typ`.
     * Remote-sign adapters (KMS/HSM) perform the remote call here.
     */
    sign(options: SignJwtOptions): Promise<string>;
    /**
     * Returns the current signing kid as a fallback for verifying
     * legacy/malformed tokens that lack a `kid` header. **Do not use for
     * rotation-safe lookup** — for rotation, pass the token's own `kid` to
     * `getVerificationKey(kid)`.
     *
     * **MUST be synchronous and cheap**. Remote-sign adapters (KMS/HSM)
     * must cache the current kid locally and return it without any remote
     * call. Never exposes private key material.
     */
    getSigningKidFallback(): string;
    /** Active verification keys for JWKS endpoint. Remote adapters may fetch + cache. */
    getVerificationKeys(): Promise<ManagedKey[]>;
    /** Specific kid's public key. Throws on unknown or expired kid. */
    getVerificationKey(kid: string): Promise<KeyLike>;
}
export interface AsymmetricKeyStoreOptions {
    algorithm: "RS256" | "ES256" | "EdDSA";
    kid: string;
    privateKeyPem: string;
    publicKeyPem: string;
    previousKeys?: Array<{
        kid: string;
        publicKeyPem: string;
        expiresAt: Date;
    }>;
}
export declare function createAsymmetricKeyStore(options: AsymmetricKeyStoreOptions): Promise<KeyStore>;
export declare function createSymmetricKeyStore(secret: string, kid?: string): KeyStore;
//# sourceMappingURL=KeyStore.d.mts.map