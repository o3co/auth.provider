import type { KeyStore } from "../keys/KeyStore.mjs";
import type { UserSessionClaims } from "../user-sessions/types.mjs";
import type { Token } from "./token.mjs";
export interface GenerateIdTokenOptions {
    readonly sub: string;
    readonly aud: string;
    readonly azp?: string;
    readonly authTime: Date;
    readonly nonce?: string;
    readonly sid: string;
    readonly scopes: ReadonlyArray<string>;
    readonly userClaims: UserSessionClaims;
    readonly keyStore: KeyStore;
    readonly issuer: string;
    readonly expiresIn?: number;
}
/**
 * Generates a signed id_token JWT (OIDC 1.0 Core §2).
 *
 * Claim composition:
 *   - iss = issuer
 *   - sub (required)
 *   - aud (required)
 *   - azp (optional, added when provided)
 *   - exp / iat (seconds since epoch)
 *   - auth_time (seconds since epoch, from `authTime`)
 *   - sid (session identifier for back-channel logout)
 *   - nonce (when provided by the authorize request)
 *   - scope-filtered user claims via {@link filterClaimsByScope}
 *
 * Header: `typ: "id+jwt"` (RFC 9068 is at+jwt; id_token is in the OIDC family but
 * we use typ for introspection convenience — the header is a hint, not spec-mandated).
 */
export declare function generateIdToken(opts: GenerateIdTokenOptions): Promise<Token>;
//# sourceMappingURL=idToken.d.mts.map