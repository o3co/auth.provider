import type { KeyStore } from "../keys/KeyStore.mjs";
export declare const formatObject: <T extends object>(data: T) => Partial<T>;
export interface Token {
    token: string;
    expiresIn?: number;
    subject?: string;
    scope?: string;
    tokenType?: "at+jwt" | "rt+jwt";
    audience?: string;
    issuer?: string;
}
export interface IntermediateToken {
    accessToken: Token;
    refreshToken?: Token;
    idToken?: Token;
}
export interface TokenResponse {
    access_token: string;
    token_type: string;
    scope?: string;
    refresh_token?: string | null;
    expires_in?: number;
    id_token?: string;
}
export declare const generateTokenResponse: ({ accessToken, refreshToken, idToken, }: IntermediateToken) => TokenResponse;
export interface GenerateTokenOptions {
    expiresIn?: number;
    keyStore: KeyStore;
    issuer?: string | null;
    audience?: string | null;
    subject?: string | null;
    authorizedParty?: string | null;
    scope?: string | null;
    tokenType?: "at+jwt" | "rt+jwt";
}
export declare const generateToken: (data: object, { expiresIn, keyStore, issuer, audience, subject, authorizedParty, scope, tokenType, }: GenerateTokenOptions) => Promise<Token>;
//# sourceMappingURL=token.d.mts.map