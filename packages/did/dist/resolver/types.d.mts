export interface JsonWebKey {
    kty?: string;
    crv?: string;
    x?: string;
    y?: string;
}
export interface VerificationMethod {
    id: string;
    type: string;
    controller: string;
    publicKeyJwk?: JsonWebKey;
    publicKeyMultibase?: string;
}
export interface DidDocument {
    id: string;
    verificationMethod?: VerificationMethod[];
}
export interface DidDocumentResolver {
    resolve(did: string): Promise<DidDocument>;
}
//# sourceMappingURL=types.d.mts.map