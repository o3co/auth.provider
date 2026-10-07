import * as pkijs from "pkijs";
export interface BuiltRequest {
    readonly der: Uint8Array;
    readonly certId: pkijs.CertID;
    /** The nonce extension's `extnValue` — the bytes the responder must echo. */
    readonly nonce: Uint8Array;
}
export declare const buildRequest: (certificate: pkijs.Certificate, issuer: pkijs.Certificate, crypto: pkijs.ICryptoEngine) => Promise<BuiltRequest>;
/**
 * Whether `basic` echoes `nonce`, the one the request sent. A response carrying none passes
 * only when `requireNonce` is false.
 */
export declare const checkNonce: (basic: pkijs.BasicOCSPResponse, nonce: Uint8Array, requireNonce: boolean) => {
    readonly ok: true;
} | {
    readonly ok: false;
    readonly reason: "nonce_missing" | "nonce_mismatch";
    readonly detail: string;
};
//# sourceMappingURL=ocspRequest.d.mts.map