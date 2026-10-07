import * as pkijs from "pkijs";
import { type AlgorithmPolicy } from "./algorithms.mjs";
/** Why a signer was refused: a signature that is not the CA's, or material outside the policy. */
type SignerRefusal = {
    readonly ok: false;
    readonly reason: "bad_signature" | "algorithm_not_permitted";
    readonly detail: string;
};
/** The certificate whose key must have signed `basic`: the CA, or a responder it delegated to. */
export declare const identifySigner: (basic: pkijs.BasicOCSPResponse, issuer: pkijs.Certificate, now: Date, crypto: pkijs.ICryptoEngine, algorithms: AlgorithmPolicy) => Promise<{
    ok: true;
    signer: pkijs.Certificate;
    delegate?: pkijs.Certificate;
} | SignerRefusal>;
export declare const verifySignature: (basic: pkijs.BasicOCSPResponse, signer: pkijs.Certificate, crypto: pkijs.ICryptoEngine) => Promise<{
    ok: true;
} | {
    ok: false;
    detail: string;
    cause?: unknown;
}>;
export {};
//# sourceMappingURL=ocspSigner.d.mts.map