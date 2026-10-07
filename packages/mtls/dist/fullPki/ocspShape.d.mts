/**
 * What a response is shaped like, judged before its signature as in `crl.mts`: a single response
 * matching the certificate's `CertID`, no unprocessed critical extension, and a signature
 * algorithm the path's policy allows (pkijs accepts SHA-1). Each can only refuse, so a refusal
 * is remembered per certificate.
 */
import * as pkijs from "pkijs";
import { type AlgorithmPolicy } from "./algorithms.mjs";
/** What a shape check found: the single response about the certificate, or why none can be used. */
export type ShapeCheck = {
    readonly ok: true;
    readonly single: pkijs.SingleResponse;
} | {
    readonly ok: false;
    readonly reason: "no_matching_response" | "unsupported_critical_extension" | "algorithm_not_permitted";
    readonly detail: string;
};
/**
 * The response's shape, in order: the single response matching `requested`, then critical
 * extensions, then the response's signature algorithm.
 */
export declare const checkResponseShape: (basic: pkijs.BasicOCSPResponse, certificate: pkijs.Certificate, issuer: pkijs.Certificate, requested: pkijs.CertID, crypto: pkijs.ICryptoEngine, algorithms: AlgorithmPolicy) => Promise<ShapeCheck>;
//# sourceMappingURL=ocspShape.d.mts.map