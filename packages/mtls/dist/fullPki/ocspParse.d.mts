/**
 * Decoding a responder's answer: a DER `OCSPResponse` whose status is `successful` and whose
 * bytes are an `id-pkix-ocsp-basic` response. Anything else is `unparseable` or
 * `responder_error`; nothing the response says is trusted yet.
 */
import * as pkijs from "pkijs";
export type Parsed = {
    readonly ok: true;
    readonly basic: pkijs.BasicOCSPResponse;
} | {
    readonly ok: false;
    readonly reason: "unparseable" | "responder_error";
    readonly detail: string;
    readonly cause?: unknown;
};
export declare const parseResponse: (bytes: Uint8Array) => Parsed;
//# sourceMappingURL=ocspParse.d.mts.map