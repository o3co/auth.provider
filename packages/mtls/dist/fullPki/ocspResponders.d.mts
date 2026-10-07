/**
 * Where a certificate says to ask about it: the `id-ad-ocsp` HTTP(S) URIs in its
 * `authorityInfoAccess`, in the order listed. A certificate naming none is `no_responder`,
 * never a pass.
 */
import type * as pkijs from "pkijs";
export type OcspResponders = {
    readonly ok: true;
    readonly urls: readonly string[];
} | {
    readonly ok: false;
    readonly reason: "no_responder";
    readonly detail: string;
};
/**
 * The OCSP responders a certificate advertises, in the order listed. RFC
 * 5280 §4.2.2.1 lets a CA list several; they are tried in turn until one
 * yields an answer that can be used. Only absolute HTTP(S) URIs are kept —
 * a certificate left with none is `no_responder`, the OCSP twin of
 * `no_distribution_point`: an honest "cannot check", not a silent pass.
 */
export declare const ocspResponders: (certificate: pkijs.Certificate) => OcspResponders;
//# sourceMappingURL=ocspResponders.d.mts.map