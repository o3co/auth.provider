import type * as pkijs from "pkijs";
/** `GeneralName` tag for `uniformResourceIdentifier` (RFC 5280 §4.2.1.6). */
export declare const GENERAL_NAME_URI = 6;
/** Whether a location is an absolute HTTP(S) URI, the only kind fetched. */
export declare const isHttpUrl: (value: string) => boolean;
/**
 * The issuer's key, as the hex SHA-256 of its DER `subjectPublicKeyInfo`. A cached
 * answer is keyed by it as well as its source: two CAs can share a subject name — a
 * key rollover keeps the DN — and an answer verified for one must never be handed
 * to a certificate the other issued.
 */
export declare const issuerKeyId: (issuer: pkijs.Certificate) => string;
//# sourceMappingURL=revocationSource.d.mts.map