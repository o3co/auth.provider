/** Why a candidate issuer was rejected, phrased for a boot-time error message. */
export type IssuerRejection = "not-a-string" | "empty" | "not-absolute-url" | "unsupported-scheme" | "insecure-scheme" | "has-query" | "has-fragment" | "has-credentials";
/**
 * Returns `null` when `value` is a usable canonical issuer, otherwise the
 * reason it is not.
 *
 * Accepts an absolute `https:` URL, with a path prefix if the deployment needs
 * one, and an `http:` URL only for a loopback host. Rejects query strings and
 * fragments (OIDC Discovery derives the metadata URL from the issuer, so either
 * would produce a different document URL than the one served) and embedded
 * credentials.
 */
export declare function checkCanonicalIssuer(value: unknown): IssuerRejection | null;
/** Whether `value` is a usable canonical issuer. */
export declare function isCanonicalIssuer(value: unknown): value is string;
/** Operator-facing explanation for each rejection reason. */
export declare function describeIssuerRejection(reason: IssuerRejection): string;
//# sourceMappingURL=canonical.d.mts.map