/**
 * The resolver's cache, keyed per responder, issuer key and serial: concurrent lookups share one
 * request; answers live until their expiry; failures are remembered for
 * `OCSP_NEGATIVE_CACHE_TTL_MS` per responder or per certificate, never `bad_signature` or
 * `nonce_mismatch`; a cached delegated responder's answer re-checks it on every hit.
 */
import type * as pkijs from "pkijs";
import { type Answer } from "./ocspAnswer.mjs";
import type { ResponderVerdict } from "./ocspDelegate.mjs";
/**
 * How long a responder that could not be used is remembered, in
 * milliseconds. The CRL resolver's window, for the CRL resolver's reasons.
 */
export declare const OCSP_NEGATIVE_CACHE_TTL_MS = 30000;
export declare const DEFAULT_MAX_CACHE_ENTRIES = 1024;
export declare const serialHex: (certificate: pkijs.Certificate) => string;
/** Asks a responder about a certificate, without the cache. */
export type OcspQuery = (url: string, certificate: pkijs.Certificate, issuer: pkijs.Certificate, now: Date) => Promise<Answer>;
/** Re-checks the delegated responder a cached answer depends on. */
export type OcspResponderCheck = (delegate: pkijs.Certificate, issuer: pkijs.Certificate, now: Date) => Promise<ResponderVerdict>;
export interface OcspCache {
    lookup(url: string, certificate: pkijs.Certificate, issuer: pkijs.Certificate, issuerId: string, serial: string, now: Date): Promise<Answer>;
    /** Entry count, usable and remembered-unavailable alike. */
    size(): number;
}
export declare const createOcspCache: (maxEntries: number, query: OcspQuery, checkResponder: OcspResponderCheck) => OcspCache;
//# sourceMappingURL=ocspCache.d.mts.map