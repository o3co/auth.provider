/**
 * Critical extension processing (RFC 5280 §6.1.2, #341 item 4).
 *
 * > "A certificate using system MUST reject the certificate if it encounters
 * > a critical extension it does not recognize or a critical extension that
 * > contains information that it cannot process."
 *
 * The narrow mode ignored unrecognised critical extensions, which is the
 * exact inversion of what the flag means: the issuer marked the extension as
 * one a validator must understand *before* trusting the certificate, and
 * ignoring it accepts a certificate on terms the issuer explicitly refused.
 *
 * ### Why this is not left to pkijs
 *
 * The engine does apply this rule — inside `checkForCA`, which it runs only
 * over the CA certificates in the path. **The leaf is skipped.** So a client
 * certificate carrying a critical extension nobody understands validates
 * cleanly, which is precisely the position a certificate whose issuer
 * constrained it in some way this code has never heard of should not be in.
 * This module closes that, and applies the same rule uniformly to every
 * certificate on the path rather than to some of them.
 *
 * ### What "recognised" means here
 *
 * Only extensions this deployment actually acts on. Listing an OID that
 * nothing processes would be a worse bug than not listing it: it would turn a
 * refusal into an acceptance while looking like diligence.
 */
import type * as pkijs from "pkijs";
export type CriticalExtensionCheck = {
    readonly ok: true;
} | {
    readonly ok: false;
    readonly step: string;
    readonly detail: string;
};
/**
 * @param path the validated path, leaf first.
 */
export declare const checkCriticalExtensions: (path: readonly pkijs.Certificate[]) => CriticalExtensionCheck;
/**
 * A client certificate authenticates by signing in the TLS handshake, so a
 * `keyUsage` that excludes `digitalSignature` describes a key that cannot do
 * the thing this certificate is being presented to do.
 *
 * Absence is unconstrained, exactly as for `extendedKeyUsage` — RFC 5280
 * §4.2.1.3 makes the extension a restriction, not a grant.
 *
 * This also earns `keyUsage`'s place in `PROCESSED_ANYWHERE`: without it the
 * extension would be listed as recognised while nothing examined it on a
 * leaf.
 */
export declare const checkLeafKeyUsage: (leaf: pkijs.Certificate) => CriticalExtensionCheck;
//# sourceMappingURL=criticalExtensions.d.mts.map