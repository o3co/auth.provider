import type * as pkijs from "pkijs";
import type { CriticalExtensionCheck } from "./criticalExtensions.mjs";
/**
 * RFC 7633: a certificate whose TLS feature extension names `status_request`
 * (or `status_request_v2`) demands a stapled OCSP response, which this server
 * cannot present for a client certificate. It is refused under every
 * revocation mode, `disabled` included, since the demand is the
 * certificate's own. Other feature numbers are ignored; an undecodable value
 * is refused whether or not the extension is critical.
 */
export declare const checkMustStaple: (leaf: pkijs.Certificate) => CriticalExtensionCheck;
//# sourceMappingURL=ocspMustStaple.d.mts.map