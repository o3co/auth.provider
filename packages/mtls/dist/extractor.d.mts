import type { Logger, TokenBindingMechanism } from "@o3co/auth-provider-core";
import { type CertHeaderDialect } from "./headers.mjs";
/** Per Wave 2 Phase 3 spec §5.2. */
export interface MtlsMechanismOptions {
    readonly source: "header" | "tls-layer";
    readonly certHeader?: string;
    readonly certHeaderDialect?: CertHeaderDialect;
    readonly mode: "self-signed" | "pki";
    readonly trustedCas?: readonly string[];
    readonly logger?: Logger;
}
/**
 * Create an mTLS `TokenBindingMechanism`. The returned mechanism:
 *
 *   - `kind === "mtls"`.
 *   - `intentExplicit === false` — mTLS cert presentation is ambient at the
 *     transport layer (RFC 8705 §3); even when sourced from a forwarded
 *     header, the underlying signal is not an application-layer artifact.
 *   - `extract(req)` returns `null` when no cert is presented (ambient
 *     dispatch), `TokenBinding` on success, throws `MtlsError` on failure.
 *
 * Boot-time checks (defense-in-depth for programmatic callers that bypass
 * `mtlsModule`):
 *
 *   - `mode === "pki"` + empty `trustedCas` → throw at construction.
 *   - `mode === "pki"` + `source === "tls-layer"` → throw at construction
 *     (Codex Round 1 Important #1 fix — TLS-layer full-chain extraction
 *     is deferred to a future phase per spec §1.3).
 *
 * Per spec §8 + §11.2.
 */
export declare const createMtlsMechanism: (options: MtlsMechanismOptions) => TokenBindingMechanism;
//# sourceMappingURL=extractor.d.mts.map