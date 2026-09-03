/**
 * Public exports for `@o3co/auth-provider-mtls`.
 *
 * Intentionally NOT exported (internal helpers):
 *   - `parseEnvoyXfccHeader`, `parsePlainPemHeader` — dialect parsers
 *     are composed via the `cert-header-dialect` config key, not imported
 *     directly.
 *   - `validateCertChain` — internal PKI helper; consumers configure
 *     `mode = "pki"` and `trusted-cas` rather than calling it.
 *   - `pemToDer`, `derToPem` — internal codec; surface minimization.
 *
 * Per Wave 2 Phase 3 spec §5.1.
 */
export type { ClientCertificate } from "./certificate.mjs";
export { MtlsError, type MtlsErrorCode, type MtlsReasonCode } from "./errors.mjs";
export { createMtlsMechanism, type MtlsMechanismOptions } from "./extractor.mjs";
export type { CertHeaderDialect } from "./headers.mjs";
export { mtlsConfigSchema, mtlsModule } from "./module.mjs";
export { computeCertThumbprint } from "./thumbprint.mjs";
//# sourceMappingURL=index.d.mts.map