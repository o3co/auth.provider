/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Public exports for `@o3co/auth-provider-mtls`.
 *
 * Intentionally NOT exported (internal helpers):
 *   - `parseEnvoyXfccHeader`, `parsePlainPemHeader` — dialect parsers
 *     are composed via the `cert-header-dialect` config key, not imported
 *     directly.
 *   - `validateCertChain` — internal PKI helper; consumers configure
 *     `mode = "pki"` and `trusted-cas` rather than calling it.
 *   - `createTrustedProxyMatcher` — internal; consumers configure
 *     `trusted-proxies` rather than building a matcher themselves. Exporting
 *     it would invite a second, subtly different notion of "trusted proxy"
 *     alongside the one #292 is consolidating.
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
