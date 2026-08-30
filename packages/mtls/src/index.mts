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
 *   - `createTrustedProxyMatcher` — no longer lives here at all. #292 moved the
 *     trusted-proxy vocabulary into `@o3co/auth-provider-core`, where
 *     `http.trustProxy` validates against the same definition; this package
 *     consumes it. Consumers configure `trusted-proxies` rather than building a
 *     matcher, and anything that does need one imports core's so a second,
 *     subtly different notion of "trusted proxy" cannot appear.
 *   - `pemToDer`, `derToPem` — internal codec; surface minimization.
 *   - the `fullPki/` internals (`createFullPkiValidator`, the CRL resolver,
 *     the guarded fetch) — `mode = "full-pki"` is reached through config, not
 *     by assembling the validator by hand. Only the algorithm vocabulary is
 *     exported, because an operator writing
 *     `oauth.mtls.full-pki.signature-algorithms` needs to know what the legal
 *     values are, and a list in prose drifts from the one the schema enforces.
 *
 * Per Wave 2 Phase 3 spec §5.1.
 */

export type { ClientCertificate } from "./certificate.mjs";
export { MtlsError, type MtlsErrorCode, type MtlsReasonCode } from "./errors.mjs";
export { createMtlsMechanism, type MtlsMechanismOptions } from "./extractor.mjs";
export {
	DEFAULT_SIGNATURE_ALGORITHMS,
	SIGNATURE_ALGORITHM_NAMES,
	type SignatureAlgorithmName,
} from "./fullPki/algorithms.mjs";
export type { CertHeaderDialect } from "./headers.mjs";
export { mtlsConfigSchema, mtlsModule } from "./module.mjs";
export { computeCertThumbprint } from "./thumbprint.mjs";
