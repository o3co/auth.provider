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
 * Sub-PR 3a exports: the stable primitive types and the cert thumbprint
 * utility. `createMtlsMechanism`, `mtlsModule`, and `mtlsConfigSchema` are
 * NOT exported here — they land in Sub-PR 3b (extractor + module wiring).
 *
 * Per Wave 2 Phase 3 spec §5.1.
 */

export type { ClientCertificate } from "./certificate.mjs";
export { MtlsError, type MtlsErrorCode, type MtlsReasonCode } from "./errors.mjs";
export type { CertHeaderDialect } from "./headers.mjs";
export { computeCertThumbprint } from "./thumbprint.mjs";
