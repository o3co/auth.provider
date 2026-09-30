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
 * The header parsers, `validateCertChain`, the PEM codec and the `fullPki/`
 * internals are not exported: consumers reach them through config
 * (`certHeaderDialect`, `mode`, `trustedCas`). The trusted-proxy matcher is
 * core's, shared with `http.trustProxy`. Only the `full-pki` algorithm
 * vocabulary is exported, so the legal `signatureAlgorithms` values are the
 * list the schema enforces rather than prose that drifts.
 */

export type { ClientCertificate } from "./certificate.mjs";
export {
	MtlsError,
	type MtlsErrorCode,
	type MtlsReasonCode,
	MtlsRevocationSourceError,
	MtlsRevocationUnavailableError,
} from "./errors.mjs";
export { createMtlsMechanism, type MtlsMechanismOptions } from "./extractor.mjs";
export {
	DEFAULT_SIGNATURE_ALGORITHMS,
	SIGNATURE_ALGORITHM_NAMES,
	type SignatureAlgorithmName,
} from "./fullPki/algorithms.mjs";
export type { CertHeaderDialect } from "./headers.mjs";
export { mtlsConfigSchema, mtlsModule } from "./module.mjs";
export { computeCertThumbprint } from "./thumbprint.mjs";
