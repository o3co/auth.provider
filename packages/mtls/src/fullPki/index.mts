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

/** Public surface of the `full-pki` arm (issue #341). */
export {
	type AlgorithmCheck,
	type AlgorithmPolicy,
	checkAlgorithmPolicy,
	checkSignatureAlgorithm,
	DEFAULT_SIGNATURE_ALGORITHMS,
	SIGNATURE_ALGORITHM_NAMES,
	SIGNATURE_ALGORITHM_OIDS,
	type SignatureAlgorithmCheck,
	type SignatureAlgorithmName,
} from "./algorithms.mjs";
export {
	type CrlDistributionPoints,
	type CrlLookup,
	type CrlPointUnavailable,
	type CrlResolver,
	type CrlResolverOptions,
	type CrlUnavailableReason,
	createCrlResolver,
	crlDistributionPoints,
	describeUnavailable,
} from "./crl.mjs";
export {
	createGuardedFetch,
	type FetchOutcome,
	type FetchRejection,
	type GuardedFetch,
	type GuardedFetchOptions,
	type GuardedRequest,
} from "./fetchGuard.mjs";
export {
	checkMustStaple,
	createOcspResolver,
	OCSP_CLOCK_SKEW_MS,
	OCSP_NEGATIVE_CACHE_TTL_MS,
	OCSP_UNDATED_RESPONSE_MAX_AGE_MS,
	type OcspCertificateStatus,
	type OcspLookup,
	type OcspResolver,
	type OcspResolverOptions,
	type OcspResponders,
	type OcspUnavailableReason,
	ocspResponders,
} from "./ocsp.mjs";
export {
	createFullPkiValidator,
	type FullPkiOptions,
	type FullPkiResult,
	type FullPkiValidator,
	type OnRevocationUnavailable,
	type RevocationPolicy,
	type RevocationSource,
} from "./validate.mjs";
