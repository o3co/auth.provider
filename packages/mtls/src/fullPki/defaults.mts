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
 * The tuning defaults for `mode = "full-pki"`, in one place: `mtlsConfigSchema`
 * fills them in for config that omits the keys, and the mechanism factory for
 * a composition root that bypasses the schema. A second copy would drift
 * unseen, on the path nobody tests by default.
 *
 * These bound work and pin strength, so a conservative default suits almost
 * every deployment. `revocation.mode` and `.on-unavailable` trade an outage
 * against a revoked certificate still working, so they have no defaults
 * (README, "Revocation has no defaults, on purpose").
 *
 * A missing `max-chain-depth` reaching `validate` as `undefined` makes
 * `presented > undefined` false, so the depth guard never fires; a missing
 * `min-rsa-key-bits` does the same to the key-size floor. Both fail open,
 * silently.
 */

import {
	type AlgorithmPolicy,
	DEFAULT_SIGNATURE_ALGORITHMS,
	type SignatureAlgorithmName,
} from "./algorithms.mjs";

export interface FullPkiTuning {
	readonly maxChainDepth: number;
	readonly signatureAlgorithms: readonly SignatureAlgorithmName[];
	readonly minRsaKeyBits: number;
}

export const FULL_PKI_DEFAULT_MAX_CHAIN_DEPTH = 6;
export const FULL_PKI_DEFAULT_MIN_RSA_KEY_BITS = 2048;

export const FULL_PKI_DEFAULTS: FullPkiTuning = {
	maxChainDepth: FULL_PKI_DEFAULT_MAX_CHAIN_DEPTH,
	signatureAlgorithms: DEFAULT_SIGNATURE_ALGORITHMS,
	minRsaKeyBits: FULL_PKI_DEFAULT_MIN_RSA_KEY_BITS,
};

/**
 * The algorithm policy when the operator configures none, derived from
 * `FULL_PKI_DEFAULTS` so it cannot drift. `crl.mts` and `ocsp.mts` fall back
 * to it when their `algorithms` option is omitted.
 */
export const DEFAULT_ALGORITHM_POLICY: AlgorithmPolicy = {
	signatureAlgorithms: FULL_PKI_DEFAULTS.signatureAlgorithms,
	minRsaKeyBits: FULL_PKI_DEFAULTS.minRsaKeyBits,
};

/**
 * Fill in any tuning value a caller left unset. Checks each value at runtime
 * rather than trusting the type: the config crossed a HOCON parse and an
 * `as never` cast at the composition root.
 */
export const resolveFullPkiTuning = (
	partial:
		| {
				readonly "max-chain-depth"?: number;
				readonly "signature-algorithms"?: readonly SignatureAlgorithmName[];
				readonly "min-rsa-key-bits"?: number;
		  }
		| undefined,
): FullPkiTuning => ({
	maxChainDepth:
		typeof partial?.["max-chain-depth"] === "number"
			? partial["max-chain-depth"]
			: FULL_PKI_DEFAULTS.maxChainDepth,
	signatureAlgorithms:
		Array.isArray(partial?.["signature-algorithms"]) && partial["signature-algorithms"].length > 0
			? partial["signature-algorithms"]
			: FULL_PKI_DEFAULTS.signatureAlgorithms,
	minRsaKeyBits:
		typeof partial?.["min-rsa-key-bits"] === "number"
			? partial["min-rsa-key-bits"]
			: FULL_PKI_DEFAULTS.minRsaKeyBits,
});
