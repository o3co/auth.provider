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
 * The tuning defaults for `mode = "full-pki"`, in one place.
 *
 * Two consumers need them and they must not drift: `mtlsConfigSchema`, which
 * fills them in for config that omits the keys, and `buildFullPkiValidator`,
 * which fills them in for a composition root that builds the mechanism
 * directly and bypasses the schema. Written twice, they would eventually
 * disagree, and the disagreement would be invisible — the second copy only
 * runs on the path nobody tests by default.
 *
 * ### Why these have defaults when `revocation` does not
 *
 * These three bound work and pin strength. Every deployment wants *a* value,
 * and a conservative one is right for almost all of them; getting the default
 * is not a decision anyone is dodging. `revocation.mode` and
 * `.on-unavailable` are different in kind: they trade an availability
 * incident against a window in which a revoked certificate still works, and
 * there is no answer that is right for every deployment. So those have no
 * defaults and `mtlsModule` refuses to boot without them.
 *
 * The failure mode this file closes is specific: a missing `max-chain-depth`
 * reaching `validate` as `undefined` makes `presented > undefined` evaluate
 * to `false`, so the depth guard silently never fires. A missing
 * `min-rsa-key-bits` does the same to the key-size floor. Both fail **open**,
 * and neither raises anything at boot.
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
 * The algorithm policy a `full-pki` deployment gets when the operator
 * configures none — the two tuning values above, in the shape
 * `checkAlgorithmPolicy` takes.
 *
 * Derived from `FULL_PKI_DEFAULTS` rather than restated, for this file's
 * usual reason: a second copy only runs on the path nobody tests by default,
 * and would eventually disagree. The resolvers in `crl.mts` and `ocsp.mts`
 * fall back to it when their `algorithms` option is omitted.
 */
export const DEFAULT_ALGORITHM_POLICY: AlgorithmPolicy = {
	signatureAlgorithms: FULL_PKI_DEFAULTS.signatureAlgorithms,
	minRsaKeyBits: FULL_PKI_DEFAULTS.minRsaKeyBits,
};

/**
 * Fill in any tuning value a caller left unset.
 *
 * Deliberately tolerant of a partially-populated object rather than trusting
 * the declared type: the config that reaches here has crossed a HOCON parse
 * and an `as never` cast at the composition root, so the type is a claim
 * about the shape, not a guarantee of it.
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
