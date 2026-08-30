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
 * Critical extension processing (RFC 5280 §6.1.2, #341 item 4).
 *
 * > "A certificate using system MUST reject the certificate if it encounters
 * > a critical extension it does not recognize or a critical extension that
 * > contains information that it cannot process."
 *
 * The narrow mode ignored unrecognised critical extensions, which is the
 * exact inversion of what the flag means: the issuer marked the extension as
 * one a validator must understand *before* trusting the certificate, and
 * ignoring it accepts a certificate on terms the issuer explicitly refused.
 *
 * ### Why this is not left to pkijs
 *
 * The engine does apply this rule — inside `checkForCA`, which it runs only
 * over the CA certificates in the path. **The leaf is skipped.** So a client
 * certificate carrying a critical extension nobody understands validates
 * cleanly, which is precisely the position a certificate whose issuer
 * constrained it in some way this code has never heard of should not be in.
 * This module closes that, and applies the same rule uniformly to every
 * certificate on the path rather than to some of them.
 *
 * ### What "recognised" means here
 *
 * Only extensions this deployment actually acts on. Listing an OID that
 * nothing processes would be a worse bug than not listing it: it would turn a
 * refusal into an acceptance while looking like diligence.
 */

import type * as pkijs from "pkijs";

/**
 * Critical extensions processed at any position on the path.
 *
 * - `basicConstraints` — `cA` by the engine, `pathLenConstraint` by
 *   `validate.mts`.
 * - `keyUsage` — `keyCertSign` / `cRLSign` on CAs by the engine,
 *   `digitalSignature` on the leaf by `checkLeafKeyUsage` below.
 * - `nameConstraints`, `certificatePolicies`, `policyMappings`,
 *   `policyConstraints`, `inhibitAnyPolicy` — the engine's RFC 5280 §6.1
 *   name-constraint and policy-tree processing.
 * - `subjectAltName` — the names the engine matches constraints against.
 */
const PROCESSED_ANYWHERE: ReadonlySet<string> = new Set([
	"2.5.29.19", // basicConstraints
	"2.5.29.15", // keyUsage
	"2.5.29.17", // subjectAltName
	"2.5.29.30", // nameConstraints
	"2.5.29.32", // certificatePolicies
	"2.5.29.33", // policyMappings
	"2.5.29.36", // policyConstraints
	"2.5.29.54", // inhibitAnyPolicy
]);

/**
 * `extendedKeyUsage` is processed **only on the leaf**, by
 * `checkClientLeafProfile` in `pki.mts`.
 *
 * On a CA it would mean EKU chaining — constraining what purposes the CA may
 * issue for — which RFC 5280 does not define and this module does not
 * implement. A CA that marks it critical is asking for enforcement there is
 * none of, so it is refused rather than waved through.
 */
const PROCESSED_ON_LEAF_ONLY: ReadonlySet<string> = new Set([
	"2.5.29.37", // extKeyUsage
]);

/** OID of `keyUsage`. */
const OID_KEY_USAGE = "2.5.29.15";

export type CriticalExtensionCheck =
	| { readonly ok: true }
	| { readonly ok: false; readonly step: string; readonly detail: string };

/**
 * @param path the validated path, leaf first.
 */
export const checkCriticalExtensions = (
	path: readonly pkijs.Certificate[],
): CriticalExtensionCheck => {
	for (const [index, certificate] of path.entries()) {
		const isLeaf = index === 0;
		for (const extension of certificate.extensions ?? []) {
			if (!extension.critical) continue;
			if (PROCESSED_ANYWHERE.has(extension.extnID)) continue;
			if (isLeaf && PROCESSED_ON_LEAF_ONLY.has(extension.extnID)) continue;
			return {
				ok: false,
				step: "unrecognised critical extension",
				detail:
					`${isLeaf ? "leaf" : `CA at depth ${index}`} carries critical extension ` +
					`${extension.extnID}, which this validator does not process ` +
					"(RFC 5280 §6.1.2 requires rejection rather than ignoring it)",
			};
		}
	}
	return { ok: true };
};

/**
 * A client certificate authenticates by signing in the TLS handshake, so a
 * `keyUsage` that excludes `digitalSignature` describes a key that cannot do
 * the thing this certificate is being presented to do.
 *
 * Absence is unconstrained, exactly as for `extendedKeyUsage` — RFC 5280
 * §4.2.1.3 makes the extension a restriction, not a grant.
 *
 * This also earns `keyUsage`'s place in `PROCESSED_ANYWHERE`: without it the
 * extension would be listed as recognised while nothing examined it on a
 * leaf.
 */
export const checkLeafKeyUsage = (leaf: pkijs.Certificate): CriticalExtensionCheck => {
	const extension = leaf.extensions?.find((ext) => ext.extnID === OID_KEY_USAGE);
	if (extension === undefined) return { ok: true };
	const parsed = extension.parsedValue as
		| { valueBlock?: { valueHexView?: Uint8Array } }
		| undefined;
	const bytes = parsed?.valueBlock?.valueHexView;
	if (bytes === undefined || bytes.length === 0) return { ok: true };
	const DIGITAL_SIGNATURE = 0x80;
	if ((bytes[0] & DIGITAL_SIGNATURE) === DIGITAL_SIGNATURE) return { ok: true };
	return {
		ok: false,
		step: "leaf keyUsage excludes digitalSignature",
		detail:
			"the leaf's keyUsage does not permit digitalSignature, which TLS client " +
			"authentication requires (RFC 5280 §4.2.1.3)",
	};
};
