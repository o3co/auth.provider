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
 * Critical extension processing (RFC 5280 §6.1.2):
 *
 * > "A certificate using system MUST reject the certificate if it encounters
 * > a critical extension it does not recognize or a critical extension that
 * > contains information that it cannot process."
 *
 * pkijs applies it to the CA certificates only (`checkForCA`), skipping the
 * leaf; this module applies it to the whole path (README, "What the library
 * does, and what this package still owns").
 *
 * "Recognised" means only extensions this deployment acts on: listing an OID
 * nothing processes would turn a refusal into an acceptance.
 *
 * The same rule and listing discipline apply to CRLs (RFC 5280 §5.2, §5.3)
 * for `crl.mts` and to OCSP responses (RFC 6960 §4.4) for `ocspShape.mts`, below.
 */

import type * as pkijs from "pkijs";

/**
 * Critical extensions processed at any position on the path: `basicConstraints`
 * (`cA` by the engine, `pathLenConstraint` by `validate.mts`), `keyUsage` (CA
 * bits by the engine, `digitalSignature` on the leaf by `checkLeafKeyUsage`),
 * and `subjectAltName` plus the name-constraint and policy extensions (the
 * engine's RFC 5280 §6.1 processing).
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
 * Extensions processed only on the leaf:
 *
 * - `extendedKeyUsage`, by `checkClientLeafProfile` in `pki.mts`. On a CA it
 *   would mean EKU chaining, which RFC 5280 does not define and this module
 *   does not implement, so a critical one on a CA is refused.
 * - `tlsfeature` (RFC 7633), by `checkMustStaple` in `ocspMustStaple.mts`, which
 *   refuses a leaf demanding a stapled OCSP response.
 */
const PROCESSED_ON_LEAF_ONLY: ReadonlySet<string> = new Set([
	"2.5.29.37", // extKeyUsage
	"1.3.6.1.5.5.7.1.24", // tlsfeature — read, and refused when it demands must-staple
]);

/**
 * Extensions pkijs has no class for, whose value this package decodes
 * itself. The `parsedValue` requirement below does not apply to them: pkijs
 * leaves it undefined for every one, parseable or not, and the reader is
 * what decides whether the value could be honoured — `checkMustStaple`
 * refuses an undecodable `tlsfeature` on its own.
 */
const PARSED_LOCALLY: ReadonlySet<string> = new Set([
	"1.3.6.1.5.5.7.1.24", // tlsfeature
]);

/**
 * Critical CRL extensions `crl.mts` processes (RFC 5280 §5.2: a CRL with a
 * critical extension the application cannot process MUST NOT be used). Both
 * are processed by being refused: `crl.mts` recognises a delta or scoped CRL
 * and reports it as unsupported.
 *
 * pkijs's `CertificateRevocationList.verify` applies the same rule against
 * its own longer list and answers `false`, indistinguishable from a forged
 * signature. Every OID here is on that list, so a CRL this check passes is
 * never refused by pkijs on this ground.
 */
const CRL_PROCESSED: ReadonlySet<string> = new Set([
	"2.5.29.27", // deltaCRLIndicator — recognised, and refused as a delta CRL
	"2.5.29.28", // issuingDistributionPoint — recognised, and refused when it scopes the CRL
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
		const where = isLeaf ? "leaf" : `CA at depth ${index}`;
		for (const extension of certificate.extensions ?? []) {
			if (!extension.critical) continue;

			const recognised =
				PROCESSED_ANYWHERE.has(extension.extnID) ||
				(isLeaf && PROCESSED_ON_LEAF_ONLY.has(extension.extnID));
			if (!recognised) {
				return {
					ok: false,
					step: "unrecognised critical extension",
					detail:
						`${where} carries critical extension ${extension.extnID}, which this ` +
						"validator does not process (RFC 5280 §6.1.2 requires rejection " +
						"rather than ignoring it)",
				};
			}

			if (PARSED_LOCALLY.has(extension.extnID)) continue;

			// §6.1.2's second half, "a critical extension that contains
			// information that it cannot process": a recognised OID whose value
			// did not parse. Treating it as satisfied would turn an unparseable
			// `keyUsage` into an unconstrained key.
			if (extension.parsedValue === undefined || extension.parsedValue === null) {
				return {
					ok: false,
					step: "unparseable critical extension",
					detail:
						`${where} carries critical extension ${extension.extnID} whose value ` +
						"could not be parsed, so the restriction it states cannot be honoured",
				};
			}
		}
	}
	return { ok: true };
};

/**
 * A client certificate authenticates by signing in the TLS handshake, so a
 * leaf `keyUsage` must permit `digitalSignature`. Absence is unconstrained
 * (RFC 5280 §4.2.1.3: a restriction, not a grant). This check is what
 * entitles `keyUsage` to its place in `PROCESSED_ANYWHERE` on a leaf.
 */
export const checkLeafKeyUsage = (leaf: pkijs.Certificate): CriticalExtensionCheck => {
	const extension = leaf.extensions?.find((ext) => ext.extnID === OID_KEY_USAGE);
	if (extension === undefined) return { ok: true };
	const parsed = extension.parsedValue as
		| { valueBlock?: { valueHexView?: Uint8Array } }
		| undefined;
	const bytes = parsed?.valueBlock?.valueHexView;
	// Present but yielding no bits is a restriction that could not be read,
	// not "unconstrained", so it is refused (usually critical, so also the
	// §6.1.2 "cannot process" case).
	if (bytes === undefined || bytes.length === 0) {
		return {
			ok: false,
			step: "unparseable leaf keyUsage",
			detail:
				"the leaf carries a keyUsage extension whose bit string could not be read, " +
				"so the restriction it states cannot be honoured",
		};
	}
	const DIGITAL_SIGNATURE = 0x80;
	if (((bytes[0] ?? 0) & DIGITAL_SIGNATURE) === DIGITAL_SIGNATURE) return { ok: true };
	return {
		ok: false,
		step: "leaf keyUsage excludes digitalSignature",
		detail:
			"the leaf's keyUsage does not permit digitalSignature, which TLS client " +
			"authentication requires (RFC 5280 §4.2.1.3)",
	};
};

/**
 * Whether pkijs read the extension's value. pkijs reports failure as
 * `parsedValue === undefined` (not DER) or, for an OID it has a class for, as
 * an empty instance carrying `parsingError`, whose fields all read as
 * defaults, so a test for `undefined` alone reads it as "no restriction".
 */
export const extensionValueParsed = (extension: pkijs.Extension): boolean => {
	const value: unknown = extension.parsedValue;
	if (value === undefined || value === null) return false;
	return !(
		typeof value === "object" &&
		"parsingError" in value &&
		value.parsingError !== undefined
	);
};

export type CrlCriticalExtensionCheck =
	| { readonly ok: true }
	| { readonly ok: false; readonly detail: string };

/**
 * RFC 5280 §5.2 for the CRL's own extensions and §5.3 for its entries'.
 * pkijs's `verify` never looks at entry extensions: a critical
 * `certificateIssuer` (the marker that an indirect CRL's entries were issued
 * by someone else) would be ignored and the serial matched against the wrong
 * issuer. No entry extension is processed here, so any critical one is a
 * refusal.
 */
export const checkCrlCriticalExtensions = (
	crl: pkijs.CertificateRevocationList,
): CrlCriticalExtensionCheck => {
	for (const extension of crl.crlExtensions?.extensions ?? []) {
		if (!extension.critical) continue;
		if (!CRL_PROCESSED.has(extension.extnID)) {
			return {
				ok: false,
				detail:
					`the CRL carries critical extension ${extension.extnID}, which this validator ` +
					"does not process (RFC 5280 §5.2 forbids using the CRL)",
			};
		}
		if (!extensionValueParsed(extension)) {
			return {
				ok: false,
				detail:
					`the CRL carries critical extension ${extension.extnID} whose value could not ` +
					"be parsed, so what it states cannot be honoured",
			};
		}
	}
	for (const entry of crl.revokedCertificates ?? []) {
		for (const extension of entry.crlEntryExtensions?.extensions ?? []) {
			if (!extension.critical) continue;
			return {
				ok: false,
				detail:
					`a CRL entry carries critical extension ${extension.extnID}, which this validator ` +
					"does not process (RFC 5280 §5.3 forbids using the CRL)",
			};
		}
	}
	return { ok: true };
};

/**
 * Critical OCSP response extensions the OCSP check processes (RFC 6960 §4.4:
 * "unrecognized critical extensions in the response MUST be rejected"). Only
 * the nonce is acted on, compared against the request's by `checkNonce` in
 * `ocspRequest.mts`. The RFC's other
 * response extensions are informational and non-critical, and none is read.
 */
const OCSP_PROCESSED: ReadonlySet<string> = new Set([
	"1.3.6.1.5.5.7.48.1.2", // id-pkix-ocsp-nonce
]);

/**
 * The response-level extensions and the single response's own, for the one
 * single response that is about the certificate in question. Other single
 * responses in the same message are not consulted, so their extensions are
 * not either.
 */
export const checkOcspCriticalExtensions = (
	responseExtensions: readonly pkijs.Extension[],
	singleExtensions: readonly pkijs.Extension[],
): CrlCriticalExtensionCheck => {
	for (const [where, extensions] of [
		["response", responseExtensions],
		["single response", singleExtensions],
	] as const) {
		for (const extension of extensions) {
			if (!extension.critical) continue;
			if (!OCSP_PROCESSED.has(extension.extnID)) {
				return {
					ok: false,
					detail:
						`the OCSP ${where} carries critical extension ${extension.extnID}, which this ` +
						"validator does not process (RFC 6960 §4.4 requires rejection)",
				};
			}
		}
	}
	return { ok: true };
};
