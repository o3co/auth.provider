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
 *
 * The same rule, with the same listing discipline, is applied to CRLs (RFC
 * 5280 §5.2 and §5.3) on behalf of `crl.mts`, and to OCSP responses (RFC
 * 6960 §4.4) on behalf of `ocsp.mts`, at the bottom of this file.
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
 * Extensions processed **only on the leaf**.
 *
 * - `extendedKeyUsage` — by `checkClientLeafProfile` in `pki.mts`. On a CA
 *   it would mean EKU chaining — constraining what purposes the CA may issue
 *   for — which RFC 5280 does not define and this module does not implement.
 *   A CA that marks it critical is asking for enforcement there is none of,
 *   so it is refused rather than waved through.
 * - `tlsfeature` (RFC 7633) — by `checkMustStaple` in `ocsp.mts`, which
 *   refuses a leaf demanding a stapled OCSP response (#431). Processed by
 *   being refused, as the CRL scope extensions are.
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
 * Critical CRL extensions `crl.mts` processes (RFC 5280 §5.2).
 *
 * §5.2 is §6.1.2's twin — "if a CRL contains a critical extension that the
 * application cannot process, then the application MUST NOT use that CRL to
 * determine the status of certificates" — and the listing discipline is the
 * same: only what is acted on. Both entries are acted on by being *refused*:
 * `crl.mts` reads them to recognise a delta or a scoped CRL and reports it as
 * unsupported, which is processing the extension, not ignoring it.
 *
 * pkijs applies this rule inside `CertificateRevocationList.verify`, against
 * its own longer list, and answers `false` — the same answer as a forged
 * signature. Every OID here is on that list, so a CRL this check passes is
 * never refused by pkijs on this ground, and the two cannot disagree in the
 * direction that would resurrect #447.
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

			// §6.1.2 has two halves, and the second is easy to lose: the rule
			// covers an unrecognised critical extension "**or** a critical
			// extension that contains information that it cannot process". A
			// recognised OID whose value did not parse is exactly that case —
			// knowing an extension's name is not the same as having read it, and
			// treating a restriction we could not decode as satisfied is how an
			// unparseable `keyUsage` becomes an unconstrained key.
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
	// A `keyUsage` that is present but yields no bits is not "unconstrained" —
	// it is a restriction that could not be read. Absence is unconstrained
	// (handled above); an unreadable value is a refusal, because the
	// alternative is treating a stated restriction as satisfied because we
	// could not decode it. `keyUsage` is usually CRITICAL, which makes this the
	// §6.1.2 "cannot process" case as well.
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
 * Whether pkijs managed to read the extension's value.
 *
 * pkijs reports failure two ways: `parsedValue` is `undefined` when the value
 * is not valid DER at all, and — for an OID it has a class for — an *empty
 * instance carrying `parsingError`* when the DER did not fit that class. The
 * second is the subtler one: the object is there, every field reads as its
 * default, and a check that only tests for `undefined` treats "could not
 * decode the restriction" as "no restriction".
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
 * RFC 5280 §5.2 for the CRL's own extensions and §5.3 for its entries'. The
 * entry half matters because pkijs's `verify` never looks at entry extensions
 * at all: a critical `certificateIssuer` — the marker that an indirect CRL's
 * entries were issued by someone else — would otherwise be ignored, and the
 * serial matched against the wrong issuer. No entry extension is processed
 * here, so any critical one is a refusal.
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
 * Critical OCSP response extensions `ocsp.mts` processes (RFC 6960 §4.4).
 *
 * §4.4: "unrecognized critical extensions in the response MUST be
 * rejected". Only the nonce is acted on — it is compared against the one the
 * request carried. The other extensions the RFC defines for a response
 * (`crlID`, `archiveCutoff`, `serviceLocator`, extended-revoke) are
 * informational and always non-critical; none is read, so none is listed.
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
