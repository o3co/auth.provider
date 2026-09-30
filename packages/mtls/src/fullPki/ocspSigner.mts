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
 * Who may sign an answer and whether they did (RFC 6960 §4.2.2.2): the issuing CA, or a
 * certificate it issued carrying `id-kp-OCSPSigning`, within its validity, with no unprocessed
 * critical extension and within the path's algorithm policy; then the signature itself.
 */

import { X509Certificate } from "node:crypto";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { type AlgorithmPolicy, checkAlgorithmPolicy } from "./algorithms.mjs";
import { checkCriticalExtensions, extensionValueParsed } from "./criticalExtensions.mjs";
import { equalBytes } from "./ocspBytes.mjs";

/** `id-kp-OCSPSigning` (RFC 6960 §4.2.2.2). */
const OID_KP_OCSP_SIGNING = "1.3.6.1.5.5.7.3.9";

/** `extendedKeyUsage` (RFC 5280 §4.2.1.12). */
const OID_EXT_KEY_USAGE = "2.5.29.37";

/** Node's view of a certificate — what `checkAlgorithmPolicy` reads the key size from. */
const toNode = (certificate: pkijs.Certificate): X509Certificate =>
	new X509Certificate(Buffer.from(certificate.toSchema(true).toBER(false)));

/** Why a signer was refused: a signature that is not the CA's, or material outside the policy. */
type SignerRefusal = {
	readonly ok: false;
	readonly reason: "bad_signature" | "algorithm_not_permitted";
	readonly detail: string;
};

/** Whether `candidate` is the responder `responderID` names — by name, or by SHA-1 of its key. */
const isNamedResponder = async (
	candidate: pkijs.Certificate,
	responderId: unknown,
	crypto: pkijs.ICryptoEngine,
): Promise<boolean> => {
	if (responderId instanceof pkijs.RelativeDistinguishedNames) {
		return candidate.subject.isEqual(responderId);
	}
	if (responderId instanceof asn1js.OctetString) {
		const hash = await crypto.digest(
			{ name: "SHA-1" },
			// `.slice()` copies onto a plain ArrayBuffer — WebCrypto's `BufferSource`
			// refuses a view over a possibly-shared buffer.
			candidate.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView.slice(),
		);
		return equalBytes(new Uint8Array(hash), responderId.valueBlock.valueHexView);
	}
	return false;
};

/**
 * RFC 6960 §4.2.2.2: a responder other than the CA itself must hold a
 * certificate that CA issued, carrying `id-kp-OCSPSigning`. "Issued by"
 * means both the name chain and the signature; the EKU is the CA's
 * statement that this key may speak for it about revocation, and without
 * it any end-entity certificate the CA ever issued could un-revoke itself.
 */
const checkDelegatedResponder = async (
	candidate: pkijs.Certificate,
	issuer: pkijs.Certificate,
	now: Date,
	crypto: pkijs.ICryptoEngine,
	algorithms: AlgorithmPolicy,
): Promise<{ ok: true } | SignerRefusal> => {
	const notIssued =
		"the responder certificate was not issued by the certificate's issuing CA (RFC 6960 §4.2.2.2)";
	if (!candidate.issuer.isEqual(issuer.subject)) {
		return { ok: false, reason: "bad_signature", detail: notIssued };
	}
	let issued = false;
	try {
		issued = await candidate.verify(issuer, crypto);
	} catch {
		issued = false;
	}
	if (!issued) return { ok: false, reason: "bad_signature", detail: notIssued };

	if (
		candidate.notBefore.value.getTime() > now.getTime() ||
		candidate.notAfter.value.getTime() < now.getTime()
	) {
		return {
			ok: false,
			reason: "bad_signature",
			detail: "the responder certificate is outside its validity period",
		};
	}

	const eku = candidate.extensions?.find((ext) => ext.extnID === OID_EXT_KEY_USAGE);
	const purposes = (eku?.parsedValue as pkijs.ExtKeyUsage | undefined)?.keyPurposes;
	if (
		eku === undefined ||
		!extensionValueParsed(eku) ||
		purposes === undefined ||
		!purposes.includes(OID_KP_OCSP_SIGNING)
	) {
		return {
			ok: false,
			reason: "bad_signature",
			detail:
				"the responder certificate does not carry id-kp-OCSPSigning in extendedKeyUsage " +
				"(RFC 6960 §4.2.2.2)",
		};
	}

	// RFC 5280 §6.1.2 applies to the responder certificate as to any other;
	// a critical extension nothing here processes is a refusal, not a pass.
	const critical = checkCriticalExtensions([candidate]);
	if (!critical.ok) {
		return {
			ok: false,
			reason: "bad_signature",
			detail: `responder certificate: ${critical.detail}`,
		};
	}

	// The responder certificate is the one key an answer introduces that the
	// path pass never saw, so it is held to the path's policy (signature
	// algorithm and RSA modulus). Checked last, once it is established as this
	// CA's delegate: a stranger's certificate is refused as not issued, and only
	// the CA's own material is remembered under this reason.
	const algorithm = checkAlgorithmPolicy(
		toNode(candidate),
		candidate.signatureAlgorithm.algorithmId,
		algorithms,
	);
	if (!algorithm.ok) {
		return {
			ok: false,
			reason: "algorithm_not_permitted",
			detail: `responder certificate: ${algorithm.detail}`,
		};
	}

	// The responder certificate's own revocation status is the caller's
	// (`checkResponder`), skipped only for one carrying `id-pkix-ocsp-nocheck`.
	return { ok: true };
};

/** The certificate whose key must have signed `basic`: the CA, or a responder it delegated to. */
export const identifySigner = async (
	basic: pkijs.BasicOCSPResponse,
	issuer: pkijs.Certificate,
	now: Date,
	crypto: pkijs.ICryptoEngine,
	algorithms: AlgorithmPolicy,
): Promise<
	{ ok: true; signer: pkijs.Certificate; delegate?: pkijs.Certificate } | SignerRefusal
> => {
	const responderId: unknown = basic.tbsResponseData.responderID;
	if (await isNamedResponder(issuer, responderId, crypto)) return { ok: true, signer: issuer };
	for (const candidate of basic.certs ?? []) {
		if (!(await isNamedResponder(candidate, responderId, crypto))) continue;
		const delegated = await checkDelegatedResponder(candidate, issuer, now, crypto, algorithms);
		return delegated.ok ? { ok: true, signer: candidate, delegate: candidate } : delegated;
	}
	return {
		ok: false,
		reason: "bad_signature",
		detail:
			"the response names a responder that is neither the issuing CA nor a certificate " +
			"attached to the response",
	};
};

export const verifySignature = async (
	basic: pkijs.BasicOCSPResponse,
	signer: pkijs.Certificate,
	crypto: pkijs.ICryptoEngine,
): Promise<{ ok: true } | { ok: false; detail: string; cause?: unknown }> => {
	let verified = false;
	try {
		verified = await crypto.verifyWithPublicKey(
			basic.tbsResponseData.tbsView,
			basic.signature,
			signer.subjectPublicKeyInfo,
			basic.signatureAlgorithm,
		);
	} catch (err) {
		// Thrown rather than answered `false`: a signature value WebCrypto
		// cannot read, a key it cannot import. Its text stays on the cause.
		return { ok: false, detail: "signature check failed", cause: err };
	}
	return verified
		? { ok: true }
		: { ok: false, detail: "signature does not verify against the responder's key" };
};
