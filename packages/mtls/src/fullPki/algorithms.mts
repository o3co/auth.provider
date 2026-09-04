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
 * Signature-algorithm and key-strength policy for `mode = "full-pki"`.
 *
 * RFC 5280 §6.1.4 leaves the acceptable algorithm set to local policy, and
 * without one "acceptable" means "whatever OpenSSL was built to parse". That
 * is not a decision a deployment made; it is a decision its base image made.
 * A certificate signed with SHA-1 still verifies, and a chain is only as
 * strong as its weakest hop — so the policy is applied to **every**
 * certificate on the validated path, anchors included, not just the leaf;
 * and to the revocation material about them — a CRL's signature, an OCSP
 * response's signature, and a delegated responder's certificate — because
 * pkijs verifies `sha1WithRSAEncryption` and `ecdsa-with-SHA1` as readily
 * as it does a certificate's, and a SHA-1-signed "not revoked" is no better
 * evidence than a SHA-1-signed certificate (#470).
 *
 * Names rather than OIDs in config: an operator reviewing
 * `signature-algorithms` should be able to see what it says. Unknown names
 * fail at boot rather than silently matching nothing, which would leave a
 * deployment believing it had a policy while rejecting every certificate.
 */

import type { X509Certificate } from "node:crypto";

/**
 * The algorithms this module will name. Deliberately a closed set: an
 * operator cannot express "SHA-1 is fine" by pasting an OID, because there is
 * no version of that sentence this module should help write.
 */
export const SIGNATURE_ALGORITHM_OIDS = {
	sha256WithRSAEncryption: "1.2.840.113549.1.1.11",
	sha384WithRSAEncryption: "1.2.840.113549.1.1.12",
	sha512WithRSAEncryption: "1.2.840.113549.1.1.13",
	rsassaPss: "1.2.840.113549.1.1.10",
	ecdsaWithSHA256: "1.2.840.10045.4.3.2",
	ecdsaWithSHA384: "1.2.840.10045.4.3.3",
	ecdsaWithSHA512: "1.2.840.10045.4.3.4",
	ed25519: "1.3.101.112",
	ed448: "1.3.101.113",
} as const;

export type SignatureAlgorithmName = keyof typeof SIGNATURE_ALGORITHM_OIDS;

export const SIGNATURE_ALGORITHM_NAMES = Object.keys(
	SIGNATURE_ALGORITHM_OIDS,
) as readonly SignatureAlgorithmName[];

/**
 * The default allowlist: every name above. The default is permissive across
 * *modern* algorithms and closed against everything else — SHA-1 and MD5 are
 * absent because they are not in the map at all, so no configuration can
 * reach them.
 */
export const DEFAULT_SIGNATURE_ALGORITHMS: readonly SignatureAlgorithmName[] =
	SIGNATURE_ALGORITHM_NAMES;

export interface AlgorithmPolicy {
	readonly signatureAlgorithms: readonly SignatureAlgorithmName[];
	/** Minimum RSA modulus size in bits. Ignored for EC and EdDSA keys. */
	readonly minRsaKeyBits: number;
}

export type AlgorithmCheck =
	| { readonly ok: true }
	| { readonly ok: false; readonly step: string; readonly detail: string };

/**
 * Node exposes the modulus length only for RSA keys, and only via
 * `asymmetricKeyDetails`. EC strength is carried by the named curve, which
 * the signature-algorithm allowlist already constrains — a P-256 key cannot
 * be used with `ecdsaWithSHA256` at some weaker size, the way a 512-bit RSA
 * key can be used with `sha256WithRSAEncryption`.
 */
const rsaModulusBits = (certificate: X509Certificate): number | null => {
	const key = certificate.publicKey;
	if (key.asymmetricKeyType !== "rsa" && key.asymmetricKeyType !== "rsa-pss") return null;
	const bits = key.asymmetricKeyDetails?.modulusLength;
	return typeof bits === "number" ? bits : null;
};

export type SignatureAlgorithmCheck =
	| { readonly ok: true }
	| { readonly ok: false; readonly detail: string };

/**
 * Whether a signature algorithm is one the policy names — the half of the
 * policy that applies to any signed object, not only to a certificate. A CRL
 * and an OCSP response carry a `signatureAlgorithm` exactly as a certificate
 * does, and are held to the same allowlist (#470). The detail names the
 * algorithm as the config vocabulary does when it can, and by OID when it
 * cannot — SHA-1 has no name here, deliberately.
 */
export const checkSignatureAlgorithm = (
	signatureAlgorithmOid: string,
	policy: AlgorithmPolicy,
): SignatureAlgorithmCheck => {
	const allowedOids = new Set<string>(
		policy.signatureAlgorithms.map((name) => SIGNATURE_ALGORITHM_OIDS[name]),
	);
	if (allowedOids.has(signatureAlgorithmOid)) return { ok: true };
	const known = Object.entries(SIGNATURE_ALGORITHM_OIDS).find(
		([, oid]) => oid === signatureAlgorithmOid,
	);
	return {
		ok: false,
		detail: `${known?.[0] ?? signatureAlgorithmOid} is not in oauth.mtls.full-pki.signature-algorithms`,
	};
};

export const checkAlgorithmPolicy = (
	certificate: X509Certificate,
	signatureAlgorithmOid: string,
	policy: AlgorithmPolicy,
): AlgorithmCheck => {
	const algorithm = checkSignatureAlgorithm(signatureAlgorithmOid, policy);
	if (!algorithm.ok) {
		return {
			ok: false,
			step: "signature algorithm not permitted",
			detail: `${certificate.subject}: ${algorithm.detail}`,
		};
	}

	const bits = rsaModulusBits(certificate);
	if (bits !== null && bits < policy.minRsaKeyBits) {
		return {
			ok: false,
			step: "rsa key too small",
			detail: `${certificate.subject}: ${bits}-bit RSA key is below the configured minimum of ${policy.minRsaKeyBits}`,
		};
	}

	return { ok: true };
};
