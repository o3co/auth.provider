import type * as asn1js from "asn1js";
import * as pkijs from "pkijs";

/** The signature algorithms a policy may take, by name. EdDSA is not one: the engine cannot verify it. */
export const signatureAlgorithms = [
	"rsa-pkcs1-sha256",
	"rsa-pkcs1-sha384",
	"rsa-pkcs1-sha512",
	"rsa-pss-sha256",
	"rsa-pss-sha384",
	"rsa-pss-sha512",
	"ecdsa-sha256",
	"ecdsa-sha384",
	"ecdsa-sha512",
] as const;
export type SignatureAlgorithm = (typeof signatureAlgorithms)[number];

const pss = "1.2.840.113549.1.1.10";
const mgf1 = "1.2.840.113549.1.1.8";
/** SHA-2 RSA and ECDSA, whose identifiers name the hash. */
const named = new Map<string, SignatureAlgorithm>([
	["1.2.840.113549.1.1.11", "rsa-pkcs1-sha256"],
	["1.2.840.113549.1.1.12", "rsa-pkcs1-sha384"],
	["1.2.840.113549.1.1.13", "rsa-pkcs1-sha512"],
	["1.2.840.10045.4.3.2", "ecdsa-sha256"],
	["1.2.840.10045.4.3.3", "ecdsa-sha384"],
	["1.2.840.10045.4.3.4", "ecdsa-sha512"],
]);
const pssOver = new Map<string, SignatureAlgorithm>([
	["2.16.840.1.101.3.4.2.1", "rsa-pss-sha256"],
	["2.16.840.1.101.3.4.2.2", "rsa-pss-sha384"],
	["2.16.840.1.101.3.4.2.3", "rsa-pss-sha512"],
]);
/** The keys each family is checked with: RSA (PSS also by a PSS key), and EC. */
const keysOf = {
	rsa: new Set(["1.2.840.113549.1.1.1"]),
	pss: new Set(["1.2.840.113549.1.1.1", pss]),
	ecdsa: new Set(["1.2.840.10045.2.1"]),
};
const familyOf = (name: SignatureAlgorithm) =>
	name.startsWith("rsa-pss") ? "pss" : name.startsWith("rsa") ? "rsa" : "ecdsa";

/** PSS's name, by its hash, where its mask is MGF1 over that hash and its trailer the only one. */
function pssNameOf(params: asn1js.AsnType | undefined): SignatureAlgorithm | undefined {
	try {
		const read = new pkijs.RSASSAPSSParams({ schema: params });
		const hash = read.hashAlgorithm.algorithmId;
		const mask = read.maskGenAlgorithm;
		const maskHash = new pkijs.AlgorithmIdentifier({ schema: mask.algorithmParams }).algorithmId;
		if (mask.algorithmId !== mgf1 || maskHash !== hash || read.trailerField !== 1) return undefined;
		return pssOver.get(hash);
	} catch {
		return undefined;
	}
}

/** A signature algorithm's name: one above, or PSS over SHA-2 (its default is SHA-1); else none. */
function nameOf(algorithm: pkijs.AlgorithmIdentifier): SignatureAlgorithm | undefined {
	if (algorithm.algorithmId === pss) return pssNameOf(algorithm.algorithmParams);
	return named.get(algorithm.algorithmId);
}

/** Whether a signature algorithm is one of those taken. */
export function isTaken(
	algorithm: pkijs.AlgorithmIdentifier,
	taken: readonly SignatureAlgorithm[],
): boolean {
	const name = nameOf(algorithm);
	return name !== undefined && taken.includes(name);
}

/** Whether an algorithm is of the family of the key it is checked with, as the engine checks by the key. */
export function fitsKey(algorithm: pkijs.AlgorithmIdentifier, key: pkijs.PublicKeyInfo): boolean {
	const name = nameOf(algorithm);
	return name !== undefined && keysOf[familyOf(name)].has(key.algorithm.algorithmId);
}

/** Whether the algorithm signed inside the content is the one stated beside the signature. */
export const sameAlgorithm = (
	signed: pkijs.AlgorithmIdentifier,
	stated: pkijs.AlgorithmIdentifier,
) =>
	Buffer.from(signed.toSchema().toBER(false)).equals(Buffer.from(stated.toSchema().toBER(false)));

/** Whether a certificate states an algorithm taken, alike inside and beside its signature, of its signer's key. */
export const isSignedAsTaken = (
	cert: pkijs.Certificate,
	signer: pkijs.Certificate,
	taken: readonly SignatureAlgorithm[],
) =>
	isTaken(cert.signatureAlgorithm, taken) &&
	sameAlgorithm(cert.signature, cert.signatureAlgorithm) &&
	fitsKey(cert.signatureAlgorithm, signer.subjectPublicKeyInfo);

/** Whether the signature holds under the signer's key, by an algorithm of that key's family. */
export const signedBy = (
	signer: pkijs.Certificate,
	tbs: Uint8Array,
	signature: asn1js.BitString,
	algorithm: pkijs.AlgorithmIdentifier,
) =>
	fitsKey(algorithm, signer.subjectPublicKeyInfo)
		? pkijs
				.getCrypto(true)
				.verifyWithPublicKey(tbs, signature, signer.subjectPublicKeyInfo, algorithm)
				.catch(() => false)
		: Promise.resolve(false);
