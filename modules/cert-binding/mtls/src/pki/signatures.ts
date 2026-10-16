import type * as asn1js from "asn1js";
import * as pkijs from "pkijs";

const pss = "1.2.840.113549.1.1.10";
/** SHA-2 RSA and ECDSA, whose identifiers name the hash. EdDSA is not: the engine cannot verify it. */
const named = new Set([
	"1.2.840.113549.1.1.11",
	"1.2.840.113549.1.1.12",
	"1.2.840.113549.1.1.13",
	"1.2.840.10045.4.3.2",
	"1.2.840.10045.4.3.3",
	"1.2.840.10045.4.3.4",
]);
const sha2 = new Set([
	"2.16.840.1.101.3.4.2.1",
	"2.16.840.1.101.3.4.2.2",
	"2.16.840.1.101.3.4.2.3",
]);

/** Whether a signature algorithm is taken: those above, and PSS over SHA-2 (its default is SHA-1). */
export function isStrong(algorithm: pkijs.AlgorithmIdentifier): boolean {
	if (named.has(algorithm.algorithmId)) return true;
	if (algorithm.algorithmId !== pss) return false;
	try {
		const params = new pkijs.RSASSAPSSParams({ schema: algorithm.algorithmParams });
		return sha2.has(params.hashAlgorithm.algorithmId);
	} catch {
		return false;
	}
}

export const signedBy = (
	signer: pkijs.Certificate,
	tbs: Uint8Array,
	signature: asn1js.BitString,
	algorithm: pkijs.AlgorithmIdentifier,
) =>
	pkijs
		.getCrypto(true)
		.verifyWithPublicKey(tbs, signature, signer.subjectPublicKeyInfo, algorithm)
		.catch(() => false);
