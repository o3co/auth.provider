import { certificateOf, type PathRefusal, type PathRules, pathOf } from "@mod/x509-path";
import type { Checked, PathPolicy, Pki, RevocationPolicy, Sources } from "./contract.ts";
import { revocationOver } from "./revocation/revocation.ts";

export { signatureAlgorithms } from "@mod/x509-path";

const clientAuth = "1.3.6.1.5.5.7.3.2";
/** Key usage's signing and key agreement bits (RFC 5280 §4.2.1.3), one of which a client's key usage allows. */
const signingOrAgreement = 0x80 | 0x08;

/** A client's path rules: the policy's, and the leaf for client authentication, signing or key agreement. */
const rulesOf = (path: PathPolicy): PathRules => ({
	...path,
	purpose: { ekus: [clientAuth], on: "leaf" },
	leafKeyUsage: signingOrAgreement,
});

/** A path's refusal in mtls's words: one for another purpose is not for client authentication. */
const reasonOf = (refusal: PathRefusal) =>
	refusal === "purpose" ? "not for client authentication" : refusal;

/** Whether the bytes are one certificate (DER) and nothing else. */
export const isCertificate = (der: Uint8Array) => certificateOf(der) !== undefined;

/** Checks a client's path to the anchors, and its revocation where a policy says how. */
export function pkiOver(
	path: PathPolicy,
	revocation?: { readonly policy: RevocationPolicy; readonly sources: Sources },
): Pki {
	const revocations =
		revocation &&
		revocationOver(
			{
				...revocation.policy,
				minRsaBits: path.minRsaBits,
				signatureAlgorithms: path.signatureAlgorithms,
			},
			revocation.sources,
		);
	return {
		check: async (leaf, chain, now): Promise<Checked> => {
			const built = await pathOf(leaf, chain, rulesOf(path), now);
			if (built.kind === "invalid") return { kind: "invalid", reason: reasonOf(built.reason) };
			if (!revocations) return { kind: "valid" };
			const status = await revocations.check(built.path);
			switch (status.kind) {
				case "good":
					return { kind: "valid" };
				case "revoked":
					return { kind: "revoked" };
				case "refused":
					return { kind: "invalid", reason: status.reason };
				case "outage":
					return { kind: "outage", reason: status.reason };
			}
		},
	};
}
