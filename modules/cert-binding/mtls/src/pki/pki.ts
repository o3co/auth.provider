import type { Checked, PathPolicy, Pki, RevocationPolicy, Sources } from "./contract.ts";
import { certificateOf, pathOf } from "./path.ts";
import { revocationOver } from "./revocation/revocation.ts";

/** Whether the bytes are one certificate (DER) and nothing else. */
export const isCertificate = (der: Uint8Array) => certificateOf(der) !== undefined;

/** Checks a client's path to the anchors, and its revocation where a policy says how. */
export function pkiOver(
	path: PathPolicy,
	revocation?: { readonly policy: RevocationPolicy; readonly sources: Sources },
): Pki {
	const revocations =
		revocation &&
		revocationOver({ ...revocation.policy, minRsaBits: path.minRsaBits }, revocation.sources);
	return {
		check: async (leaf, chain, now): Promise<Checked> => {
			const built = await pathOf(leaf, chain, path, now);
			if (built.kind === "invalid") return built;
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
