import { createHash } from "node:crypto";
import type { ForwardedCertificate } from "@mod/client-certificate";
import type { BindingRead, Scene } from "@mod/sender-binding";
import type { Pki } from "./pki/contract.ts";
import { isCertificate } from "./pki/pki.ts";

export interface Checking {
	readonly now: () => number;
	readonly log: (event: string, fields: Readonly<Record<string, string>>) => void;
	/** Under PKI: the checks, and what an outage of revocation's sources leads to. */
	readonly pki?: { readonly checks: Pki; readonly onUnavailable: "reject" | "allow" };
}

/**
 * What the client's certificate binds a token to: its SHA-256 thumbprint, once it is checked. A
 * refusal is RFC 6749's invalid_client at issuance, and an invalid token at a resource (RFC 8705 §3).
 */
export async function readCertificate(
	certificate: ForwardedCertificate | undefined,
	scene: Scene,
	checking: Checking,
): Promise<BindingRead> {
	if (!certificate) return { kind: "absent" };
	// Why is logged, not answered.
	const refused = (reason: string): BindingRead => {
		checking.log("mtls.certificate_refused", { reason });
		const error = scene.kind === "resource" ? "invalid_token" : "invalid_client";
		return { kind: "refused", error, description: "certificate refused" };
	};
	if (certificate.kind === "malformed") return refused("forwarded unreadable");
	const bound: BindingRead = {
		kind: "bound",
		confirmation: createHash("sha256").update(certificate.leaf).digest("base64url"),
	};
	if (!checking.pki) return isCertificate(certificate.leaf) ? bound : refused("malformed");
	const checked = await checking.pki.checks.check(
		certificate.leaf,
		certificate.chain,
		checking.now(),
	);
	switch (checked.kind) {
		case "valid":
			return bound;
		case "revoked":
			return refused("revoked");
		case "invalid":
			return refused(checked.reason);
		case "outage":
			if (checking.pki.onUnavailable === "allow") {
				checking.log("mtls.revocation_unconfirmed", { reason: checked.reason });
				return bound;
			}
			return {
				kind: "refused",
				error: "temporarily_unavailable",
				description: "revocation not confirmed",
				unavailable: true,
			};
	}
}
