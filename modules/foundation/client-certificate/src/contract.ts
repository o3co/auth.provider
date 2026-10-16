import { contract } from "@mod/kernel";

export { type CertificateRead, certificateOf } from "./certificate.ts";
export { certificateSettings } from "./settings.ts";
export { ignoredCertificates } from "./warnings.ts";

/** Where a trusted proxy puts the client's certificate, and in what form. */
export interface CertificateHeaders {
	/** "rfc9440": byte sequences; "pem": one PEM block; "xfcc": Envoy's, the chain in the same header. */
	readonly dialect: "rfc9440" | "pem" | "xfcc";
	readonly header: string;
	readonly "chain-header"?: string;
}

/** What a trusted proxy forwarded of the client's certificate: it, or that it was malformed. */
export type ForwardedCertificate =
	| {
			readonly kind: "certificate";
			readonly leaf: Uint8Array;
			readonly chain: readonly Uint8Array[];
	  }
	| { readonly kind: "malformed" };

/** Whether the operator named where a trusted proxy forwards the client's certificate. */
export interface CertificateForwarding {
	readonly configured: boolean;
}

export const certificateForwarding = contract<CertificateForwarding>(
	"client-certificate.certificate-forwarding",
);
