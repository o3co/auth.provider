import { X509Certificate } from "node:crypto";
import { getCACertificates } from "node:tls";
import {
	certificateOf,
	type PathRules,
	signatureAlgorithms,
	type Trust,
	trustOf,
} from "@mod/x509-path";

const serverAuth = "1.3.6.1.5.5.7.3.1";
const anyPurpose = "2.5.29.37.0";
/** Key usage's signing, key encipherment and key agreement bits (RFC 5280 §4.2.1.3): a TLS server's. */
const serving = 0x80 | 0x20 | 0x08;

/**
 * The rules a peer's path is held to before its revocation is said confirmed: OpenSSL's for a TLS
 * server and more, as the path checked may be another than OpenSSL's: every certificate's extended
 * key usage, where it has one, for server authentication; RSA of 2048 bits at least and EC on P-256,
 * P-384 or P-521 alone, anchor included; six intermediates at most.
 */
export const peerRules = Object.freeze<PathRules>({
	maxIntermediates: 6,
	signatureAlgorithms,
	minRsaBits: 2048,
	ecCurves: ["P-256", "P-384", "P-521"],
	purpose: { ekus: [serverAuth, anyPurpose], on: "path" },
	leafKeyUsage: serving,
});

/** A certificate as x509-path reads it. */
export type Certificate = NonNullable<ReturnType<typeof certificateOf>>;

const blocks = (pem: string) =>
	pem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g) ?? [];

/**
 * What a peer's path is checked toward, read once: the platform's store as TLS reads it, its
 * self-signed certificates the anchors and the others intermediates a peer may leave out; or a
 * test's authorities, their self-signed ones alone. One x509-path cannot read is left out.
 */
export function storeTrust(ca?: string): Trust {
	const read = (ca === undefined ? getCACertificates("default") : blocks(ca)).flatMap((pem) => {
		const x509 = new X509Certificate(pem);
		const der = new Uint8Array(x509.raw);
		return certificateOf(der) ? [{ x509, der }] : [];
	});
	const selfSigned = ({ x509 }: { x509: X509Certificate }) =>
		x509.checkIssued(x509) && x509.verify(x509.publicKey);
	return trustOf({
		anchors: read.filter(selfSigned).map((one) => one.der),
		intermediates:
			ca === undefined ? read.filter((one) => !selfSigned(one)).map((one) => one.der) : [],
		selfSignedAnchorsOnly: true,
	});
}
