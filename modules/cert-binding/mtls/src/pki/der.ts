import * as asn1js from "asn1js";
import type * as pkijs from "pkijs";

export const oid = {
	keyUsage: "2.5.29.15",
	reasonCode: "2.5.29.21",
	subjectAltName: "2.5.29.17",
	basicConstraints: "2.5.29.19",
	deltaCrlIndicator: "2.5.29.27",
	issuingDistributionPoint: "2.5.29.28",
	certificateIssuer: "2.5.29.29",
	nameConstraints: "2.5.29.30",
	crlDistributionPoints: "2.5.29.31",
	certificatePolicies: "2.5.29.32",
	policyConstraints: "2.5.29.36",
	extKeyUsage: "2.5.29.37",
	inhibitAnyPolicy: "2.5.29.54",
	authorityInfoAccess: "1.3.6.1.5.5.7.1.1",
	ocspNonce: "1.3.6.1.5.5.7.48.1.2",
	ocspNoCheck: "1.3.6.1.5.5.7.48.1.5",
} as const;

export const generalName = { dns: 2, uri: 6, ip: 7 } as const;

/** Whether a CRLReason is certificateHold (RFC 5280 §5.3.1), the one revocation that can be lifted. */
export const isHold = (reason: asn1js.BaseBlock | undefined) =>
	reason instanceof asn1js.Enumerated && reason.valueBlock.valueDec === 6;

/** Key usage bits in its first byte (RFC 5280 §4.2.1.3). */
export const usage = { digitalSignature: 0x80, keyAgreement: 0x08, cRLSign: 0x02 } as const;

export const parsedExtension = <T>(cert: pkijs.Certificate, id: string) =>
	cert.extensions?.find((extension) => extension.extnID === id)?.parsedValue as T | undefined;

/** Whether key usage, where present, allows any of `bits`. */
export function keyUsageAllows(cert: pkijs.Certificate, bits: number): boolean {
	const value = parsedExtension<asn1js.BitString>(cert, oid.keyUsage);
	return !value || ((value.valueBlock.valueHexView[0] ?? 0) & bits) !== 0;
}

export const same = (a: Uint8Array, b: Uint8Array) =>
	a.length === b.length && a.every((byte, at) => byte === b[at]);

/** `make` over DER holding exactly one value; undefined if it does not, or `make` refuses it. */
export function decoded<T>(der: Uint8Array, make: (schema: asn1js.AsnType) => T): T | undefined {
	try {
		const parsed = asn1js.fromBER(der);
		if (parsed.offset === -1 || parsed.offset !== der.byteLength) return undefined;
		return make(parsed.result);
	} catch {
		return undefined;
	}
}
