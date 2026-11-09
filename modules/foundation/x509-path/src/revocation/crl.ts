import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { decoded, generalName, isHold, keyUsageAllows, oid, usage } from "../der.ts";
import {
	isTaken,
	type SignatureAlgorithm,
	sameAlgorithm,
	signedBy,
} from "../signatures/signatures.ts";

const scoping = new Set<string>([oid.deltaCrlIndicator, oid.issuingDistributionPoint]);

/** What a CRL says of one certificate, and until when; or why it says nothing. */
export type Judged =
	| { readonly kind: "good"; readonly until: number }
	| { readonly kind: "revoked"; readonly until: number; readonly held: boolean }
	| { readonly kind: "unusable"; readonly reason: string };

/** A CRL whose signature and scope were checked: its times, its number and what it lists, by serial. */
export interface VerifiedCrl {
	readonly issuer: pkijs.RelativeDistinguishedNames;
	readonly thisUpdate: number;
	readonly nextUpdate: number;
	/** Its CRLNumber, where it has one. */
	readonly number?: bigint;
	/** Each certificate it lists, by its serial's bytes in hex, revoked on hold or not. */
	readonly listed: ReadonlyMap<string, { readonly held: boolean }>;
}

/** A certificate's CRL distribution points: none, the extension unreadable, or the points it names. */
export type DistributionPoints =
	| { readonly kind: "none" }
	| { readonly kind: "malformed" }
	| {
			readonly kind: "points";
			/** The http and https full names of points for every reason, by its issuer. */
			readonly urls: readonly string[];
			/** The points that give no such name. */
			readonly unusable: number;
	  };

const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString("hex");
/** What a CRL says of a serial it lists, one object for every entry alike: a large CRL holds many. */
const held = Object.freeze({ held: true });
const revoked = Object.freeze({ held: false });

/** A certificate's CRL distribution points, told by the extension's identifier and its value. */
export function distributionPointsOf(cert: pkijs.Certificate): DistributionPoints {
	const extension = cert.extensions?.find((e) => e.extnID === oid.crlDistributionPoints);
	if (!extension) return { kind: "none" };
	const value: unknown = extension.parsedValue;
	// pkijs keeps a value that does not parse as its kind, marked by `parsingError`.
	if (!(value instanceof pkijs.CRLDistributionPoints) || "parsingError" in value) {
		return { kind: "malformed" };
	}
	const urlsOf = (point: pkijs.DistributionPoint) =>
		point.reasons || point.cRLIssuer
			? []
			: // A name relative to the issuer holds no URI.
				(Array.isArray(point.distributionPoint) ? point.distributionPoint : [])
					.filter((name) => name.type === generalName.uri && /^https?:\/\//i.test(name.value))
					.map((name) => name.value as string);
	const each = value.distributionPoints.map(urlsOf);
	return {
		kind: "points",
		urls: Object.freeze(each.flat()),
		unusable: each.filter((urls) => urls.length === 0).length,
	};
}

/**
 * The CRL `issuer` signed, read as of `now`. Nothing in it is used before its signature is checked
 * with the issuer's key, by an algorithm `taken`; a this update past `now` by more than `skewMs` is
 * not yet in force; a delta, scoped or indirect CRL, or any critical extension, is unsupported.
 */
export async function verifyCrl(
	der: Uint8Array,
	issuer: pkijs.Certificate,
	now: number,
	skewMs: number,
	taken: readonly SignatureAlgorithm[],
): Promise<
	| { readonly kind: "verified"; readonly crl: VerifiedCrl }
	| { readonly kind: "unusable"; readonly reason: string }
> {
	const unusable = (reason: string) => ({ kind: "unusable" as const, reason });
	const crl = decoded(der, (schema) => new pkijs.CertificateRevocationList({ schema }));
	if (!crl) return unusable("malformed");
	if (!isTaken(crl.signatureAlgorithm, taken)) return unusable("signature algorithm");
	if (!sameAlgorithm(crl.signature, crl.signatureAlgorithm)) return unusable("signature algorithm");
	if (!crl.issuer.isEqual(issuer.subject)) return unusable("issuer");
	if (!keyUsageAllows(issuer, usage.cRLSign)) return unusable("issuer cannot sign crls");
	if (now < issuer.notBefore.value.getTime() || issuer.notAfter.value.getTime() < now) {
		return unusable("issuer out of date");
	}
	// The signature alone: what the CRL's extensions mean is judged here, not by the engine.
	if (!(await signedBy(issuer, crl.tbsView, crl.signatureValue, crl.signatureAlgorithm))) {
		return unusable("signature");
	}
	const next = crl.nextUpdate?.value.getTime();
	if (next === undefined || next < now) return unusable("stale");
	const thisUpdate = crl.thisUpdate.value.getTime();
	if (thisUpdate > now + skewMs) return unusable("not yet");
	const entries = crl.revokedCertificates ?? [];
	// Delta, scoped and indirect CRLs, marked critical or not, and any other critical extension.
	if (
		crl.crlExtensions?.extensions.some((e) => e.critical || scoping.has(e.extnID)) ||
		entries.some((entry) =>
			entry.crlEntryExtensions?.extensions.some(
				(e) => e.critical || e.extnID === oid.certificateIssuer,
			),
		)
	) {
		return unusable("unsupported");
	}
	const listed = new Map<string, { readonly held: boolean }>();
	for (const entry of entries) {
		const reason = entry.crlEntryExtensions?.extensions.find((e) => e.extnID === oid.reasonCode);
		const read = reason && decoded(reason.extnValue.valueBlock.valueHexView, (schema) => schema);
		listed.set(hex(entry.userCertificate.valueBlock.valueHexView), isHold(read) ? held : revoked);
	}
	const number = crl.crlExtensions?.extensions.find((e) => e.extnID === oid.crlNumber);
	const read = number && decoded(number.extnValue.valueBlock.valueHexView, (schema) => schema);
	// A CRLNumber is a non-negative INTEGER (RFC 5280 §5.2.3); any other is a CRL unread.
	const bytes = read instanceof asn1js.Integer ? read.valueBlock.valueHexView : undefined;
	if (number && (bytes === undefined || ((bytes[0] ?? 0) & 0x80) !== 0))
		return unusable("malformed");
	return {
		kind: "verified",
		crl: Object.freeze({
			issuer: crl.issuer,
			thisUpdate,
			nextUpdate: next,
			...(bytes ? { number: BigInt(`0x${hex(bytes) || "0"}`) } : {}),
			listed,
		}),
	};
}

/**
 * What a verified CRL says of `cert`, `issuer`'s, as of `now`: until its next update or the issuer's
 * end. The issuer's name, its right to sign CRLs and its dates are asked again here, every time.
 */
export function crlSays(
	verified: VerifiedCrl,
	cert: pkijs.Certificate,
	issuer: pkijs.Certificate,
	now: number,
): Judged {
	if (verified.nextUpdate < now) return { kind: "unusable", reason: "stale" };
	if (!verified.issuer.isEqual(cert.issuer)) return { kind: "unusable", reason: "issuer" };
	// Asked of every judgment: another issuer of the same name and key may be the path's now.
	if (!keyUsageAllows(issuer, usage.cRLSign)) {
		return { kind: "unusable", reason: "issuer cannot sign crls" };
	}
	if (now < issuer.notBefore.value.getTime() || issuer.notAfter.value.getTime() < now) {
		return { kind: "unusable", reason: "issuer out of date" };
	}
	const until = Math.min(verified.nextUpdate, issuer.notAfter.value.getTime());
	const entry = verified.listed.get(hex(cert.serialNumber.valueBlock.valueHexView));
	if (!entry) return { kind: "good", until };
	return { kind: "revoked", until, held: entry.held };
}
