import * as pkijs from "pkijs";
import {
	decoded,
	generalName,
	isHold,
	keyUsageAllows,
	oid,
	parsedExtension,
	usage,
} from "../der.ts";
import { isStrong, signedBy } from "../signatures.ts";

const scoping = new Set<string>([oid.deltaCrlIndicator, oid.issuingDistributionPoint]);

/** What a CRL says of one certificate, and until when; or why it says nothing. */
export type Judged =
	| { readonly kind: "good"; readonly until: number }
	| { readonly kind: "revoked"; readonly until: number; readonly held: boolean }
	| { readonly kind: "unusable"; readonly reason: string };

/** Where a certificate's CRL is: http and https full names of points for every reason, by its issuer. */
export function crlUrlsOf(cert: pkijs.Certificate): readonly string[] {
	const points = parsedExtension<pkijs.CRLDistributionPoints>(cert, oid.crlDistributionPoints);
	return (
		(points?.distributionPoints ?? [])
			.filter((point) => !point.reasons && !point.cRLIssuer)
			// A name relative to the issuer holds no URI.
			.flatMap((point) => (Array.isArray(point.distributionPoint) ? point.distributionPoint : []))
			.filter((name) => name.type === generalName.uri && /^https?:\/\//i.test(name.value))
			.map((name) => name.value as string)
	);
}

/**
 * What the CRL says of `cert`, as of `now`. Nothing in it is used before its signature is checked
 * with the issuer's key; a this update past `now` by more than `skewMs` is not yet in force.
 */
export async function judgeCrl(
	der: Uint8Array,
	cert: pkijs.Certificate,
	issuer: pkijs.Certificate,
	now: number,
	skewMs: number,
): Promise<Judged> {
	const unusable = (reason: string): Judged => ({ kind: "unusable", reason });
	const crl = decoded(der, (schema) => new pkijs.CertificateRevocationList({ schema }));
	if (!crl) return unusable("malformed");
	if (!isStrong(crl.signatureAlgorithm)) return unusable("signature algorithm");
	if (!crl.issuer.isEqual(cert.issuer)) return unusable("issuer");
	if (!keyUsageAllows(issuer, usage.cRLSign)) return unusable("issuer cannot sign crls");
	// The signature alone: what the CRL's extensions mean is judged here, not by the engine.
	if (!(await signedBy(issuer, crl.tbsView, crl.signatureValue, crl.signatureAlgorithm))) {
		return unusable("signature");
	}
	const next = crl.nextUpdate?.value.getTime();
	if (next === undefined || next < now) return unusable("stale");
	if (crl.thisUpdate.value.getTime() > now + skewMs) return unusable("not yet");
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
	const listed = entries.find((entry) => entry.userCertificate.isEqual(cert.serialNumber));
	const until = Math.min(next, issuer.notAfter.value.getTime());
	if (!listed) return { kind: "good", until };
	const reason = listed.crlEntryExtensions?.extensions.find((e) => e.extnID === oid.reasonCode);
	const read = reason && decoded(reason.extnValue.valueBlock.valueHexView, (schema) => schema);
	return { kind: "revoked", until, held: isHold(read) };
}
