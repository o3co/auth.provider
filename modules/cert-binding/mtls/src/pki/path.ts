import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import type { PathPolicy } from "./contract.ts";
import { decoded, keyUsageAllows, oid, parsedExtension, same, usage } from "./der.ts";
import { isSelfIssued, nameConstraintsRefusal } from "./names.ts";
import { isStrong } from "./signatures.ts";

const clientAuth = "1.3.6.1.5.5.7.3.2";
/** Extensions a path is judged by; any other marked critical refuses the certificate. */
const known = new Set<string>([
	oid.keyUsage,
	oid.subjectAltName,
	oid.basicConstraints,
	oid.nameConstraints,
	oid.certificatePolicies,
	oid.policyConstraints,
	oid.extKeyUsage,
	oid.inhibitAnyPolicy,
]);
/** Kinds the engine keeps as a bare value, and the class that value must be. */
const bareKinds = new Map<string, typeof asn1js.BitString | typeof asn1js.Integer>([
	[oid.keyUsage, asn1js.BitString],
	[oid.inhibitAnyPolicy, asn1js.Integer],
]);

/** Whether the certificate marks critical an extension it is not judged by. */
export const hasUnknownCritical = (cert: pkijs.Certificate) =>
	cert.extensions?.some((e) => e.critical && !known.has(e.extnID)) ?? false;

/** Whether an extension's value fails to parse as its kind (the engine then reads it as unconstrained). */
export const hasMalformedExtension = (cert: pkijs.Certificate) =>
	cert.extensions?.some((e) => {
		const value: unknown = e.parsedValue;
		const bare = bareKinds.get(e.extnID);
		if (bare) return !(value instanceof bare);
		return (
			value === undefined ||
			(typeof value === "object" && value !== null && "parsingError" in value)
		);
	}) ?? false;

export function rsaBits(cert: pkijs.Certificate): number | undefined {
	const key = cert.subjectPublicKeyInfo.parsedKey;
	if (!(key instanceof pkijs.RSAPublicKey)) return undefined;
	const modulus = key.modulus.valueBlock.valueHexView;
	// The number's own length: zero bytes an encoding puts first, past the one DER allows, add none.
	const first = modulus.findIndex((byte) => byte !== 0);
	if (first === -1) return 0;
	return (modulus.length - first) * 8 - (Math.clz32(modulus[first] as number) - 24);
}

/** Why a path the engine built is still refused, if it is. */
function refusalOf(path: readonly pkijs.Certificate[], policy: PathPolicy): string | undefined {
	const [leaf] = path;
	if (!leaf) return "no path";
	const intermediates = path.length - 2;
	if (intermediates > policy.maxIntermediates) return "too many intermediates";
	for (const [at, cert] of path.entries()) {
		const anchor = at === path.length - 1;
		if (!anchor && !isStrong(cert.signatureAlgorithm)) return "signature algorithm";
		const bits = rsaBits(cert);
		if (bits !== undefined && bits < policy.minRsaBits) return "rsa key too small";
		if (hasMalformedExtension(cert)) return "malformed extension";
		if (hasUnknownCritical(cert)) return "critical extension";
		const basic = parsedExtension<pkijs.BasicConstraints>(cert, oid.basicConstraints);
		if (at === 0) {
			if (basic?.cA) return "leaf is a ca";
			continue;
		}
		// An issuer that is not a CA never makes a path the engine builds; self-issued CAs are not counted.
		const below = path.slice(1, at).filter((ca) => !isSelfIssued(ca)).length;
		if (typeof basic?.pathLenConstraint === "number" && below > basic.pathLenConstraint) {
			return "path length";
		}
	}
	const names = nameConstraintsRefusal(path);
	if (names) return names;
	const eku = parsedExtension<pkijs.ExtKeyUsage>(leaf, oid.extKeyUsage);
	if (eku && !eku.keyPurposes.includes(clientAuth)) return "not for client authentication";
	if (!keyUsageAllows(leaf, usage.digitalSignature | usage.keyAgreement)) {
		return "not for client authentication";
	}
	return undefined;
}

/** Parses a certificate; undefined for anything that is not one. */
export const certificateOf = (der: Uint8Array) =>
	decoded(der, (schema) => new pkijs.Certificate({ schema }));

const parsed = (c: pkijs.Certificate | undefined): c is pkijs.Certificate => c !== undefined;

/** The path from the leaf to an anchor, through the chain the client sent, as of `now`. */
export async function pathOf(
	leaf: Uint8Array,
	chain: readonly Uint8Array[],
	policy: PathPolicy,
	now: number,
): Promise<
	| { readonly kind: "path"; readonly path: readonly pkijs.Certificate[] }
	| { readonly kind: "invalid"; readonly reason: string }
> {
	// The engine takes the end entity last, and drops a certificate sent twice.
	const sent = [...chain.filter((der) => !same(der, leaf)), leaf];
	const certificates = sent.map(certificateOf);
	const anchors = policy.anchors.map(certificateOf);
	if (!certificates.every(parsed) || !anchors.every(parsed)) {
		return { kind: "invalid", reason: "malformed" };
	}
	const engine = new pkijs.CertificateChainValidationEngine({
		trustedCerts: anchors,
		certs: certificates,
		checkDate: new Date(now),
	});
	const built = await engine.verify().catch(() => undefined);
	const path = built?.certificatePath ?? [];
	if (!built?.result || path.length === 0) return { kind: "invalid", reason: "path" };
	// The path must start with the leaf sent itself: the certificate a token is bound to.
	if (path[0] !== certificates.at(-1)) return { kind: "invalid", reason: "path" };
	const refused = refusalOf(path, policy);
	return refused ? { kind: "invalid", reason: refused } : { kind: "path", path };
}
