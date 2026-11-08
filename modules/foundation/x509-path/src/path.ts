import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { decoded, keyUsageAllows, oid, parsedExtension, same } from "./der.ts";
import { isSelfIssued, nameConstraintsRefusal } from "./names.ts";
import { isSignedAsTaken, type SignatureAlgorithm } from "./signatures/signatures.ts";

/** The EC curves a rule may take, by name, as their identifiers name them. */
const curves = {
	"P-256": "1.2.840.10045.3.1.7",
	"P-384": "1.3.132.0.34",
	"P-521": "1.3.132.0.35",
} as const;
export type EcCurve = keyof typeof curves;
const ecPublicKey = "1.2.840.10045.2.1";

/** What a path is held to, as its caller chooses it. */
export interface PathRules {
	/** Trust anchors (DER); a peer never sends one that counts. */
	readonly anchors: readonly Uint8Array[];
	/** At most this many certificates between the leaf and an anchor. */
	readonly maxIntermediates: number;
	/** The signature algorithms taken on the path, anchors' own aside. */
	readonly signatureAlgorithms: readonly SignatureAlgorithm[];
	/** The fewest bits an RSA key on the path, anchor included, may have. */
	readonly minRsaBits: number;
	/** The EC curves a key on the path, anchor included, may be on; any where none are given. */
	readonly ecCurves?: readonly EcCurve[];
	/**
	 * The purposes (extended key usage identifiers) one of which a certificate's extended key usage,
	 * where it has one, must name: the leaf's alone, or every certificate's on the path, anchor included.
	 */
	readonly purpose: { readonly ekus: readonly string[]; readonly on: "leaf" | "path" };
	/** Key usage bits the leaf's key usage, where it has one, must allow one of. */
	readonly leafKeyUsage: number;
}

/** Why a path is refused. */
export type PathRefusal =
	| "malformed"
	| "path"
	| "too many intermediates"
	| "signature algorithm"
	| "rsa key too small"
	| "ec curve"
	| "malformed extension"
	| "critical extension"
	| "leaf is a ca"
	| "path length"
	| "name constraints"
	| "name constraints unsupported"
	| "purpose";
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

/** Whether an EC key is on one of the curves taken; any other key, or no curves given, passes. */
function onCurve(cert: pkijs.Certificate, taken: readonly EcCurve[] | undefined): boolean {
	const algorithm = cert.subjectPublicKeyInfo.algorithm;
	if (taken === undefined || algorithm.algorithmId !== ecPublicKey) return true;
	const params: unknown = algorithm.algorithmParams;
	// A curve given by its parameters rather than its name is none taken.
	if (!(params instanceof asn1js.ObjectIdentifier)) return false;
	const named = params.valueBlock.toString();
	return taken.some((curve) => curves[curve] === named);
}

/** Whether a certificate's extended key usage, where it has one, names one of the purposes. */
function forPurpose(cert: pkijs.Certificate, ekus: readonly string[]): boolean {
	const eku = parsedExtension<pkijs.ExtKeyUsage>(cert, oid.extKeyUsage);
	return !eku || eku.keyPurposes.some((purpose) => ekus.includes(purpose));
}

/** Why a path the engine built is still refused, if it is. */
function refusalOf(path: readonly pkijs.Certificate[], rules: PathRules): PathRefusal | undefined {
	const [leaf] = path;
	if (!leaf) return "path";
	const intermediates = path.length - 2;
	if (intermediates > rules.maxIntermediates) return "too many intermediates";
	for (const [at, cert] of path.entries()) {
		// The anchor's own signature is not checked: it is trusted as it is.
		const signer = path[at + 1];
		if (signer && !isSignedAsTaken(cert, signer, rules.signatureAlgorithms))
			return "signature algorithm";
		const bits = rsaBits(cert);
		if (bits !== undefined && bits < rules.minRsaBits) return "rsa key too small";
		if (!onCurve(cert, rules.ecCurves)) return "ec curve";
		if (rules.purpose.on === "path" && !forPurpose(cert, rules.purpose.ekus)) return "purpose";
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
	if (!forPurpose(leaf, rules.purpose.ekus)) return "purpose";
	if (!keyUsageAllows(leaf, rules.leafKeyUsage)) return "purpose";
	return undefined;
}

/** Parses a certificate; undefined for anything that is not one. */
export const certificateOf = (der: Uint8Array) =>
	decoded(der, (schema) => new pkijs.Certificate({ schema }));

const parsed = (c: pkijs.Certificate | undefined): c is pkijs.Certificate => c !== undefined;

/**
 * The path from the leaf to an anchor, through the candidates given (a chain a peer sent), as of
 * `now`. The engine builds over every candidate and anchor given, unbounded: a caller bounds them, or
 * hands it one chain.
 */
export async function pathOf(
	leaf: Uint8Array,
	candidates: readonly Uint8Array[],
	rules: PathRules,
	now: number,
): Promise<
	| { readonly kind: "path"; readonly path: readonly pkijs.Certificate[] }
	| { readonly kind: "invalid"; readonly reason: PathRefusal }
> {
	// The engine takes the end entity last, and drops a certificate sent twice.
	const sent = [...candidates.filter((der) => !same(der, leaf)), leaf];
	const certificates = sent.map(certificateOf);
	const anchors = rules.anchors.map(certificateOf);
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
	// The path must start with the leaf given itself.
	if (path[0] !== certificates.at(-1)) return { kind: "invalid", reason: "path" };
	const refused = refusalOf(path, rules);
	return refused ? { kind: "invalid", reason: refused } : { kind: "path", path };
}
