import { createPrivateKey, createPublicKey, KeyObject, type webcrypto } from "node:crypto";
import { calculateJwkThumbprint, exportJWK, type JWK } from "jose";
import { canonical } from "./jws.ts";

export type Jwk = Readonly<Record<string, unknown>>;

const rsa = (jwk: Jwk) => jwk.kty === "RSA";
/** The kind of key each asymmetric algorithm verifies with. */
const fits = {
	RS256: rsa,
	RS384: rsa,
	RS512: rsa,
	PS256: rsa,
	PS384: rsa,
	PS512: rsa,
	ES256: (jwk: Jwk) => jwk.kty === "EC" && jwk.crv === "P-256",
	ES384: (jwk: Jwk) => jwk.kty === "EC" && jwk.crv === "P-384",
	ES512: (jwk: Jwk) => jwk.kty === "EC" && jwk.crv === "P-521",
	EdDSA: (jwk: Jwk) => jwk.kty === "OKP" && (jwk.crv === "Ed25519" || jwk.crv === "Ed448"),
} as const;

/** An asymmetric algorithm a public key may verify under. */
export type VerifyAlgorithm = keyof typeof fits;

/** The asymmetric algorithms a public key may verify under. */
export const verifyAlgorithms: readonly VerifyAlgorithm[] = Object.freeze(
	Object.keys(fits) as VerifyAlgorithm[],
);

export const isVerifyAlgorithm = (value: unknown): value is VerifyAlgorithm =>
	typeof value === "string" && Object.hasOwn(fits, value);

/** The members of each public key type. A Map, so no inherited name is a type. */
const membersOf: ReadonlyMap<unknown, readonly string[]> = new Map([
	["EC", ["kty", "crv", "x", "y"]],
	["OKP", ["kty", "crv", "x"]],
	["RSA", ["kty", "n", "e"]],
]);
/** Members describing a key that carry no key material. */
const describing = new Set(["kid", "alg", "use", "key_ops"]);

/** Whether each key member is base64url as its bytes encode, so one key has one JWK. */
const inOneForm = (jwk: Jwk) =>
	(membersOf.get(jwk.kty) ?? [])
		.filter((member) => member !== "kty" && member !== "crv")
		.every((member) => typeof jwk[member] !== "string" || canonical(jwk[member] as string));

const privateMembers = ["d", "p", "q", "dp", "dq", "qi", "k", "oth"];

/** A JWK the platform reads as a public key, kept as given; none with a private member, a `kid` that is no string, or a key member not in its one form. */
export function publicJwk(jwk: Jwk): { readonly jwk: Jwk; readonly key: KeyObject } | undefined {
	if (privateMembers.some((member) => Object.hasOwn(jwk, member))) return undefined;
	if (jwk.kid !== undefined && typeof jwk.kid !== "string") return undefined;
	if (!inOneForm(jwk)) return undefined;
	try {
		return { jwk, key: createPublicKey({ key: jwk as webcrypto.JsonWebKey, format: "jwk" }) };
	} catch {
		return undefined;
	}
}

function isPrivate(pem: string): boolean {
	try {
		createPrivateKey(pem);
		return true;
	} catch {
		return false;
	}
}

/** A public key written as PEM; none for anything else, a private key above all. */
export function publicPem(pem: string): KeyObject | undefined {
	// The platform reads a public key out of a private one, so a private key is refused first.
	if (isPrivate(pem)) return undefined;
	try {
		return createPublicKey(pem);
	} catch {
		return undefined;
	}
}

/**
 * Whether a JWK may verify: its `use` is `sig` and its `key_ops` hold `verify` where named, and its
 * kind and curve fit `alg` (and its own `alg` is `alg`), or, with no `alg`, any algorithm here.
 */
export function verifiesUnder(jwk: Jwk, alg?: string): boolean {
	if (jwk.use !== undefined && jwk.use !== "sig") return false;
	if (jwk.key_ops !== undefined && !(Array.isArray(jwk.key_ops) && jwk.key_ops.includes("verify")))
		return false;
	if (alg === undefined) return Object.values(fits).some((fit) => fit(jwk));
	const fit = isVerifyAlgorithm(alg) ? fits[alg] : undefined;
	return (fit?.(jwk) ?? false) && (jwk.alg === undefined || jwk.alg === alg);
}

/**
 * The JWK rebuilt from its type's public members alone; none if it holds any other member but
 * those describing it, or a member that is no string. Not read by the platform.
 */
export function publicMembers(jwk: unknown): Readonly<Record<string, string>> | undefined {
	if (typeof jwk !== "object" || jwk === null || Array.isArray(jwk)) return undefined;
	const given = jwk as Record<string, unknown>;
	const members = membersOf.get(given.kty);
	if (!members) return undefined;
	if (Object.keys(given).some((m) => !members.includes(m) && !describing.has(m))) return undefined;
	const rebuilt: Record<string, string> = {};
	for (const m of members) {
		const value = given[m];
		if (typeof value !== "string") return undefined;
		rebuilt[m] = value;
	}
	return inOneForm(rebuilt) ? rebuilt : undefined;
}

/**
 * A key's JWK thumbprint (RFC 7638), SHA-256 in base64url: of a key read (`KeyObject`), from its
 * JWK; of a JWK given, from its required members as written.
 */
export async function thumbprint(key: KeyObject | Jwk): Promise<string> {
	const jwk = key instanceof KeyObject ? await exportJWK(key) : key;
	return calculateJwkThumbprint(jwk as JWK, "sha256");
}
