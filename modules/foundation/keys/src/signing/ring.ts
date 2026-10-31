import { createPrivateKey, createPublicKey, createSecretKey, type KeyObject } from "node:crypto";
import { bytesOf } from "../secret/secret.ts";
import type { AsymmetricAlg, Section } from "./section.ts";

export interface RingKey {
	readonly kid: string;
	readonly alg: string;
	readonly key: KeyObject;
	readonly expiresAt?: number;
}

export interface Ring {
	readonly signing: RingKey;
	/** The key that signs next, published among `publicKeys` too. */
	readonly next?: RingKey;
	/** Keys safe to publish: the signing key's public half (unless HS256), the previous keys and the next. */
	readonly publicKeys: readonly RingKey[];
}

/** RS256's least modulus, in bits (RFC 7518 §3.3). */
const rsaModulusFloor = 2048;

const keyTypes: Readonly<Record<AsymmetricAlg, (key: KeyObject) => boolean>> = {
	EdDSA: (key) => key.asymmetricKeyType === "ed25519",
	ES256: (key) =>
		key.asymmetricKeyType === "ec" && key.asymmetricKeyDetails?.namedCurve === "prime256v1",
	RS256: (key) =>
		key.asymmetricKeyType === "rsa" &&
		(key.asymmetricKeyDetails?.modulusLength ?? 0) >= rsaModulusFloor,
};

/** True once the key's expiry has passed; reads the clock only for keys that expire. */
export function expired(key: RingKey, now: () => number): boolean {
	return key.expiresAt !== undefined && key.expiresAt <= now();
}

function parsed(read: () => KeyObject): KeyObject | undefined {
	try {
		return read();
	} catch {
		return undefined;
	}
}

function signingKey(signing: Section["signing"]): RingKey | undefined {
	if (signing.alg === "HS256") {
		return {
			kid: signing.kid,
			alg: "HS256",
			key: createSecretKey(
				bytesOf(signing.secret, { hex: true, encoding: signing["secret-encoding"] }) ??
					Buffer.alloc(0),
			),
		};
	}
	// createPrivateKey refuses a public key, so what it reads is always private.
	const key = parsed(() => createPrivateKey(signing["private-key"]));
	if (!key || !keyTypes[signing.alg](key)) return undefined;
	return { kid: signing.kid, alg: signing.alg, key };
}

/** Returns the config path that cannot be read as a key of its alg, or the ring. */
export function readRing(section: Section): Ring | { readonly unreadable: string } {
	const signing = signingKey(section.signing);
	if (!signing) return { unreadable: "signing.private-key" };
	const publicKeys: RingKey[] =
		signing.alg === "HS256" ? [] : [{ ...signing, key: createPublicKey(signing.key) }];
	for (const [i, entry] of section.previous.entries()) {
		// The provider's own previous key: a private PEM is taken too, for its public half.
		const key = parsed(() => createPublicKey(entry["public-key"]));
		if (!key || !keyTypes[entry.alg](key)) return { unreadable: `previous.${i}.public-key` };
		publicKeys.push({
			kid: entry.kid,
			alg: entry.alg,
			key,
			expiresAt: Date.parse(entry["expires-at"]),
		});
	}
	const coming = section.next;
	if (coming === undefined) return { signing, publicKeys };
	const key = parsed(() => createPublicKey(coming["public-key"]));
	if (!key || !keyTypes[coming.alg](key)) return { unreadable: "next.public-key" };
	const next = { kid: coming.kid, alg: coming.alg, key };
	publicKeys.push(next);
	return { signing, next, publicKeys };
}
