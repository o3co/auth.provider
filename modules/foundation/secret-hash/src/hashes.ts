import { scrypt } from "node:crypto";
import { type Random, sameSecret } from "@mod/kernel";
import bcrypt from "bcryptjs";
import type { SecretHash } from "./contract.ts";

export type Hash = SecretHash &
	(
		| { readonly format: "bcrypt"; readonly text: string; readonly cost: number }
		| {
				readonly format: "scrypt";
				readonly ln: number;
				readonly r: number;
				readonly p: number;
				readonly salt: Buffer;
				readonly key: Buffer;
		  }
	);

/**
 * bcrypt's text: the salt's 22nd character has 4 unused low bits and the hash's 31st 2, which must be
 * zero, so one hash has one text.
 */
const bcryptShape =
	/^\$2[aby]\$(\d{2})\$[./A-Za-z0-9]{21}[.Oeu][./A-Za-z0-9]{30}[.CGKOSWaeimquy26]$/;
const scryptShape = /^\$scrypt\$ln=(\d+),r=(\d+),p=(\d+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$/;
/** The highest bcrypt cost read, so a stored hash cannot make each check or the boot take too long. */
const bcryptMaxCost = 14;
/** The most bytes of scrypt's large buffer read, for the same reason. */
const scryptMaxBytes = 128 * 1024 * 1024;
const within = (n: number, min: number, max: number) => n >= min && n <= max;
/** The bytes of canonical unpadded base64, or undefined: Buffer.from skips stray characters and loose final bits. */
const unpaddedBase64Bytes = (text: string) => {
	const bytes = Buffer.from(text, "base64");
	return bytes.toString("base64").replace(/=+$/, "") === text ? bytes : undefined;
};

/** The bytes of scrypt's large buffer, 128·N·r; the card's limit per run is on this. */
export const scryptBytes = (ln: number, r: number) => 128 * 2 ** ln * r;

/** The hash behind a SecretHash; every SecretHash is made by readHash. */
export const hashOf = (hash: SecretHash) => hash as Hash;

/** A stored hash, or undefined for anything else, plain text included; the only maker of a SecretHash. */
export function readHash(text: string): Hash | undefined {
	const b = bcryptShape.exec(text);
	if (b) {
		const cost = Number(b[1]);
		if (cost < 4 || cost > bcryptMaxCost) return undefined;
		return { format: "bcrypt", text, cost, work: `bcrypt:${cost}` } as Hash;
	}
	const s = scryptShape.exec(text);
	if (!s) return undefined;
	const [ln, r, p] = [Number(s[1]), Number(s[2]), Number(s[3])];
	const salt = unpaddedBase64Bytes(s[4] ?? "");
	const key = unpaddedBase64Bytes(s[5] ?? "");
	// Node's scrypt rejects an N of 2^(16·r) or more.
	const runs = ln < 16 * r;
	const fits = ln >= 10 && r >= 1 && p >= 1 && p <= 2 && scryptBytes(ln, r) <= scryptMaxBytes;
	// scrypt's time grows with the salt and key length, and every check pays for each work in use.
	const sized = salt && key && within(salt.length, 16, 64) && within(key.length, 32, 64);
	if (!runs || !fits || !sized) return undefined;
	const work = `scrypt:${ln},${r},${p},${key.length}`;
	return { format: "scrypt", ln, r, p, salt, key, work } as Hash;
}

/** A hash of a random secret with the same work as `like`, every random byte drawn from `random`. */
export function decoyOf(like: Hash, random: Random["bytes"]): Hash {
	if (like.format === "bcrypt") {
		const secret = Buffer.from(random(16)).toString("hex");
		// A salt given as text, so bcrypt draws nothing itself.
		const salt = `$2b$${String(like.cost).padStart(2, "0")}$${bcrypt.encodeBase64(random(16), 16)}`;
		return readHash(bcrypt.hashSync(secret, salt)) as Hash;
	}
	return {
		...like,
		salt: Buffer.from(random(like.salt.length)),
		key: Buffer.from(random(like.key.length)),
	};
}

export async function matches(hash: Hash, secret: string): Promise<boolean> {
	if (hash.format === "bcrypt") {
		const same = await bcrypt.compare(secret, hash.text);
		// bcrypt would read only the first 72 bytes, so a longer secret never matches.
		return same && !bcrypt.truncates(secret);
	}
	// A ceiling, not an allocation: scrypt takes 128·r·(N + 2) + 128·r·p bytes.
	const maxmem = 2 * scryptBytes(hash.ln, hash.r) * hash.p;
	const derived = await new Promise<Buffer>((resolve, reject) =>
		scrypt(
			secret,
			hash.salt,
			hash.key.length,
			{ N: 2 ** hash.ln, r: hash.r, p: hash.p, maxmem },
			(error, key) => (error ? reject(error) : resolve(key)),
		),
	);
	return sameSecret(derived, hash.key);
}
