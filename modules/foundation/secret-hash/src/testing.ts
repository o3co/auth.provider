import { randomBytes, scryptSync } from "node:crypto";
import type { Random } from "@mod/kernel";
import bcrypt from "bcryptjs";
import { checkerWith, defaultMaxConcurrent, placesOf } from "./checker.ts";
import type { SecretChecker, SecretHash } from "./contract.ts";
import { matches, scryptBytes } from "./hashes.ts";

const toUnpaddedBase64 = (bytes: Buffer) => bytes.toString("base64").replace(/=+$/, "");

/** A bcrypt hash, by default with the cheapest work allowed. */
export function testBcryptHash(secret: string, cost = 4): string {
	return bcrypt.hashSync(secret, cost);
}

/** A scrypt hash, by default with the cheapest work allowed. */
export function testScryptHash(secret: string, ln = 10): string {
	const salt = randomBytes(16);
	const key = scryptSync(secret, salt, 32, {
		N: 2 ** ln,
		r: 8,
		p: 1,
		maxmem: 2 * scryptBytes(ln, 8),
	});
	return `$scrypt$ln=${ln},r=8,p=1$${toUnpaddedBase64(salt)}$${toUnpaddedBase64(key)}`;
}

/** A secret of exactly 72 bytes in UTF-8, made of 3-byte characters. */
export const seventyTwoBytes = "あ".repeat(24);

/** A checker as `secretCheckers` makes it, with the work of every computation recorded in order; its own limit, the default. */
export function recordingChecker(
	inUse: Iterable<SecretHash>,
	random: Random["bytes"],
): { readonly checker: SecretChecker; readonly works: readonly string[] } {
	const works: string[] = [];
	const record = (hash: Parameters<typeof matches>[0], secret: string) => {
		works.push(hash.work);
		return matches(hash, secret);
	};
	const checker = checkerWith(inUse, random, record, placesOf(defaultMaxConcurrent));
	return { checker, works };
}
