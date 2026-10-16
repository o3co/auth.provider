import { createHmac } from "node:crypto";
import { sameSecret } from "@mod/kernel";

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
/** RFC 6238's defaults, which every authenticator app supports. */
export const algorithm = "SHA1";
export const periodSeconds = 30;
export const digits = 6;

/** RFC 4648 base32, without padding. */
export function base32(bytes: Uint8Array): string {
	let bits = 0;
	let value = 0;
	let out = "";
	for (const byte of bytes) {
		value = (value << 8) | byte;
		bits += 8;
		while (bits >= 5) {
			out += alphabet[(value >>> (bits - 5)) & 31];
			bits -= 5;
		}
	}
	return bits > 0 ? out + alphabet[(value << (5 - bits)) & 31] : out;
}

function unbase32(text: string): Buffer {
	let bits = 0;
	let value = 0;
	const out: number[] = [];
	for (const char of text) {
		value = (value << 5) | alphabet.indexOf(char);
		bits += 5;
		if (bits >= 8) {
			out.push((value >>> (bits - 8)) & 255);
			bits -= 8;
		}
	}
	return Buffer.from(out);
}

/** RFC 6238 with SHA-1: the code for one time step. */
export function codeAt(secret: string, step: number): string {
	const counter = Buffer.alloc(8);
	counter.writeBigUInt64BE(BigInt(step));
	const mac = createHmac("sha1", unbase32(secret)).update(counter).digest();
	const offset = (mac[mac.length - 1] ?? 0) & 15;
	const n = (mac.readUInt32BE(offset) & 0x7fffffff) % 10 ** digits;
	return String(n).padStart(digits, "0");
}

/** The step a proof matches within one step either side, compared in constant time; none if none. */
export function matchedStep(secret: string, proof: string, now: number): number | undefined {
	if (!/^\d{6}$/.test(proof)) return undefined;
	const current = Math.floor(now / 1000 / periodSeconds);
	let found: number | undefined;
	// Every step is compared, so the time taken does not tell which one matched.
	for (const step of [current - 1, current, current + 1]) {
		const same = sameSecret(codeAt(secret, step), proof);
		if (same && found === undefined) found = step;
	}
	return found;
}
