import { createHmac } from "node:crypto";
import { sameSecret } from "@mod/kernel";

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
/** The HMAC a code is made with, and the length of a new secret for it: its output's (RFC 4226 §4). */
export const algorithms = { SHA1: 20, SHA256: 32, SHA512: 64 } as const;
export type Algorithm = keyof typeof algorithms;

/** What a factor's codes are made with: fixed when it is enrolled, kept with its secret. */
export interface Parameters {
	readonly algorithm: Algorithm;
	readonly digits: number;
	readonly periodSeconds: number;
}

/** RFC 6238's defaults, which every authenticator app supports: what an unmarked secret is read with, whatever the section says. */
export const unmarked: Parameters = { algorithm: "SHA1", digits: 6, periodSeconds: 30 };

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

/**
 * The secret mfa keeps for a factor: its base32, marked `<algorithm>:<digits>:<period>:` where its
 * parameters are not 0.19's, so a factor enrolled under the defaults is kept as 0.19 kept it.
 */
export function keptSecret(parameters: Parameters, secret: string): string {
	const { algorithm, digits, periodSeconds } = parameters;
	const same =
		algorithm === unmarked.algorithm &&
		digits === unmarked.digits &&
		periodSeconds === unmarked.periodSeconds;
	return same ? secret : `${algorithm}:${digits}:${periodSeconds}:${secret}`;
}

/** A kept secret's parameters and base32: unmarked, 0.19's; a mark that does not read, none. */
export function readSecret(
	kept: string,
): { readonly parameters: Parameters; readonly secret: string } | undefined {
	const parts = kept.split(":");
	if (parts.length === 1)
		return /^[A-Z2-7]+$/.test(kept) ? { parameters: unmarked, secret: kept } : undefined;
	const [algorithm = "", digits = "", period = "", secret = ""] = parts;
	if (parts.length !== 4 || !Object.hasOwn(algorithms, algorithm)) return undefined;
	if (!/^[678]$/.test(digits) || !/^(30|60)$/.test(period) || !/^[A-Z2-7]+$/.test(secret))
		return undefined;
	const parameters = {
		algorithm: algorithm as Algorithm,
		digits: Number(digits),
		periodSeconds: Number(period),
	};
	return { parameters, secret };
}

/** RFC 6238 under the factor's parameters: the code for one time step. */
export function codeAt(parameters: Parameters, secret: string, step: number): string {
	const counter = Buffer.alloc(8);
	counter.writeBigUInt64BE(BigInt(step));
	const hash = parameters.algorithm.toLowerCase();
	const mac = createHmac(hash, unbase32(secret)).update(counter).digest();
	const offset = (mac[mac.length - 1] ?? 0) & 15;
	const n = (mac.readUInt32BE(offset) & 0x7fffffff) % 10 ** parameters.digits;
	return String(n).padStart(parameters.digits, "0");
}

/**
 * The step a proof matches within `driftSteps` either side of the current one, its length the
 * factor's and its steps the factor's period, compared in constant time; none if none.
 */
export function matchedStep(
	parameters: Parameters,
	secret: string,
	proof: string,
	now: number,
	driftSteps: number,
): number | undefined {
	if (!new RegExp(`^\\d{${parameters.digits}}$`).test(proof)) return undefined;
	const current = Math.floor(now / 1000 / parameters.periodSeconds);
	let found: number | undefined;
	const steps = Array.from({ length: 2 * driftSteps + 1 }, (_, i) => current - driftSteps + i);
	// Every step is compared, so the time taken does not tell which one matched.
	for (const step of steps) {
		const same = sameSecret(codeAt(parameters, secret, step), proof);
		if (same && found === undefined) found = step;
	}
	return found;
}
