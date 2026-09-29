/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/**
 * Minimum-entropy checks for operator-supplied shared secrets: the HS256 JWT
 * signing secret and the express-session cookie secret, HMAC keys in all but
 * name. A short secret is brute-forced offline, and for the JWT secret that
 * yields the ability to MINT tokens, not merely to read them.
 */

/**
 * Required key material for an HMAC-family secret, in bytes.
 *
 * 32 bytes = 256 bits = the output width of SHA-256, which is the most a
 * HS256 key can contribute. RFC 7518 §3.2 states the requirement directly:
 * "A key of the same size as the hash output ... or larger MUST be used."
 */
export const MIN_SECRET_ENTROPY_BYTES = 32;

/** Identifies the setting under check so the failure can name it. */
export interface SecretEntropyRequirement {
	/** Dotted config path, e.g. `"session.secret"`. */
	readonly configKey: string;
	/** Environment variable the shipped HOCON binds it to, e.g. `"SESSION_SECRET"`. */
	readonly envVar: string;
	/** Override for {@link MIN_SECRET_ENTROPY_BYTES}. */
	readonly minBytes?: number;
}

/** Decoded byte length if `value` is a well-formed hex string, else undefined. */
function hexByteLength(value: string): number | undefined {
	if (value.length === 0 || value.length % 2 !== 0) return undefined;
	if (!/^[0-9a-fA-F]+$/.test(value)) return undefined;
	return value.length / 2;
}

/**
 * Decoded byte length if `value` is well-formed base64 / base64url, else
 * undefined.
 *
 * Hand-rolled because Node's `Buffer.from(v, "base64")` silently drops
 * characters outside the alphabet, so it measures non-base64 strings, and
 * small, rejecting good passphrases. Padding is held to the same standard:
 * only the zero, one or two `=` the body length calls for. `"abcd="` is not
 * base64 and falls back to the raw-bytes reading; trimming any `=` run would
 * score a passphrase ending in `=` at three-quarters of its length.
 */
function base64ByteLength(value: string): number | undefined {
	// Count the trailing '=' run without assuming it is well-formed.
	const padding = value.length - value.replace(/=+$/, "").length;
	if (padding > 2) return undefined;
	const body = value.slice(0, value.length - padding);
	if (body.length === 0) return undefined;
	// Standard (`+/`) and URL-safe (`-_`) alphabets; a value mixing the two is
	// not a valid encoding in either.
	if (!/^[A-Za-z0-9+/]+$/.test(body) && !/^[A-Za-z0-9_-]+$/.test(body)) return undefined;
	const remainder = body.length % 4;
	// No base64 encoding produces a body of length ≡ 1 (mod 4).
	if (remainder === 1) return undefined;
	// When padding is present it must bring the total to a multiple of 4.
	if (padding > 0 && remainder !== 4 - padding) return undefined;
	return Math.floor((body.length * 3) / 4);
}

/**
 * Estimates how many bytes of key material a configured secret carries: the
 * SMALLEST plausible reading of the string, because that is the one an
 * attacker uses. `openssl rand -hex 16` gives 32 characters but 16 bytes; a
 * 32-character base64 body is 24 bytes. The conservative reading also suits
 * values never meant as an encoding: a 32-character `[A-Za-z0-9]` password
 * scores 24 bytes and genuinely carries only ~190 bits.
 *
 * It cannot see structure: a 40-character English sentence measures 40 bytes
 * and carries far less. The floor checks key length; it does not replace
 * generating the key randomly, which the failure message tells the operator.
 */
export function measureSecretEntropyBytes(secret: string): number {
	const candidates = [
		Buffer.byteLength(secret, "utf8"),
		hexByteLength(secret),
		base64ByteLength(secret),
	].filter((n): n is number => n !== undefined);
	return Math.min(...candidates);
}

/**
 * Operator-facing explanation for a secret that misses the floor.
 *
 * Never includes the rejected value: this message is destined for stdout, a
 * container log, and quite possibly a pasted bug report.
 */
export function describeWeakSecret(
	actualBytes: number,
	requirement: SecretEntropyRequirement,
): string {
	const minBytes = requirement.minBytes ?? MIN_SECRET_ENTROPY_BYTES;
	return (
		`${requirement.configKey} must carry at least ${minBytes} bytes ` +
		`(${minBytes * 8} bits) of key material; the configured value carries ${actualBytes}. ` +
		`Generate one with \`openssl rand -hex ${minBytes}\` and set it via ` +
		`${requirement.envVar}. ` +
		`Hex and base64 values are measured on their DECODED length, so a ` +
		`${minBytes}-character hex string counts as only ${minBytes / 2} bytes.`
	);
}

/**
 * Throw unless `secret` clears the entropy floor. Callers that need to report
 * through a different channel (a Zod issue, say) use
 * {@link measureSecretEntropyBytes} + {@link describeWeakSecret} directly.
 */
export function assertSecretEntropy(secret: string, requirement: SecretEntropyRequirement): void {
	const minBytes = requirement.minBytes ?? MIN_SECRET_ENTROPY_BYTES;
	const actualBytes = measureSecretEntropyBytes(secret);
	if (actualBytes < minBytes) {
		throw new Error(describeWeakSecret(actualBytes, requirement));
	}
}
