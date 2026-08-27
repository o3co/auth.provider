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
 * Minimum-entropy checks for operator-supplied shared secrets (#282).
 *
 * Two secrets in this library are HMAC keys in everything but name — the
 * HS256 JWT signing secret and the express-session cookie signing secret —
 * and before #282 both were accepted at any non-zero length. A one-character
 * secret is trivially brute-forced offline, and for the JWT secret that
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
 * Decoded byte length if `value` is a well-formed base64 / base64url string,
 * else undefined.
 *
 * Deliberately hand-rolled rather than delegated to `Buffer.from(v, "base64")`:
 * Node's decoder is lenient — it silently drops characters outside the
 * alphabet — so `Buffer.from("not a secret!!", "base64").length` answers for a
 * string that is not base64 at all, and answers *small*, which would reject
 * perfectly good passphrases.
 *
 * Padding is held to the same standard as the alphabet. An encoder emits zero,
 * one or two `=`, and only where the body length calls for it: one after a
 * 3-character final group, two after a 2-character one. `"abcd===="` and
 * `"abcd="` are therefore not base64 at all, and this returns undefined for
 * them so `measureSecretEntropyBytes` falls back to the raw-bytes reading.
 * Trimming any run of `=` would instead turn a passphrase that merely ends in
 * equals signs into a "valid" base64 body and score it three-quarters of its
 * real length — fail-closed, but a usability trap with no security to show
 * for it.
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
 * Estimate how many bytes of key material a configured secret actually
 * carries.
 *
 * The answer is the SMALLEST plausible reading of the string, because that is
 * the one an attacker gets to use. `openssl rand -hex 16` produces a
 * 32-*character* value that is only 16 *bytes* of randomness; counting its
 * characters would wave through a key with half the intended strength. The
 * same reasoning applies to base64: a 32-character base64 body is 24 bytes.
 *
 * The conservative reading is also right for values that were never meant as
 * an encoding. A 32-character password drawn from `[A-Za-z0-9]` reads as
 * base64 here and scores 24 bytes — and it genuinely carries only ~190 bits,
 * because 62 possibilities per character is ~5.95 bits, not 8. Treating
 * printable-ASCII characters as a full byte each is the optimistic error, and
 * this function does not make it.
 *
 * What it cannot see is structure: a 40-character English sentence measures
 * 40 bytes and carries far less. The floor is a check on key *length*, not a
 * substitute for generating the key randomly — which is what the failure
 * message tells the operator to do.
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
