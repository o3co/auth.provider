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
export declare const MIN_SECRET_ENTROPY_BYTES = 32;
/** Identifies the setting under check so the failure can name it. */
export interface SecretEntropyRequirement {
    /** Dotted config path, e.g. `"session.secret"`. */
    readonly configKey: string;
    /** Environment variable the shipped HOCON binds it to, e.g. `"SESSION_SECRET"`. */
    readonly envVar: string;
    /** Override for {@link MIN_SECRET_ENTROPY_BYTES}. */
    readonly minBytes?: number;
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
export declare function measureSecretEntropyBytes(secret: string): number;
/**
 * Operator-facing explanation for a secret that misses the floor.
 *
 * Never includes the rejected value: this message is destined for stdout, a
 * container log, and quite possibly a pasted bug report.
 */
export declare function describeWeakSecret(actualBytes: number, requirement: SecretEntropyRequirement): string;
/**
 * Throw unless `secret` clears the entropy floor. Callers that need to report
 * through a different channel (a Zod issue, say) use
 * {@link measureSecretEntropyBytes} + {@link describeWeakSecret} directly.
 */
export declare function assertSecretEntropy(secret: string, requirement: SecretEntropyRequirement): void;
//# sourceMappingURL=secretEntropy.d.mts.map