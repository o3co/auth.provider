import { contract, type Random } from "@mod/kernel";
import { checkerWith } from "./checker.ts";
import { matches, readHash } from "./hashes.ts";

declare const madeByRead: unique symbol;
/** A stored hash, made only by `readSecretHash`; `work` names what checking against it costs, alike for equal work. */
export interface SecretHash {
	readonly work: string;
	readonly [madeByRead]: true;
}

export interface SecretChecker {
	/**
	 * Whether the secret matches the hash. Every call computes once per kind of work in use, a decoy
	 * for each kind but the hash's, so a call without a hash takes the same work as one with it.
	 * Rejects as unavailable, before any computation, while the process runs its limit of checks.
	 */
	check(hash: SecretHash | undefined, secret: string): Promise<boolean>;
}

/** Checkers made in one assembly, its `max-concurrent` shared by them all; decoys from the kernel's random. */
export interface SecretCheckers {
	checkerOf(inUse: Iterable<SecretHash>): SecretChecker;
}

export const secretCheckers = contract<SecretCheckers>("secret-hash.checkers");

/** A bcrypt or scrypt hash, or undefined for anything else, plain text included. */
export function readSecretHash(text: string): SecretHash | undefined {
	return readHash(text);
}

/** A checker for the hashes in use, with a decoy per kind of work drawn from `random`. */
export function secretChecker(inUse: Iterable<SecretHash>, random: Random["bytes"]): SecretChecker {
	return checkerWith(inUse, random, matches);
}
