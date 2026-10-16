import { type Random, Unavailable } from "@mod/kernel";
import type { SecretChecker, SecretHash } from "./contract.ts";
import { decoyOf, type Hash, hashOf } from "./hashes.ts";

/** The longest secret checked; a longer one never matches. */
const maxSecretBytes = 1024;

/** The checks under way in this process, every checker's together, and how many may be. */
export const defaultMaxConcurrent = 8;
const places = { max: defaultMaxConcurrent, taken: 0 };

/** Sets how many checks this process runs at once; the module sets it from its section. */
export function limitChecks(max: number): number {
	places.max = max;
	return max;
}

/** A checker that computes every match with `matches`; tests record the work through it. */
export function checkerWith(
	inUse: Iterable<SecretHash>,
	random: Random["bytes"],
	matches: (hash: Hash, secret: string) => Promise<boolean>,
): SecretChecker {
	const decoys = new Map<string, Hash>();
	for (const hash of inUse) {
		if (!decoys.has(hash.work)) decoys.set(hash.work, decoyOf(hashOf(hash), random));
	}
	const computed = async (hash: SecretHash | undefined, secret: string) => {
		const own = hash && hashOf(hash);
		// Started inside a promise: one that throws at once must not stop the others being waited for.
		const counted = (h: Hash) => Promise.resolve().then(() => matches(h, secret));
		const dropped = (h: Hash) => counted(h).then(() => false);
		// A hash whose work is not in use is computed besides the decoys.
		const extra = own && !decoys.has(own.work) ? [counted(own)] : [];
		// Per kind of work in use: the hash itself when it is of that kind, else that kind's decoy.
		const perWork = [...decoys].map(([work, decoy]) =>
			own?.work === work ? counted(own) : dropped(decoy),
		);
		// Every computation ends before the place is given back, even after one fails.
		const settled = await Promise.allSettled([...extra, ...perWork]);
		const failed = settled.find((s) => s.status === "rejected");
		if (failed) throw failed.reason;
		return settled.some((s) => s.status === "fulfilled" && s.value);
	};
	return {
		check: async (hash, secret) => {
			// The length is the sender's choice, so answering early tells nothing about the hash.
			if (Buffer.byteLength(secret) > maxSecretBytes) return false;
			// Refused before any computation, so a flood of checks cannot queue up work.
			if (places.taken >= places.max) throw new Unavailable("secret-hash");
			places.taken++;
			try {
				return await computed(hash, secret);
			} finally {
				places.taken--;
			}
		},
	};
}
