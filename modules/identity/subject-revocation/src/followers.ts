import type { Log } from "@mod/kernel";
import type { RevocationFollower, Revocations } from "./contract.ts";

/** Writes the boundary, and only that. */
export type Write = (subject: string, keepDelegations: boolean) => Promise<void>;

/**
 * `record` followed by each follower, one at a time in the order given. A failing follower is
 * logged by name and kind and does not stop the rest; the boundary stays, nothing retries it, and
 * the revocation answers incomplete.
 */
export function followedBy(
	write: Write,
	followers: readonly RevocationFollower[],
	log: Log,
): Revocations["record"] {
	return async (subject, options) => {
		const keepDelegations = options?.keepDelegations === true;
		await write(subject, keepDelegations);
		let complete = true;
		for (const follower of followers) {
			try {
				await follower.follow(subject, { keepDelegations });
			} catch (error) {
				complete = false;
				log.warn("subject-revocation.follower_failed", {
					follower: follower.name,
					kind: error instanceof Error ? error.name : typeof error,
				});
			}
		}
		return { complete };
	};
}
