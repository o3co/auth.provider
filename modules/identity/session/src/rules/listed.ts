import { Unavailable } from "@mod/kernel";
import type { Sessions } from "../contract.ts";

/** Closes each listed session of the subject, one at a time; one that fails or is left pending stays listed and does not stop the rest. */
export async function closeListed(
	subject: string,
	listed: { members(subject: string): Promise<readonly { readonly member: string }[]> },
	close: (handle: string) => ReturnType<Sessions["close"]>,
): Promise<void> {
	let unfinished = 0;
	for (const { member } of await listed.members(subject)) {
		try {
			if ((await close(member)).kind === "pending") unfinished++;
		} catch {
			unfinished++;
		}
	}
	// Work left for later fails the follower, so the revocation answers incomplete; the boundary still refuses.
	if (unfinished > 0) throw new Unavailable("session");
}
