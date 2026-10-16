import type { Log } from "@mod/kernel";
import { keptAttributes as keeping, type SourcedAttributes } from "@mod/login-attributes";

/** A record's attributes, kept again on every read. */
export const keptAttributes = (given: unknown) => keeping(given).kept;

/**
 * What a session keeps of a login's attributes, as login-attributes keeps them, logging the names
 * it dropped: never a value, and names outside the set only as a count.
 */
export function keptAtLogin(given: unknown, log: Log): SourcedAttributes | undefined {
	const { kept, dropped, others } = keeping(given);
	if (dropped.length > 0 || others > 0) {
		log.warn("session-lifecycle.attributes_dropped", { dropped: dropped.join(","), others });
	}
	return kept;
}
