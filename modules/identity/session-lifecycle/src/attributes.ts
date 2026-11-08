import type { Log } from "@mod/kernel";
import { type AttributeCaps, keepingWith, type SourcedAttributes } from "@mod/login-attributes";

/** A session's keeping of a login's attributes, as login-attributes keeps them under `caps`. */
export function attributesUnder(caps: AttributeCaps) {
	const keeping = keepingWith(caps);
	return {
		/** A record's attributes, kept again on every read. */
		read: (given: unknown) => keeping(given).kept,
		/** What a session keeps at login, logging the names dropped: never a value, names outside the set as a count. */
		atLogin: (given: unknown, log: Log): SourcedAttributes | undefined => {
			const { kept, dropped, others } = keeping(given);
			if (dropped.length > 0 || others > 0) {
				log.warn("session-lifecycle.attributes_dropped", { dropped: dropped.join(","), others });
			}
			return kept;
		},
	};
}

/** The keeping a session gives a login's attributes. */
export type AttributesKeeping = ReturnType<typeof attributesUnder>;
