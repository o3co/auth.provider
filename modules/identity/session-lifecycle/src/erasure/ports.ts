import type { SessionStore, SubjectSessions } from "../store.ts";

/** The stores' erasure ports, offered whole: the session store's and the listing's, each called on its store. */
export interface SessionPorts {
	readonly erase: Required<SessionStore>["erase"];
	readonly migrate: Required<SessionStore>["migrate"];
	readonly eraseListing: Required<SubjectSessions>["erase"];
	readonly migrateListing: Required<SubjectSessions>["migrate"];
}

/** Why the stores' ports cannot be used, or none: the one statement of the set, as the card gives it. */
export function portsRefused(kept: SessionStore, listed: SubjectSessions): string | undefined {
	const offered = [kept.erase, kept.migrate, listed.erase, listed.migrate].filter(
		(port) => port !== undefined,
	);
	if (offered.length === 0 || offered.length === 4) return undefined;
	return "the session store and the listing offer part of erase and migrate: both offer both, or neither does";
}

/** The set, where the stores offer it whole; none otherwise, `portsRefused` refusing a part at build. */
export function portsOf(kept: SessionStore, listed: SubjectSessions): SessionPorts | undefined {
	const { erase, migrate } = kept;
	const { erase: eraseListing, migrate: migrateListing } = listed;
	if (!erase || !migrate || !eraseListing || !migrateListing) return undefined;
	// Called on the store, so an implementation keeps its own `this`.
	return {
		erase: (subject, signal, eachRemoved) => erase.call(kept, subject, signal, eachRemoved),
		migrate: (walk, reading, signal) => migrate.call(kept, walk, reading, signal),
		eraseListing: (subject, signal) => eraseListing.call(listed, subject, signal),
		migrateListing: (walk, reading, signal) => migrateListing.call(listed, walk, reading, signal),
	};
}
