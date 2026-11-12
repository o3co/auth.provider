import type { Eraser, SetReading, SubjectReading } from "@mod/erasure-extensions";
import { fromStored } from "../lifecycle/record.ts";
import type { SessionStore, StoredSession, SubjectSessions } from "../store.ts";
import { portsOf } from "./ports.ts";

/**
 * Whose a session's record is, as the migration reads it: the subject it holds; a closed mark alone
 * (holding no subject, 0.19's raw shape), an orphan by its shape; anything else unreadable, as it
 * may hold a subject's data.
 */
export const sessionSubjectOf: SubjectReading = async (_key, value) => {
	const record = fromStored(value as StoredSession);
	if (record === undefined)
		return { kind: "unreadable", reason: "a session's record of another shape" };
	return "subject" in record ? { kind: "subject", subject: record.subject } : { kind: "orphan" };
};

/** The listing's reading, never asked: a listing keyed by its subject has nothing to migrate. */
const listingUnread: SetReading = async () => ({
	kind: "unreadable",
	reason: "a listing keyed by its subject is never read",
});

/** Whether a removed record was a session whose participants were never told: open, closing, or unreadable (counted high). */
const untold = (record: StoredSession) => {
	const read = fromStored(record);
	return read === undefined || read.state !== "closed";
};

/**
 * session-lifecycle's eraser, `session-lifecycle`, as its spaces' `erasedBy` names it: a subject's
 * sessions and listing erased through the stores' own ports, each open, closing or unreadable
 * session removed counted as a logout gap. `erasable` only where the stores offer their ports whole;
 * where they do not, empty reports, the field carrying the fact.
 */
export function sessionEraser(kept: SessionStore, listed: SubjectSessions): Eraser {
	const ports = portsOf(kept, listed);
	if (!ports) {
		const none = { reports: [], logoutGaps: 0 };
		return {
			name: "session-lifecycle",
			erasable: false,
			online: async () => none,
			window: async () => none,
			migrate: async () => [],
		};
	}
	const online = async (subject: string, signal: AbortSignal) => {
		let logoutGaps = 0;
		const sessions = await ports.erase(subject, signal, (record) => {
			if (untold(record)) logoutGaps += 1;
		});
		const listing = await ports.eraseListing(subject, signal);
		return { reports: [sessions, listing], logoutGaps };
	};
	return {
		name: "session-lifecycle",
		erasable: true,
		online,
		// Sessions are indexed and listed by their subject: no walk reaches more, so a window erases each.
		window: async (subjects, _walk, signal) => {
			const reports = [];
			let logoutGaps = 0;
			for (const subject of subjects) {
				const erased = await online(subject, signal);
				reports.push(...erased.reports);
				logoutGaps += erased.logoutGaps;
			}
			return { reports, logoutGaps };
		},
		migrate: async (walk, signal) => [
			await ports.migrate(walk, sessionSubjectOf, signal),
			await ports.migrateListing(walk, listingUnread, signal),
		],
	};
}
