import type { Eraser, SubjectReading } from "@mod/erasure-extensions";
import { fromStored } from "../record.ts";
import type { FamilyStore, StoredFamily } from "../store.ts";
import { portsOf } from "./ports.ts";

/**
 * Whose a family's record is, as the migration reads it: a family's subject, the one it holds; a
 * revoked mark, `{ format: 1, revoked: true }` and nothing else, holds no subject's data, an orphan
 * by its shape; anything else is unreadable, as it may hold a subject's data.
 */
export const familySubjectOf: SubjectReading = async (_key, value) => {
	const kept = fromStored(value as StoredFamily);
	if (kept === undefined)
		return { kind: "unreadable", reason: "a family's record of another shape" };
	return "current" in kept ? { kind: "subject", subject: kept.subject } : { kind: "orphan" };
};

/**
 * refresh's eraser, `refresh`, as its space's `erasedBy` names it: a subject's families erased through
 * the family store's own ports. `erasable` only where the store offers its ports whole; one that
 * does not answers empty reports, the field carrying the fact.
 */
export function familyEraser(families: FamilyStore): Eraser {
	const ports = portsOf(families);
	if (!ports) {
		const none = { reports: [], logoutGaps: 0 };
		return {
			name: "refresh",
			erasable: false,
			online: async () => none,
			window: async () => none,
			migrate: async () => [],
		};
	}
	const online = async (subject: string, signal: AbortSignal) => ({
		reports: [await ports.erase(subject, signal)],
		logoutGaps: 0,
	});
	return {
		name: "refresh",
		erasable: true,
		online,
		// Families are indexed by their subject: no walk reaches more, so a window erases each subject.
		window: async (subjects, _walk, signal) => {
			const reports = [];
			for (const subject of subjects) reports.push(...(await online(subject, signal)).reports);
			return { reports, logoutGaps: 0 };
		},
		migrate: async (walk, signal) => [await ports.migrate(walk, familySubjectOf, signal)],
	};
}
