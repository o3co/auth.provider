import type { FamilySubjects } from "@mod/claims-selection";
import type { Eraser, SubjectReading } from "@mod/erasure-extensions";
import { Unavailable } from "@mod/kernel";
import { fromStored } from "../record.ts";
import type { FamilyStore, StoredFamily } from "../store.ts";
import { portsOf } from "./ports.ts";

/**
 * Whose a family's record is, as the migration reads it: the subject it holds; a revoked mark alone,
 * an orphan by its shape, removed safely as the migration runs after the epoch lockout, with no 0.19
 * founder in flight for it to stop; anything else unreadable, as it may hold a subject's data.
 */
export const familySubjectOf: SubjectReading = async (_key, value) => {
	const kept = fromStored(value as StoredFamily);
	if (kept === undefined)
		return { kind: "unreadable", reason: "a family's record of another shape" };
	return "current" in kept ? { kind: "subject", subject: kept.subject } : { kind: "orphan" };
};

/** Whose a family is, for `claims-selection`: one confirmed change writing nothing (the card). */
export function familySubjectsIn(families: FamilyStore): FamilySubjects {
	return {
		subjectOf: async (familyId) => {
			const answered = await families.update(familyId, () => undefined);
			if (answered === undefined) return { kind: "ended" };
			const whose = await familySubjectOf(familyId, answered.before);
			if (whose.kind === "unreadable") throw new Unavailable(`refresh: ${whose.reason}`);
			return whose.kind === "subject" ? whose : { kind: "ended" };
		},
	};
}

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
