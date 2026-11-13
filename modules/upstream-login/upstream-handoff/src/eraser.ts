import type { Eraser, SubjectReading } from "@mod/erasure-extensions";
import { portsOf } from "./ports.ts";
import type { HeldLoginStore } from "./store.ts";

/** Held logins are bounded: a migration indexes none, and reads none; one asked to read is a defect. */
const heldSubjectOf: SubjectReading = async () => {
	throw new Error("upstream-handoff: a held login is bounded, so no migration reads one");
};

/**
 * upstream-handoff's eraser, `upstream-handoff`, as its space's `erasedBy` names it: a subject's held
 * logins fenced through the Store's own ports. `erasable` only where the Store offers `erase` and
 * `migrate`; one that does not answers empty reports, the field carrying the fact.
 */
export function heldLoginEraser(held: HeldLoginStore): Eraser {
	const ports = portsOf(held);
	if (!ports) {
		const none = { reports: [], logoutGaps: 0 };
		return {
			name: "upstream-handoff",
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
		name: "upstream-handoff",
		erasable: true,
		online,
		// Bounded: no walk reaches a held login the fence does not, so a window fences each subject.
		window: async (subjects, _walk, signal) => {
			const reports = [];
			for (const subject of subjects) reports.push(...(await online(subject, signal)).reports);
			return { reports, logoutGaps: 0 };
		},
		migrate: async (walk, signal) => [await ports.migrate(walk, heldSubjectOf, signal)],
	};
}
