import type { Eraser, SubjectReading } from "@mod/erasure-extensions";
import { type ErasableStores, portsOf } from "./ports.ts";

/** Codes and redemption records are bounded: a migration indexes none, and reads none; one asked to read is a defect. */
const noneRead: SubjectReading = async () => {
	throw new Error(
		"code-grant: codes and redemption records are bounded, so no migration reads one",
	);
};

/**
 * code-grant's eraser, `code-grant`, as its spaces' `erasedBy` names it: a subject's codes and
 * redemption records fenced through the places' own ports. `erasable` only where both offer `erase`
 * and `migrate`; where neither does, it answers empty reports, the field carrying the fact.
 */
export function codeGrantEraser(stores: ErasableStores): Eraser {
	const ports = portsOf(stores);
	if (!ports) {
		const none = { reports: [], logoutGaps: 0 };
		return {
			name: "code-grant",
			erasable: false,
			online: async () => none,
			window: async () => none,
			migrate: async () => [],
		};
	}
	const online = async (subject: string, signal: AbortSignal) => ({
		reports: [await ports.codes.erase(subject, signal), await ports.kept.erase(subject, signal)],
		logoutGaps: 0,
	});
	return {
		name: "code-grant",
		erasable: true,
		online,
		// Bounded: no walk reaches a record the fence does not, so a window fences each subject.
		window: async (subjects, _walk, signal) => {
			const reports = [];
			for (const subject of subjects) reports.push(...(await online(subject, signal)).reports);
			return { reports, logoutGaps: 0 };
		},
		migrate: async (walk, signal) => [
			await ports.codes.migrate(walk, noneRead, signal),
			await ports.kept.migrate(walk, noneRead, signal),
		],
	};
}
