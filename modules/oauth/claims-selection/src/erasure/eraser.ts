import type { Eraser } from "@mod/erasure-extensions";
import type { FamilySubjects } from "../contract.ts";
import type { SelectionRecords } from "../store.ts";
import { portsOf } from "./ports.ts";
import { selectionSubjectOf } from "./reading.ts";

/**
 * claims-selection's eraser, `claims-selection`, as its space's `erasedBy` names it: a subject's
 * selections erased through the store's own ports. `erasable` only where the store offers both;
 * one that does not answers empty reports, the field carrying the fact. It runs after no other.
 */
export function selectionEraser(
	records: SelectionRecords,
	families: FamilySubjects | undefined,
): Eraser {
	const ports = portsOf(records);
	if (!ports) {
		const none = { reports: [], logoutGaps: 0 };
		return {
			name: "claims-selection",
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
		name: "claims-selection",
		erasable: true,
		online,
		// Selections are indexed by their subject: no walk reaches more, so a window erases each subject.
		window: async (subjects, _walk, signal) => {
			const reports = [];
			for (const subject of subjects) reports.push(...(await online(subject, signal)).reports);
			return { reports, logoutGaps: 0 };
		},
		migrate: async (walk, signal) => [
			await ports.migrate(walk, selectionSubjectOf(families), signal),
		],
	};
}
