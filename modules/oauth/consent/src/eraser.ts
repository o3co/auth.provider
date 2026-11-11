import type { Eraser, MigrationReport, SpaceReport, SubjectReading } from "@mod/erasure-extensions";
import { grantSubjectOf } from "./grants/grants.ts";
import type { AskStore, GrantStore } from "./store.ts";

/** Asks are bounded: a migration indexes none, and reads none; one asked to read is a defect. */
const askSubjectOf: SubjectReading = async () => {
	throw new Error("consent: an ask is bounded, so no migration reads one");
};

/**
 * consent's eraser, `consent`, as its spaces' `erasedBy` names it: its grants erased and its asks
 * fenced through the Stores' own ports. `erasable` only where both Stores offer `erase` and
 * `migrate`; one that does not answers empty reports, the field carrying the fact.
 */
export function consentEraser(grants: GrantStore, asks: AskStore): Eraser {
	const { erase: eraseGrants, migrate: migrateGrants } = grants;
	const { erase: eraseAsks, migrate: migrateAsks } = asks;
	if (!eraseGrants || !migrateGrants || !eraseAsks || !migrateAsks) {
		const none = { reports: [], logoutGaps: 0 };
		return {
			name: "consent",
			erasable: false,
			online: async () => none,
			window: async () => none,
			migrate: async () => [],
		};
	}
	const online = async (subject: string, signal: AbortSignal) => {
		const reports: SpaceReport[] = [
			await eraseGrants.call(grants, subject, signal),
			await eraseAsks.call(asks, subject, signal),
		];
		return { reports, logoutGaps: 0 };
	};
	return {
		name: "consent",
		erasable: true,
		online,
		// The grants are indexed and the asks bounded, so no walk reaches anything the index does not.
		window: async (subjects, _walk, signal) => {
			const reports: SpaceReport[] = [];
			for (const subject of subjects) reports.push(...(await online(subject, signal)).reports);
			return { reports, logoutGaps: 0 };
		},
		migrate: async (walk, signal) => {
			const reports: MigrationReport[] = [
				await migrateGrants.call(grants, walk, grantSubjectOf, signal),
				await migrateAsks.call(asks, walk, askSubjectOf, signal),
			];
			return reports;
		},
	};
}
