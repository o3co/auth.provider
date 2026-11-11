import type { Eraser, MigrationReport, SpaceReport, SubjectReading } from "@mod/erasure-extensions";
import type { AskStore, GrantStore } from "./store.ts";

/**
 * A grant's subject, from its key (`[subject, clientId]`, grants.ts): consent's reading, so the
 * Store never opens a grant. A key in another shape proves nothing: unreadable, never an orphan,
 * as consent cannot tell an account gone from one it does not hold.
 */
export const grantSubjectOf: SubjectReading = async (key) => {
	let parsed: unknown;
	try {
		parsed = JSON.parse(key);
	} catch {
		return { kind: "unreadable", reason: "a grant key that is no JSON" };
	}
	if (
		Array.isArray(parsed) &&
		parsed.length === 2 &&
		typeof parsed[0] === "string" &&
		typeof parsed[1] === "string"
	) {
		return { kind: "subject", subject: parsed[0] };
	}
	return { kind: "unreadable", reason: "a grant key of another shape" };
};

/** Asks are bounded: a migration indexes none, so it reads none. */
const askSubjectOf: SubjectReading = async () => ({
	kind: "unreadable",
	reason: "an ask is bounded",
});

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
