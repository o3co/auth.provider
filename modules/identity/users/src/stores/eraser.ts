import type {
	Elsewhere,
	Eraser,
	MigrationReport,
	SpaceReport,
	SubjectReading,
} from "@mod/erasure-extensions";
import type { ContactStore, LinkStore, NameStore } from "../store.ts";
import { everyPortOffered } from "./ports.ts";

/** How each space's records are read for the one migration, and names' step, as the package composes them. */
export interface ErasureReadings {
	readonly links: SubjectReading;
	readonly contacts: SubjectReading;
	readonly namesKept: (names: NameStore) => Elsewhere;
}

/**
 * users' eraser, `users`, as its spaces' `erasedBy` names it: links and contacts erased through the
 * stores' own ports. `erasable` only where every port set is offered whole (`everyPortOffered`);
 * one that is not answers empty reports, the field carrying the fact.
 */
export function usersEraser(
	links: LinkStore,
	contacts: ContactStore,
	readings: ErasureReadings,
): Eraser {
	const { erase: eraseLinks, migrate: migrateLinks, names } = links;
	const { erase: eraseContacts, migrate: migrateContacts } = contacts;
	if (
		!everyPortOffered(links, contacts) ||
		!eraseLinks ||
		!migrateLinks ||
		!names ||
		!eraseContacts ||
		!migrateContacts
	) {
		const none = { reports: [], logoutGaps: 0 };
		return {
			name: "users",
			erasable: false,
			online: async () => none,
			window: async () => none,
			migrate: async () => [],
		};
	}
	const online = async (subject: string, signal: AbortSignal) => {
		const reports: SpaceReport[] = [
			await eraseLinks.call(links, subject, signal),
			await eraseContacts.call(contacts, subject, signal),
		];
		return { reports, logoutGaps: 0 };
	};
	return {
		name: "users",
		erasable: true,
		online,
		// Links are indexed by their subject and contacts keyed by it: no walk reaches more.
		window: async (subjects, _walk, signal) => {
			const reports: SpaceReport[] = [];
			for (const subject of subjects) reports.push(...(await online(subject, signal)).reports);
			return { reports, logoutGaps: 0 };
		},
		migrate: async (walk, signal) => {
			const reports: MigrationReport[] = [
				// A name's record goes to the name store before the link space lets it go.
				await migrateLinks.call(links, walk, readings.links, signal, readings.namesKept(names)),
				await migrateContacts.call(contacts, walk, readings.contacts, signal),
			];
			return reports;
		},
	};
}
