import type { Eraser, MigrationReport, SpaceReport, SubjectReading } from "@mod/erasure-extensions";
import { contactSubjectOf } from "../ledger.ts";
import { linkSubjectOf } from "../links/reading.ts";
import { isNameKey, nameSubjectOf, namesKept } from "../names/elsewhere.ts";
import type { ContactStore, LinkStore } from "../store.ts";

/** Whose a record of the link space is: a name's, by its key, no subject's; else a link's. */
const linkSpaceSubjectOf: SubjectReading = async (key, value) =>
	isNameKey(key) ? nameSubjectOf(value) : linkSubjectOf(value);
const contactsSubjectOf: SubjectReading = async (key, value) => contactSubjectOf(key, value);

/**
 * users' eraser, `users`, as its spaces' `erasedBy` names it: links and contacts erased through the
 * stores' own ports. `erasable` only where the link store offers its whole set (`remove`, `erase`,
 * `migrate`, `names`, `unowned`) and the contact store its `erase` and `migrate`; one that does not
 * answers empty reports, the field carrying the fact.
 */
export function usersEraser(links: LinkStore, contacts: ContactStore): Eraser {
	const { erase: eraseLinks, migrate: migrateLinks, names } = links;
	const { erase: eraseContacts, migrate: migrateContacts } = contacts;
	if (
		!eraseLinks ||
		!migrateLinks ||
		!links.remove ||
		!names ||
		!links.unowned ||
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
				await migrateLinks.call(links, walk, linkSpaceSubjectOf, signal, namesKept(names)),
				await migrateContacts.call(contacts, walk, contactsSubjectOf, signal),
			];
			return reports;
		},
	};
}
