import type { Eraser, SetReading, SubjectReading } from "@mod/erasure-extensions";
import type { StoredGrant } from "../store.ts";
import type { Grant } from "./grant.ts";
import { type ErasableStores, portsOf } from "./ports.ts";

/** A grant's subject, the one its record names; a record of another shape is unreadable, as it may hold one. */
export const grantSubjectOf =
	(grantOf: (stored: StoredGrant | undefined) => Grant | undefined): SubjectReading =>
	async (_key, value) => {
		const grant = grantOf(value as StoredGrant);
		return grant === undefined
			? { kind: "unreadable", reason: "a grant's record of another shape" }
			: { kind: "subject", subject: grant.subject };
	};

/** A pending pair's subject, from its key alone (`<client>\n<subject>`: a client id holds no newline, clients' rule); a key of another form is unreadable. */
export const pairSubjectOf: SetReading = async (key) => {
	const at = key.indexOf("\n");
	const subject = at < 1 ? "" : key.slice(at + 1);
	return subject === ""
		? { kind: "unreadable", reason: "a pending pair's key of another form" }
		: { kind: "subject", subject };
};

/** A listing is keyed by its subject: its migration has none to index and calls no reading. */
const listingNotRead: SetReading = async () => ({
	kind: "unreadable",
	reason: "a listing keyed by its subject is never read",
});

/** federation-grants' eraser, `federation-grants`: a subject's grants, pending pairs and listing, through the stores' ports, as the card gives it. */
export function grantsEraser(
	stores: ErasableStores,
	grantOf: (stored: StoredGrant | undefined) => Grant | undefined,
): Eraser {
	const ports = portsOf(stores);
	if (!ports) {
		const none = { reports: [], logoutGaps: 0 };
		return {
			name: "federation-grants",
			erasable: false,
			online: async () => none,
			window: async () => none,
			migrate: async () => [],
		};
	}
	const online = async (subject: string, signal: AbortSignal) => ({
		reports: [
			await ports.grants.erase(subject, signal),
			await ports.pending.erase(subject, signal),
			await ports.subjects.erase(subject, signal),
		],
		logoutGaps: 0,
	});
	return {
		name: "federation-grants",
		erasable: true,
		online,
		// Each space is indexed by its subject: no walk reaches more, so a window erases each subject.
		window: async (subjects, _walk, signal) => {
			const reports = [];
			for (const subject of subjects) reports.push(...(await online(subject, signal)).reports);
			return { reports, logoutGaps: 0 };
		},
		migrate: async (walk, signal) => [
			await ports.grants.migrate(walk, grantSubjectOf(grantOf), signal),
			await ports.pending.migrate(walk, pairSubjectOf, signal),
			await ports.subjects.migrate(walk, listingNotRead, signal),
		],
	};
}
