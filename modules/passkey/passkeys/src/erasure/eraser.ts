import type { Eraser, SubjectOf, SubjectReading } from "@mod/erasure-extensions";
import { credentialKey, holderRead, keptOf, stored, subjectKey } from "../records/records.ts";
import type { PasskeyStore, RegistrationChallengeStore } from "../store.ts";

/** Why a read failed, by the error's name. */
const failed = (what: string, error: unknown) =>
	`${what} could not be read (${error instanceof Error ? error.name : typeof error})`;

/** A credential's subject, from its value alone: a passkey, a pending one or a removal mark is its subject's. */
const credentialSubject = (value: unknown): SubjectOf => {
	try {
		return { kind: "subject", subject: keptOf(stored(value as object)).subject };
	} catch {
		return { kind: "unreadable", reason: "a credential of another shape" };
	}
};

/** Whose a credential of the passkey store is, as the migration reads it. */
export const credentialSubjectOf: SubjectReading = async (_key, value) => credentialSubject(value);

/**
 * Whose a holder of the passkey store is, as the migration reads it. The subject it holds, where its
 * key is that subject's; else one of its credentials' subjects, where the key is that one's. A holder
 * none of whose credentials is its key's subject's reads as empty; an empty holder, which a node
 * before 0.20 made with no subject, holds no subject's data a reading can recover, as its key is a
 * hash of one no field holds: an orphan, removed. A subject that is not its key's, a holder or a
 * credential of another shape, or a read that fails: unreadable, never a holder read as empty.
 */
export const holderSubjectOf =
	(store: Pick<PasskeyStore, "credentials">): SubjectReading =>
	async (key, value) => {
		const holder = holderRead(value);
		if (!holder) return { kind: "unreadable", reason: "a holder of another shape" };
		const { subject, credentials } = holder;
		if (subject !== undefined) {
			return subjectKey(subject) === key
				? { kind: "subject", subject }
				: { kind: "unreadable", reason: "a holder whose subject is not its key's" };
		}
		for (const id of credentials) {
			let record: unknown;
			try {
				record = await store.credentials.read(credentialKey(id));
			} catch (error) {
				return { kind: "unreadable", reason: failed("a credential it lists", error) };
			}
			// Gone, as confirmed: no subject from it.
			if (record === undefined) continue;
			const owner = credentialSubject(record);
			if (owner.kind !== "subject") return owner;
			if (subjectKey(owner.subject) === key) return owner;
		}
		return { kind: "orphan" };
	};

/**
 * Registration challenges are bounded: a migration indexes none, and reads none (subject-records'
 * `migrateRecords` answers a bounded space before any read); one asked to read is a defect.
 */
const boundedReading: SubjectReading = async () => {
	throw new Error("passkeys: a registration challenge is bounded, so no migration reads one");
};

/**
 * passkeys' eraser, `passkeys`, as its spaces' `erasedBy` names it: a subject's credentials and
 * holder erased, and its registration challenges fenced, through the stores' own ports. `erasable`
 * only where the passkey store offers `erase` and `migrate` in both spaces and a registration
 * challenge store is composed offering both: without one, registration challenges, each holding its
 * subject, are kept in the challenge store, which cannot erase. Otherwise, empty reports.
 */
export function passkeysEraser(
	store: PasskeyStore,
	registrations: RegistrationChallengeStore | undefined,
): Eraser {
	const { credentials, subjects } = store;
	const ports =
		credentials.erase &&
		credentials.migrate &&
		subjects.erase &&
		subjects.migrate &&
		registrations?.erase &&
		registrations.migrate
			? {
					erase: [
						credentials.erase.bind(credentials),
						subjects.erase.bind(subjects),
						registrations.erase.bind(registrations),
					],
					credentials: credentials.migrate.bind(credentials),
					subjects: subjects.migrate.bind(subjects),
					registrations: registrations.migrate.bind(registrations),
				}
			: undefined;
	if (!ports) {
		const none = { reports: [], logoutGaps: 0 };
		return {
			name: "passkeys",
			erasable: false,
			online: async () => none,
			window: async () => none,
			migrate: async () => [],
		};
	}
	const online = async (subject: string, signal: AbortSignal) => {
		const reports = [];
		for (const erase of ports.erase) reports.push(await erase(subject, signal));
		return { reports, logoutGaps: 0 };
	};
	return {
		name: "passkeys",
		erasable: true,
		online,
		// Credentials and holders are indexed by their subject, and registration challenges fenced by
		// its tombstone: no walk reaches more, so a window erases each.
		window: async (subjects, _walk, signal) => {
			const reports = [];
			for (const subject of subjects) reports.push(...(await online(subject, signal)).reports);
			return { reports, logoutGaps: 0 };
		},
		// Credentials first: a holder is read through them.
		migrate: async (walk, signal) => [
			await ports.credentials(walk, credentialSubjectOf, signal),
			await ports.subjects(walk, holderSubjectOf(store), signal),
			await ports.registrations(walk, boundedReading, signal),
		],
	};
}
