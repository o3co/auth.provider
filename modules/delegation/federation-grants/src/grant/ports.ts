import type { GrantStore, PendingIntents, SubjectGrants } from "../store.ts";

export interface ErasedStores {
	readonly grants: GrantStore;
	readonly pending: PendingIntents;
	readonly subjects: SubjectGrants;
}

/** Each store's erasure ports, offered whole, each called on its store, of the three holding a subject's data. */
export interface StorePorts {
	readonly grants: Required<Pick<GrantStore, "erase" | "migrate">>;
	readonly pending: Required<Pick<PendingIntents, "erase" | "migrate">>;
	readonly subjects: Required<Pick<SubjectGrants, "erase" | "migrate">>;
}

const portsIn = (stores: ErasedStores) =>
	[stores.grants, stores.pending, stores.subjects].flatMap((one) => [one.erase, one.migrate]);

/** Why the stores' ports cannot be used, or none: the one statement of the set, as the card gives it. */
export function portsRefused(stores: ErasedStores): string | undefined {
	const offered = portsIn(stores).filter((port) => port !== undefined).length;
	if (offered === 0 || offered === 6) return undefined;
	return "the grant, pending and subject stores offer part of their erase and migrate: all six, or none";
}

/** The set, where the stores offer it whole; none otherwise, `portsRefused` refusing a part at build. */
export function portsOf(stores: ErasedStores): StorePorts | undefined {
	const { grants, pending, subjects } = stores;
	if (!grants.erase || !grants.migrate || !pending.erase || !pending.migrate) return undefined;
	if (!subjects.erase || !subjects.migrate) return undefined;
	const [ge, gm, pe, pm, se, sm] = [
		grants.erase,
		grants.migrate,
		pending.erase,
		pending.migrate,
		subjects.erase,
		subjects.migrate,
	];
	return {
		grants: {
			erase: (subject, signal) => ge.call(grants, subject, signal),
			migrate: (walk, reading, signal) => gm.call(grants, walk, reading, signal),
		},
		pending: {
			erase: (subject, signal) => pe.call(pending, subject, signal),
			migrate: (walk, reading, signal) => pm.call(pending, walk, reading, signal),
		},
		subjects: {
			erase: (subject, signal) => se.call(subjects, subject, signal),
			migrate: (walk, reading, signal) => sm.call(subjects, walk, reading, signal),
		},
	};
}
