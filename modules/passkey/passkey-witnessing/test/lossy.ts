import { createHash } from "node:crypto";
import type {
	PasskeyKey,
	PasskeyKeys,
	PasskeyOp,
	PasskeyRead,
	PasskeyRecords,
	PasskeyStore,
	StoredPasskey,
} from "@mod/passkeys";
import { updatingAsOne } from "@mod/passkeys/testing";

type Space = keyof PasskeyKeys;
const hashOf = (value: string) => createHash("sha256").update(value).digest("base64url");

/** The keys passkeys keeps a subject's holder and a credential's record under. */
export const keyOf = {
	holder: (subject: string) => `s-${hashOf(subject)}`,
	record: (id: string) => `c-${hashOf(id)}`,
};

/**
 * A passkey store over `inner` that can lose what it keeps, or go back to an old copy, as a store
 * that broke its promises would. What it shows for a key (none, where lost) stands until a write
 * of that key replaces it; everything else is `inner`'s.
 */
export function lossy(inner: PasskeyStore) {
	const shown: Record<Space, Map<string, StoredPasskey | undefined>> = {
		credentials: new Map(),
		subjects: new Map(),
	};
	const view = (space: Space, key: string | undefined, raw: StoredPasskey | undefined) =>
		key !== undefined && shown[space].has(key) ? shown[space].get(key) : raw;
	type Saved = Parameters<PasskeyRecords["save"]>;
	/** The arguments each key was last saved with, so a save `put` makes again takes them whole. */
	const savedWith: Record<Space, Map<string, Saved>> = {
		credentials: new Map(),
		subjects: new Map(),
	};
	/** Writes `record` under `key` in `inner`, whatever it holds, and shows `inner` again. */
	const put = async (space: Space, key: string, record: StoredPasskey) => {
		shown[space].delete(key);
		if ((await inner[space].update(key, () => ({ value: record }))) === undefined) {
			const [, , ...rest] = savedWith[space].get(key) ?? [key, record, "endless"];
			await inner[space].save(...([key, record, ...rest] as Saved));
		}
	};
	const records = (space: Space): PasskeyRecords => ({
		read: async (key) => view(space, key, await inner[space].read(key)),
		// Its arguments forwarded whole, whatever the store's `save` takes.
		save: async (...given) => {
			const [key, record] = given;
			savedWith[space].set(key, given);
			if (!shown[space].has(key)) return inner[space].save(...given);
			if (shown[space].get(key) !== undefined) return "exists";
			await put(space, key, record);
			return "created";
		},
		update: async (key, change) => {
			if (!shown[space].has(key)) return inner[space].update(key, change);
			const before = shown[space].get(key);
			if (before === undefined) return undefined;
			const next = change(before);
			if (!next) return { before, after: before };
			await put(space, key, next.value);
			return { before, after: next.value };
		},
	});
	// The inner store's change as one; over its `updateTogether` where it offers no `updateAsOne` yet.
	const asOne =
		inner.updateAsOne?.bind(inner) ??
		(inner.updateTogether ? updatingAsOne(inner.updateTogether.bind(inner)) : undefined);
	type AsOne = Parameters<NonNullable<PasskeyStore["updateAsOne"]>>[0];
	const subjectIn = (value: StoredPasskey) => (value as { readonly subject?: unknown }).subject;
	/**
	 * An op passkeys decided on what this store shows, given to what `inner` holds, so it writes
	 * the value whatever `inner` keeps, as a store that broke its promises would be written over.
	 */
	const opOn = (op: PasskeyOp | undefined, actual: PasskeyRead): PasskeyOp | undefined => {
		if (op === undefined || op.kind === "remove") return op;
		const to = op.kind === "create" ? op.subject : op.kind === "move" ? op.to : undefined;
		if (actual === undefined) {
			const subject = to ?? subjectIn(op.value);
			return typeof subject === "string"
				? { kind: "create", value: op.value, lifetimeMs: "endless", subject }
				: op;
		}
		if (to === undefined || actual.subject === undefined || actual.subject === to) {
			return { kind: "change", value: op.value };
		}
		return { kind: "move", value: op.value, to };
	};
	const store: PasskeyStore = {
		credentials: records("credentials"),
		subjects: records("subjects"),
		updateAsOne: async (p) => {
			if (asOne === undefined) throw new Error("the inner store offers no change as one");
			let watchedKeys: readonly PasskeyKey[] = [];
			let seen: { targets: readonly PasskeyRead[]; watched: readonly PasskeyRead[] } = {
				targets: [],
				watched: [],
			};
			let given: { targets: readonly unknown[]; watched: readonly unknown[] } = {
				targets: [],
				watched: [],
			};
			const viewOf = (names: readonly PasskeyKey[], read: readonly PasskeyRead[]) =>
				read.map((actual, n): PasskeyRead => {
					const name = names[n];
					if (!name || !shown[name.place].has(name.key)) return actual;
					const value = shown[name.place].get(name.key);
					return value === undefined
						? undefined
						: { value, ...(actual?.subject === undefined ? {} : { subject: actual.subject }) };
				});
			const decided: AsOne = {
				targets: p.targets,
				...(p.watch
					? {
							watch: (read) => {
								watchedKeys = p.watch?.(viewOf(p.targets, read)) ?? [];
								return watchedKeys;
							},
						}
					: {}),
				decide: (read, watched) => {
					seen = { targets: viewOf(p.targets, read), watched: viewOf(watchedKeys, watched) };
					const next = p.decide(seen.targets, seen.watched);
					given = { targets: next.targets ?? [], watched: next.watched ?? [] };
					return {
						targets: read.map((actual, n) => opOn(next.targets?.[n], actual)),
						watched: watched.map((actual, n) => opOn(next.watched?.[n], actual)),
					};
				},
			};
			const answer = await asOne(decided);
			if (answer.kind !== "written") return answer;
			// What was given an op is `inner`'s again; the rest shows as it did.
			const remapped = (names: readonly PasskeyKey[], at: "targets" | "watched") =>
				answer[at].map((changed, n) => {
					const before = seen[at][n];
					const name = names[n];
					if (given[at][n] === undefined) return { before, after: before };
					if (name) shown[name.place].delete(name.key);
					return { before, after: changed.after };
				});
			return {
				kind: "written",
				targets: remapped(p.targets, "targets"),
				watched: remapped(watchedKeys, "watched"),
			};
		},
	};
	return {
		store,
		/** The store forgets the subject's holder, or the id's record. */
		lose: {
			holder: (subject: string) => void shown.subjects.set(keyOf.holder(subject), undefined),
			record: (id: string) => void shown.credentials.set(keyOf.record(id), undefined),
		},
		/** The subject's holder as kept now. */
		holderCopy: (subject: string) => store.subjects.read(keyOf.holder(subject)),
		/** The store goes back to `record` for the subject's holder. */
		backTo: (subject: string, record: object) =>
			void shown.subjects.set(keyOf.holder(subject), record as StoredPasskey),
	};
}
