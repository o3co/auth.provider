import { type BuildContext, Unavailable } from "@mod/kernel";
import { type GrantStore, grantStore, type StoredGrant } from "../store.ts";

/** A grant is kept as its range, distinct and sorted. */
const rangeOf = (record: StoredGrant | undefined) =>
	(record as unknown as readonly string[] | undefined) ?? [];
const grantOf = (range: readonly string[]) => [...new Set(range)].sort() as unknown as StoredGrant;
/** One key per subject and client, whatever either holds. */
const grantKey = (clientId: string, subject: string) => JSON.stringify([subject, clientId]);

export interface GrantsParts {
	readonly store: GrantStore;
}

/** Each subject's grants over the grant store. */
export function grantsWith({ store }: GrantsParts) {
	return {
		rangeFor: async (clientId: string, subject: string) =>
			rangeOf(await store.read(grantKey(clientId, subject))),
		covers: async (clientId: string, subject: string, range: readonly string[]) => {
			const record = await store.read(grantKey(clientId, subject));
			const known = new Set(rangeOf(record));
			return record !== undefined && range.every((r) => known.has(r));
		},
		widen: async (clientId: string, subject: string, range: readonly string[]) => {
			const key = grantKey(clientId, subject);
			const widen = (record: StoredGrant) => ({
				value: grantOf([...rangeOf(record), ...range]),
			});
			if (await store.update(key, widen)) return;
			if ((await store.save(key, grantOf(range), "endless")) === "created") return;
			// Another request saved it first: widen what it saved.
			if (!(await store.update(key, widen))) throw new Unavailable("consent");
		},
	};
}

/** The grants over the store the assembly gives. */
export const grantsOver = async (c: BuildContext<unknown>) =>
	grantsWith({ store: await c.get(grantStore) });
