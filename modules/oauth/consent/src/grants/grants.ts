import type { Client } from "@mod/clients";
import { type BuildContext, Unavailable } from "@mod/kernel";
import { underOf } from "../client-section.ts";
import { type GrantStore, grantStore, type StoredGrant } from "../store.ts";

/** A grant as consent reads it: its range, and the description it was agreed under, if any. */
interface Held {
	readonly range: readonly string[];
	readonly under?: string;
}

const isRange = (value: unknown): value is readonly string[] =>
	Array.isArray(value) && value.every((entry) => typeof entry === "string");

/** Format 1 is the range alone, format 2 `{ format: 2, range, under? }`; any other is no grant. */
function heldIn(record: StoredGrant | undefined): Held | undefined {
	const kept: unknown = record;
	if (isRange(kept)) return { range: kept };
	if (typeof kept !== "object" || kept === null) return undefined;
	const { format, range, under } = kept as Record<string, unknown>;
	if (format !== 2 || !isRange(range)) return undefined;
	return typeof under === "string" ? { range, under } : { range };
}

/** Format 2, its range distinct and sorted. */
const written = (range: readonly string[], under: string | undefined) =>
	({
		format: 2,
		range: [...new Set(range)].sort(),
		...(under === undefined ? {} : { under }),
	}) as unknown as StoredGrant;

/** One key per subject and client, whatever either holds. */
const grantKey = (clientId: string, subject: string) => JSON.stringify([subject, clientId]);

/**
 * Whether a grant held counts for the client now: for one the operator registered, whatever it is
 * under; for any other, only under what the client's source says now, which it must say.
 */
const countsFor = (client: Client, held: Held) =>
	client.registered || (underOf(client) !== undefined && held.under === underOf(client));

export interface GrantsParts {
	readonly store: GrantStore;
}

/** Each subject's grants over the grant store. */
export function grantsWith({ store }: GrantsParts) {
	const heldBy = async (clientId: string, subject: string) =>
		heldIn(await store.read(grantKey(clientId, subject)));
	const rangeFor = async (client: Client, subject: string) => {
		const held = await heldBy(client.id, subject);
		return held && countsFor(client, held) ? held.range : [];
	};
	const covers = async (client: Client, subject: string, range: readonly string[]) => {
		const held = await heldBy(client.id, subject);
		if (!held || !countsFor(client, held)) return false;
		const known = new Set(held.range);
		return range.every((r) => known.has(r));
	};
	/**
	 * Under what the agreement was shown under; a range under another description is not kept beside
	 * it. `refused` where the Store answers the subject erased: nothing kept, never read as held.
	 */
	const keep = async (
		clientId: string,
		subject: string,
		range: readonly string[],
		under: string | undefined,
	): Promise<"kept" | "refused"> => {
		const key = grantKey(clientId, subject);
		const change = (record: StoredGrant) => {
			const held = heldIn(record);
			const stays = under === undefined || held?.under === under ? (held?.range ?? []) : [];
			return { value: written([...stays, ...range], under) };
		};
		if (await store.update(key, change)) return "kept";
		const saved = await store.save(key, written(range, under), "endless", subject);
		if (saved === "created") return "kept";
		if (saved === "erased") return "refused";
		// Another request saved it first: change what it saved.
		if (!(await store.update(key, change))) throw new Unavailable("consent");
		return "kept";
	};
	return {
		rangeFor,
		covers,
		keep,
		/**
		 * `grantFor`: unavailable where the subject is erased, which only a race with its erasure
		 * reaches. A stopgap: consent's contract gains a refusal answer, its callers switch, and the
		 * throw goes.
		 */
		grant: async (client: Client, subject: string, range: readonly string[]) => {
			if ((await keep(client.id, subject, range, underOf(client))) === "refused") {
				throw new Unavailable("consent");
			}
		},
	};
}

/** The grants over the store the assembly gives. */
export const grantsOver = async (c: BuildContext<unknown>) =>
	grantsWith({ store: await c.get(grantStore) });
