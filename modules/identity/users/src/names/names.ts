import { isUnavailable, type Log, type Refusal } from "@mod/kernel";
import type { UpstreamNames } from "../contract.ts";
import { type LinkStore, type StoredLink, written } from "../store.ts";

/** A name's issuer moved, as the operator states it. */
export interface IssuerMoved {
	readonly idp: string;
	readonly from: string;
	readonly to: string;
}

type Declared = UpstreamNames["names"][number] & { readonly declaredBy: string };

const declaredIn = (declarations: readonly UpstreamNames[]): Declared[] =>
	declarations.flatMap((d) => d.names.map((n) => ({ ...n, declaredBy: d.declaredBy })));

const asDeclared = (all: readonly Pick<Declared, "declaredBy">[]) => {
	const by = [...new Set(all.map((n) => n.declaredBy))];
	return `as ${by.join(", ")} ${by.length === 1 ? "declares" : "declare"} it`;
};

/** What is refused of the names within one boot; told by the modules that declare them alone: a name and an issuer are configured values. */
export function namesRefused(declarations: readonly UpstreamNames[]): string[] {
	const declared = declaredIn(declarations);
	const empty = declared.filter((n) => n.name === "" || n.issuer === "");
	const byName = Map.groupBy(declared, (n) => n.name);
	const shared = [...byName].filter(([, all]) => new Set(all.map((n) => n.issuer)).size > 1);
	return [
		...empty.map((n) => `an IdP name or its issuer is empty, ${asDeclared([n])}`),
		...shared.map(([, all]) => `an IdP name stands for more than one issuer, ${asDeclared(all)}`),
	];
}

/** A name's key among the links': an object, where a link's is a list. */
const keyOf = (name: string) => JSON.stringify({ idp: name });
const recordOf = (issuer: string) => ({ issuer }) as unknown as StoredLink;
/** The issuer a record keeps; of another shape, an empty one, which no declared issuer equals. */
const issuerIn = (record: StoredLink) => {
	const { issuer } = record as { issuer?: unknown };
	return typeof issuer === "string" ? issuer : "";
};

/** What a boot read of the names: what it refuses, and what to write once no module refuses it. */
export interface IssuersJudged {
	readonly refusals: readonly Refusal[];
	/** Keeps each name and moves it as stated, answering what is refused of what it finds written. */
	readonly settle: () => Promise<readonly Refusal[]>;
}

/** The refusal a store that cannot answer is, never no record. */
const cannotAnswer: readonly Refusal[] = [
	{
		where: "users",
		reason: "the link store cannot answer for the issuers IdP names stand for",
	},
];
async function answeredBy<T>(run: () => Promise<T>, otherwise: T): Promise<T> {
	try {
		return await run();
	} catch (thrown) {
		if (!isUnavailable(thrown)) throw thrown;
		return otherwise;
	}
}

/**
 * Holds each declared name to the issuer kept for it, writing nothing: `settle` keeps it the first
 * time and moves it as stated. `declarations` have passed `namesRefused`, each name one issuer.
 */
export async function issuersJudged(
	declarations: readonly UpstreamNames[],
	moved: readonly IssuerMoved[],
	links: LinkStore,
	log: Pick<Log, "warn">,
): Promise<IssuersJudged> {
	const byName = Map.groupBy(declaredIn(declarations), (n) => n.name);
	const issuerOf = (name: string) => byName.get(name)?.[0]?.issuer;
	const differs = (name: string): Refusal => ({
		where: "users",
		reason: `an IdP name stands for another issuer than the one kept for it, ${asDeclared(byName.get(name) ?? [])}: use a new name, or state the move in users.issuer-moved`,
	});
	const kept = new Map<string, string | undefined>();
	const moving = new Map<string, IssuerMoved>();
	const judged = async (): Promise<readonly Refusal[]> => {
		for (const name of byName.keys()) {
			const record = await links.read(keyOf(name));
			kept.set(name, record === undefined ? undefined : issuerIn(record));
		}
		const refusals: Refusal[] = [];
		for (const [i, entry] of moved.entries()) {
			const held = kept.get(entry.idp);
			if (issuerOf(entry.idp) === entry.to && held === entry.to) continue;
			if (issuerOf(entry.idp) === entry.to && held === entry.from) {
				moving.set(entry.idp, entry);
				continue;
			}
			refusals.push({
				where: `users.issuer-moved.${i}`,
				reason:
					"the issuer kept for this IdP and the one declared are neither its from and to, nor both its to",
			});
		}
		for (const [name, held] of kept) {
			if (held !== undefined && held !== issuerOf(name) && !moving.has(name))
				refusals.push(differs(name));
		}
		return refusals;
	};
	const writeKept = async (): Promise<readonly Refusal[]> => {
		const refusals: Refusal[] = [];
		for (const [name, held] of kept) {
			const issuer = issuerOf(name) as string;
			if (held === issuer) continue;
			const move = moving.get(name);
			// Another instance may keep or move it first: what it wrote is judged as read here.
			const { after } = await written(links, keyOf(name), recordOf(issuer), (record) =>
				move && issuerIn(record) === move.from ? { value: recordOf(move.to) } : undefined,
			);
			if (issuerIn(after) !== issuer) refusals.push(differs(name));
		}
		if (refusals.length > 0) return refusals;
		for (const entry of moved) log.warn("users.issuer_moved", { idp: entry.idp });
		return [];
	};
	return {
		refusals: await answeredBy(judged, cannotAnswer),
		settle: () => answeredBy(writeKept, cannotAnswer),
	};
}
