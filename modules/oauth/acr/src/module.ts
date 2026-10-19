import { metadata } from "@mod/issuer";
import { defineModule } from "@mod/kernel";
import { logins } from "@mod/login-gates";
import { type AcrEntry, type AmrSets, acr, acrEntries, isAmrSets } from "./contract.ts";
import { section } from "./section.ts";

type Table = Readonly<Record<string, AmrSets>>;

/** The operator's table in its written order, then the entries modules offer for acr it does not name. */
async function tableOf(c: {
	collect: (point: typeof acrEntries) => Promise<readonly AcrEntry[]>;
	section: { readonly values: Table };
}): Promise<Table> {
	const table: Record<string, AmrSets> = { ...c.section.values };
	for (const entry of await c.collect(acrEntries)) {
		if (!Object.hasOwn(table, entry.acr)) table[entry.acr] = entry.sets;
	}
	return table;
}

/** The acr no declared way of logging in can meet, which would only ever answer unmet. */
const unmeetable = (table: Table, provable: { achievable(set: readonly string[]): boolean }) =>
	Object.entries(table)
		.filter(([, sets]) => !sets.some((set) => provable.achievable(set)))
		.map(([name]) => name);

export default defineModule({ name: "acr", section }, (m) => [
	m.provide(acr).by(async (c) => {
		const loose = (await c.collect(acrEntries)).filter((entry) => !isAmrSets(entry.sets));
		if (loose.length > 0) {
			const names = loose.map((entry) => entry.acr).join(", ");
			return c.refuse(
				"acr",
				`acr offered with sets that are not non-empty sets in a non-empty list: ${names}`,
			);
		}
		const table = await tableOf(c);
		const unmet = Object.keys(table).length > 0 ? unmeetable(table, await c.get(logins)) : [];
		if (unmet.length > 0) {
			// A configured acr is told by its key, never in the text; an offered one is a module's own name.
			const configured = unmet.filter((name) => Object.hasOwn(c.section.values, name));
			const offered = unmet.filter((name) => !Object.hasOwn(c.section.values, name));
			return c.refuseAll([
				...configured.map((name) => ({
					where: `acr.values.${name}`,
					reason: "no declared way of logging in can meet it",
				})),
				...(offered.length > 0
					? [
							{
								where: "acr",
								reason: `an acr a module offers has no declared way of logging in that can meet it: ${offered.join(", ")}`,
							},
						]
					: []),
			]);
		}
		return {
			known: (asked) => asked.split(" ").filter((name) => Object.hasOwn(table, name)),
			met: (known, amr) => {
				const held = new Set(amr);
				const meets = (name: string) =>
					Object.hasOwn(table, name) && table[name]?.some((set) => set.every((a) => held.has(a)));
				return known.find(meets);
			},
		};
	}),
	m.contribute(metadata).by(async (c) => {
		const offered = Object.keys(await tableOf(c));
		return { name: "acr_values_supported", value: offered.length > 0 ? offered : undefined };
	}),
]);
