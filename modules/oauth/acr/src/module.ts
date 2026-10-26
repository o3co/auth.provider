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

export default defineModule({ name: "acr", section, takes: [acrEntries, logins] }, (m) => [
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
		// Taken whatever the table holds: login-gates is composed wherever acr is (its dependency).
		const provable = await c.get(logins);
		const unmet = Object.keys(table).length > 0 ? unmeetable(table, provable) : [];
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
		/** The first of these acr, in their order, whose one set the amr hold whole. */
		const firstMet = (names: readonly string[], amr: readonly string[]) => {
			const held = new Set(amr);
			const meets = (name: string) =>
				Object.hasOwn(table, name) && table[name]?.some((set) => set.every((a) => held.has(a)));
			return names.find(meets);
		};
		return {
			known: (asked) => asked.split(" ").filter((name) => Object.hasOwn(table, name)),
			met: firstMet,
			current: (amr) => firstMet(Object.keys(table), amr),
		};
	}),
	m.contribute(metadata).by(async (c) => {
		const offered = Object.keys(await tableOf(c));
		return { name: "acr_values_supported", value: offered.length > 0 ? offered : undefined };
	}),
]);
