/** Which packages a pack takes from the registry, as npm already holds them at this version, or why it cannot go on. */
import type { Lookup } from "../release/published.ts";

/** A package the release publishes: the directory it is built in, and its name. */
export interface Unit {
	readonly dir: string;
	readonly name: string;
}

/**
 * Each package npm holds at this version, to be taken from the registry with the integrity npm gave
 * it; every other is packed. The release publishes the index's bundle after every bundle its index
 * seals over, so where that bundle is on npm, each it seals over must be too: otherwise the index
 * cannot be sealed again, and a person is to look. An answer npm gave that cannot be read stops it.
 */
export function fetchPlan(
	order: { readonly first: readonly Unit[]; readonly index: Unit; readonly last: readonly Unit[] },
	lookups: ReadonlyMap<string, Lookup>,
): { readonly fetch: (Unit & { readonly integrity: string })[] } | { readonly problems: string[] } {
	const units = [...order.first, ...order.last];
	const unread = units.flatMap((u) => {
		const l = lookups.get(u.name);
		if (l === undefined) return [`${u.name}: not looked up`];
		return l.kind === "failed" ? [`${u.name}: the registry's answer is unread (${l.why})`] : [];
	});
	if (unread.length > 0) return { problems: unread };
	const on = (u: Unit) => lookups.get(u.name)?.kind === "present";
	const missing = order.first.filter((u) => !on(u));
	if (on(order.index) && missing.length > 0) {
		return {
			problems: [
				`${order.index.name} is on npm, but ${missing.map((u) => u.name).join(", ")}, which its index seals over, ${missing.length === 1 ? "is" : "are"} not: published out of order, it cannot be sealed again`,
			],
		};
	}
	return {
		fetch: units.flatMap((u) => {
			const l = lookups.get(u.name);
			return l?.kind === "present" ? [{ ...u, integrity: l.integrity }] : [];
		}),
	};
}
