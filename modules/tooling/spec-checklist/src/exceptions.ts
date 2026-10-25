import type { Decision, Item, Ledger } from "./checklist.ts";
import { classOf } from "./ids.ts";

/** An accepted difference in a run against another implementation, as its harness records it. */
export interface ExceptionEntry {
	readonly class:
		| "deviates"
		| "noncompliant"
		| "out-of-scope"
		| "adaptation"
		| "third-party"
		| "optional";
	/** The item it accepts, for an item's mark. */
	readonly item?: string;
	/** The harness's change to the requests, for an adaptation. */
	readonly adaptation?: string;
	/** The other side's issue, for a third party's fault. */
	readonly issue?: string;
	/** The spec and its section that leave a behaviour optional, for an optional one. */
	readonly spec?: string;
	readonly section?: string;
	/** The decision that chose it, for an optional one chosen on purpose. */
	readonly decision?: string;
}

/**
 * What keeps an exception from being taken: one for an item's mark names that item, marked so;
 * a deviation's is a SHOULD's with a decision the decisions hold; an adaptation's or a third party's names no item (its test's items are reached through the test)
 * and carries its name or issue.
 */
export function exceptionProblems(
	entry: ExceptionEntry,
	known: {
		readonly items: ReadonlyMap<string, Item>;
		readonly decisions: ReadonlyMap<string, Decision>;
		/** Each spec's ledger, which an optional exception is held to. */
		readonly ledgers?: ReadonlyMap<string, Ledger>;
	},
	/** The items the excused test's title names. */
	tested: readonly string[] = [],
): string[] {
	if (entry.class === "optional") return optionalProblems(entry, known, tested);
	if (entry.class === "adaptation" || entry.class === "third-party") {
		const whose = entry.class === "adaptation" ? "an adaptation's" : "a third party's";
		return [
			...(entry.item ? [`names an item, which ${whose} exception reaches through its test`] : []),
			...(entry.class === "adaptation" && !entry.adaptation ? ["names no adaptation"] : []),
			...(entry.class === "third-party" && !/^https:\/\/\S+$/.test(entry.issue ?? "")
				? ["names no issue URL at https"]
				: []),
		];
	}
	if (!entry.item) return ["names no item"];
	const item = known.items.get(entry.item);
	if (!item) return [`names ${entry.item}, which the checklist does not hold`];
	if (item.mark?.kind !== entry.class) return [`${entry.item} is not marked ${entry.class}`];
	if (item.mark.kind === "deviates" && classOf(item.strength) === "MUST")
		return [`${entry.item} is a ${item.strength}, and deviates is for a SHOULD alone`];
	if (item.mark.kind === "deviates" && !known.decisions.has(item.mark.decision))
		return [
			`${entry.item} names the decision ${item.mark.decision}, which the decisions do not hold`,
		];
	return [];
}

/**
 * An optional behaviour the provider does not give, or gives otherwise: it names a spec and section,
 * no item, a spec whose ledger the checklist holds, a decision only one the decisions hold, and its
 * test names no item a MUST or SHOULD row of that section names.
 */
function optionalProblems(
	entry: ExceptionEntry,
	known: Parameters<typeof exceptionProblems>[1],
	tested: readonly string[],
): string[] {
	if (entry.item) return ["names an item, which an optional exception reaches through its test"];
	if (!entry.spec || !entry.section) return ["names no spec and section"];
	if (!known.ledgers) return ["cannot be checked without the ledgers"];
	const ledger = known.ledgers.get(entry.spec);
	if (!ledger) return [`names ${entry.spec}, of which the checklist holds no ledger`];
	const bound = ledger.rows.flatMap((r) =>
		r.section === entry.section && r.to.kind === "items"
			? r.to.ids.filter((id) => tested.includes(id)).map((id) => ({ id, keyword: r.keyword }))
			: [],
	);
	return [
		...bound.map(
			(b) => `its test names ${b.id}, which section ${entry.section}'s ${classOf(b.keyword)} names`,
		),
		...(entry.decision && !known.decisions.has(entry.decision)
			? [`names the decision ${entry.decision}, which the decisions do not hold`]
			: []),
	];
}
