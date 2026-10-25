import type { Decision, Item } from "./checklist.ts";
import { classOf } from "./ids.ts";

/** An accepted difference in a run against another implementation, as its harness records it. */
export interface ExceptionEntry {
	readonly class: "deviates" | "noncompliant" | "out-of-scope" | "adaptation" | "third-party";
	/** The item it accepts, for an item's mark. */
	readonly item?: string;
	/** The harness's change to the requests, for an adaptation. */
	readonly adaptation?: string;
	/** The other side's issue, for a third party's fault. */
	readonly issue?: string;
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
	},
): string[] {
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
