import { readFileSync } from "node:fs";
import { type ExceptionEntry, exceptionProblems } from "@mod/spec-checklist";

/** An accepted difference: where it is met (library, flow, check), its class and why. */
export interface Difference extends ExceptionEntry {
	readonly library: string;
	readonly flow: string;
	/** The title of the check it excuses, as written. */
	readonly check: string;
	readonly reason: string;
}

type Known = Parameters<typeof exceptionProblems>[1];

/** The differences the file holds, each held to the exceptions' rules; any it breaks are refused together. */
export function differencesIn(text: string, known: Known): Difference[] {
	const read = (JSON.parse(text) as { differences?: unknown }).differences;
	if (!Array.isArray(read)) throw new Error("known differences: no list of differences");
	const differences = read as Difference[];
	const problems = differences.flatMap((d, k) => {
		const at = `difference ${k} (${d.library} ${d.flow} "${d.check}")`;
		const narrow = [d.library, d.flow, d.check, d.reason].every(
			(v) => typeof v === "string" && v !== "",
		)
			? []
			: [`${at}: names no library, flow, check or reason`];
		return [...narrow, ...exceptionProblems(d, known).map((p) => `${at}: ${p}`)];
	});
	if (problems.length > 0) throw new Error(`known differences:\n${problems.join("\n")}`);
	return differences;
}

export const readDifferences = (file: string, known: Known) =>
	differencesIn(readFileSync(file, "utf8"), known);

/** The differences of one library's run, which tells the ones its checks met and the ones none did. */
export function differencesOf(differences: readonly Difference[], library: string) {
	const mine = differences.filter((d) => d.library === library);
	const met = new Set<Difference>();
	return {
		/** The difference that excuses this check's failure, marked met; none where it has none. */
		excusing(flow: string, check: string): Difference | undefined {
			const found = mine.find((d) => d.flow === flow && d.check === check);
			if (found) met.add(found);
			return found;
		},
		/** The differences no check met: each one fixed, or written wrong. */
		unmet: () => mine.filter((d) => !met.has(d)),
	};
}
