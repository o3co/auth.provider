/** Words that may join laid-out values; any other word between two values ends the run. */
const joining = new Set(["and", "or", "then"]);

/** The longest run of a list's consecutive values that a line lays out in order, no other word between. */
export function laidOut(line: string, list: readonly string[]): string[] {
	const text = line.toLowerCase();
	let best: string[] = [];
	let run: string[] = [];
	let at = -1;
	for (const word of text.matchAll(/[a-z][a-z0-9-]*/g)) {
		if (joining.has(word[0])) continue;
		const index = list.indexOf(word[0]);
		run = index < 0 ? [] : index === at + 1 ? [...run, word[0]] : [word[0]];
		at = index;
		if (run.length > best.length) best = run;
	}
	return best;
}
