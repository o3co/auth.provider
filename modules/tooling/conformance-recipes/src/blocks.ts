/** The marks a generated block sits between, inside a document written by hand around it. */
const opening = /<!-- generated:([a-z0-9-]+) -->\n/g;
const closing = "<!-- end generated -->";

/**
 * The document with each named block's text put between its marks, and nothing outside them
 * touched. A block the document has no marks for, marks no block is given for, a name marked twice
 * and an opening mark with no closing one are each refused, naming it.
 */
export function withBlocks(doc: string, blocks: Readonly<Record<string, string>>): string {
	const seen = new Set<string>();
	let out = "";
	let from = 0;
	for (const mark of doc.matchAll(opening)) {
		const name = mark[1] ?? "";
		const start = (mark.index ?? 0) + mark[0].length;
		if (start < from) continue;
		if (seen.has(name)) throw new Error(`generated block ${name} is marked twice`);
		seen.add(name);
		const end = doc.indexOf(closing, start);
		if (end < 0) throw new Error(`generated block ${name} has no closing mark`);
		const text = blocks[name];
		if (text === undefined) throw new Error(`generated block ${name} is given no text`);
		out += `${doc.slice(from, start)}${text.endsWith("\n") ? text : `${text}\n`}`;
		from = end;
	}
	const unmarked = Object.keys(blocks).filter((name) => !seen.has(name));
	if (unmarked.length > 0) throw new Error(`no marks for generated block ${unmarked.join(", ")}`);
	return out + doc.slice(from);
}
