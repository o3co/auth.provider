/** Where the string starting at `at` closes. */
function closing(text: string, at: number): number {
	let end = at + 1;
	while (end < text.length && text[end] !== '"') end += text[end] === "\\" ? 2 : 1;
	return end;
}

/** Whether a JSON text, one that parses, names a member twice in one object, at any depth. */
export function repeatsName(text: string): boolean {
	// Per open object its names so far; none for an open array.
	const open: (Set<string> | undefined)[] = [];
	let atName = false;
	for (let at = 0; at < text.length; at++) {
		const c = text[at];
		if (c === "{" || c === "[") open.push(c === "{" ? new Set() : undefined);
		if (c === "}" || c === "]") open.pop();
		if (c === "{" || c === ",") atName = true;
		if (c !== '"') continue;
		const end = closing(text, at);
		const names = open.at(-1);
		if (atName && names) {
			const name: string = JSON.parse(text.slice(at, end + 1));
			if (names.has(name)) return true;
			names.add(name);
		}
		atName = false;
		at = end;
	}
	return false;
}
