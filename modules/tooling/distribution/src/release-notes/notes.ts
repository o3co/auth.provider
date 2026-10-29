/** A version's heading: `## [<version>] - <when>`, the version matched as written. */
const headingOf = (line: string) => /^## \[([^\]]+)\](?: - (.*))?$/.exec(line);
const dated = /^\d{4}-\d{2}-\d{2}$/;

/**
 * The release's notes: the body of the version's section of the changelog, from its heading to the
 * next version's or the end. A version with no section, two, one not dated or one empty is refused.
 */
export function notesOf(
	changelog: string,
	version: string,
): { readonly notes: string } | { readonly problem: string } {
	const lines = changelog.split("\n");
	const at = lines.flatMap((line, i) => (headingOf(line)?.[1] === version ? [i] : []));
	const [start] = at;
	if (start === undefined) return { problem: `CHANGELOG.md has no section for ${version}` };
	if (at.length > 1) return { problem: `CHANGELOG.md has ${at.length} sections for ${version}` };
	if (!dated.test(headingOf(lines[start] ?? "")?.[2] ?? "")) {
		return { problem: `CHANGELOG.md's section for ${version} is not dated` };
	}
	const next = lines.findIndex((line, i) => i > start && headingOf(line) !== null);
	const body = lines
		.slice(start + 1, next === -1 ? undefined : next)
		.join("\n")
		.trim();
	if (body === "") return { problem: `CHANGELOG.md's section for ${version} is empty` };
	return { notes: `${body}\n` };
}
