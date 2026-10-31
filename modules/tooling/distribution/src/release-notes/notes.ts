/** A version's heading: `## [<version>] - <when>`, the version matched as written. */
const headingOf = (line: string) => /^## \[([^\]]+)\](?: - (.*))?$/.exec(line);
const dated = /^\d{4}-\d{2}-\d{2}$/;
/**
 * A link's target written relative to the repository: no scheme, and not led by `#` or `/`. Any `](`
 * reads as one, in a code span, an image, `](<…>)` or `](./…)` too; a reference's `[ref]: path` does not.
 */
const relativeLink = /\]\((?![a-z][a-z\d+.-]*:|[#/])/gi;

/**
 * The release's notes: the body of the version's section of the changelog, from its heading to the
 * next version's or the end, each link relative to the repository pointed at the file in the version's
 * tag, as a release page has no repository to resolve it in. A version with no section, two, one not
 * dated or one empty is refused, and so is a workspace stating no repository, or one not a plain https URL.
 */
export function notesOf(
	changelog: string,
	version: string,
	repository: string | undefined,
): { readonly notes: string } | { readonly problem: string } {
	if (repository === undefined) return { problem: "package.json states no repository" };
	if (!repository.startsWith("https://") || repository.endsWith(".git")) {
		return {
			problem: `package.json's repository is ${repository}; state it as a plain https URL, without git+ or .git`,
		};
	}
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
	return { notes: `${body.replace(relativeLink, `](${repository}/blob/v${version}/`)}\n` };
}
