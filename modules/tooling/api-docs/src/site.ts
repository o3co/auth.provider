import { readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

/** The dir a release's API is kept in: its minor's, which each patch writes over. */
export function versionDir(version: string): string {
	const release = /^(\d+)\.(\d+)\.(\d+)$/.exec(version);
	if (!release) throw new Error(`not a release version: ${version}`);
	return `v${release[1]}.${release[2]}`;
}

/** The minors a site keeps, newest first by number. */
function minorsIn(site: string): string[] {
	const numbers = (dir: string) => dir.slice(1).split(".").map(Number) as [number, number];
	return readdirSync(site, { withFileTypes: true })
		.filter((entry) => entry.isDirectory() && /^v\d+\.\d+$/.test(entry.name))
		.map((entry) => entry.name)
		.sort((a, b) => {
			const [am, an] = numbers(a);
			const [bm, bn] = numbers(b);
			return bm - am || bn - an;
		});
}

const page = (title: string, head: string, body: string) =>
	`<!DOCTYPE html>\n<html>\n<head>\n<meta charset="utf-8">\n${head}<title>${title}</title>\n</head>\n<body>\n${body}</body>\n</html>\n`;

/** Writes the root, pointing at the newest minor, and the list of every minor the site keeps. */
export function indexSite(site: string): void {
	const minors = minorsIn(site);
	const newest = minors[0];
	writeFileSync(
		join(site, "index.html"),
		newest === undefined
			? page("auth-provider API", "", "<p>No release's API is here yet.</p>\n")
			: page(
					"auth-provider API",
					`<meta http-equiv="refresh" content="0; url=${newest}/">\n`,
					`<p>The newest release's API: <a href="${newest}/">${newest}</a>. <a href="versions.html">Every release</a>.</p>\n`,
				),
	);
	const items = minors.map((minor) => `<li><a href="${minor}/">${minor}</a></li>\n`).join("");
	writeFileSync(
		join(site, "versions.html"),
		page("auth-provider API: every release", "", `<ul>\n${items}</ul>\n`),
	);
}
