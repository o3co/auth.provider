import { existsSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve } from "node:path";

/** The file extensions read; the longer first, each ending the name, so `.json` is never read as `.js`. */
const known = String.raw`(?:json|js|ts|md|ya?ml|xml|hocon|conf)(?![\w-])`;
/** A place in a file named by its line number, in the usual forms (after a file name, an anchor, or words). */
const lineReference = new RegExp(String.raw`[\w.-]+\.${known}:\d+|#L\d+|\bline \d+\b`, "i");
const extension = new RegExp(String.raw`\.${known}$`);
const linkTarget = /\]\(([^)\s]+)/g;
/**
 * A path with a directory and a file extension, or one that climbs out with `../`. A token rooted at `/` is a
 * location (a URL path or a system path), not a document reference, so it is not read; the token must start
 * right after a space, quote or bracket, so no later position inside it is read either. Which tokens are the
 * repository's is decided by `inRepository`.
 */
const pathToken = new RegExp(
	String.raw`(?:^|[\s\x60'"(])((?:\.{1,2}\/)?[\w.-]+(?:\/[\w.-]+)+\.${known}|\.\.\/[\w./-]*)`,
	"g",
);

/**
 * An inline path names a file of the repository when it starts with `./` or `../`, or when its first part is an
 * entry beside the document; any other names something outside it, such as a file of a generated project.
 */
const inRepository = (dir: string, token: string) =>
	/^\.{1,2}\//.test(token) || existsSync(resolve(dir, token.split("/")[0] ?? ""));

export const namesLine = (text: string) => lineReference.exec(text)?.[0];

/** A fence opening or closing a code block, as Markdown writes one. */
const fence = /^\s*(\x60{3,}|~{3,})/;
/** The text outside fenced code blocks: a block's samples show another project's files, not this one's. */
const outsideCode = (text: string) => {
	let inside = false;
	return text
		.split("\n")
		.filter((line) => {
			if (fence.test(line)) {
				inside = !inside;
				return false;
			}
			return !inside;
		})
		.join("\n");
};

/**
 * References in a document to files outside its own directory, or to files that are not there: every link
 * target, and each inline path that names a file of the repository, outside fenced code blocks.
 */
export function foreignFiles(path: string, document: string): string[] {
	const dir = dirname(path);
	const text = outsideCode(document);
	const refs = new Set([
		...[...text.matchAll(linkTarget)]
			.map((m) => m[1] ?? "")
			.filter((t) => !/^[a-z][a-z+.-]*:/i.test(t) && !t.startsWith("#"))
			.map((t) => t.split("#")[0] ?? ""),
		...[...text.matchAll(pathToken)].map((m) => m[1] ?? "").filter((t) => inRepository(dir, t)),
	]);
	return [...refs].filter((ref) => {
		const target = resolve(dir, ref);
		const inside = relative(dir, target);
		if (inside.startsWith("..") || isAbsolute(inside)) return true;
		return extension.test(ref) && !existsSync(target);
	});
}
