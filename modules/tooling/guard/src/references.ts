import { existsSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve } from "node:path";

/** A place in a file named by its line number, in the usual forms (after a file name, an anchor, or words). */
const lineReference = /[\w.-]+\.(?:ts|js|json|md|ya?ml|xml|hocon|conf):\d+|#L\d+|\bline \d+\b/i;
const extension = /\.(?:ts|js|json|md|ya?ml|xml|hocon|conf)$/;
const linkTarget = /\]\(([^)\s]+)/g;
/**
 * A path with a directory and a file extension, or one that climbs out with `../`. A token rooted at `/` is a
 * location (a URL path or a system path), not a document reference, so it is not read; the token must start
 * right after a space, quote or bracket, so no later position inside it is read either.
 */
const pathToken =
	/(?:^|[\s`'"(])((?:\.{1,2}\/)?[\w.-]+(?:\/[\w.-]+)+\.(?:ts|js|json|md|ya?ml|xml|hocon|conf)|\.\.\/[\w./-]*)/g;

export const namesLine = (text: string) => lineReference.exec(text)?.[0];

/** References in a document to files outside its own directory, or to files that are not there. */
export function foreignFiles(path: string, text: string): string[] {
	const dir = dirname(path);
	const refs = new Set([
		...[...text.matchAll(linkTarget)]
			.map((m) => m[1] ?? "")
			.filter((t) => !/^[a-z][a-z+.-]*:/i.test(t) && !t.startsWith("#"))
			.map((t) => t.split("#")[0] ?? ""),
		...[...text.matchAll(pathToken)].map((m) => m[1] ?? ""),
	]);
	return [...refs].filter((ref) => {
		const target = resolve(dir, ref);
		const inside = relative(dir, target);
		if (inside.startsWith("..") || isAbsolute(inside)) return true;
		return extension.test(ref) && !existsSync(target);
	});
}
