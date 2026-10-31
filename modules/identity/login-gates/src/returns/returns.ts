import type { ReturnPath } from "../contract.ts";

/**
 * Where a login may send the browser back to: a target the operator wrote, or a path a module
 * contributed, at the public origin. A parent taking a segment below it that no segment could be
 * told apart under is refused at build.
 */
export function returnsWith(parts: {
	readonly targets: readonly string[];
	readonly origin: string | undefined;
	readonly contributed: readonly ReturnPath[];
	readonly refuse: (where: string, reason: string) => never;
}) {
	const { origin, contributed, refuse } = parts;
	const targets = new Set<string>(parts.targets);
	const paths = new Set(contributed.filter((p) => !p.segment).map((p) => p.path));
	const parents = new Set(contributed.filter((p) => p.segment).map((p) => p.path));
	// Below the root, or a path ending in a slash, a segment would be told apart by doubled slashes;
	// below an empty path, every segment at the root would match.
	for (const parent of parents) {
		if (!parent.startsWith("/") || parent === "/" || parent.endsWith("/")) {
			refuse(
				"login-gates",
				`a return path taking a segment below it is a path below the root, beginning with a slash and not ending in one: ${parent}`,
			);
		}
	}
	/** A path one name segment below a parent contributed so: never empty, a dot, or encoded. */
	const belowParent = (pathname: string) => {
		const cut = pathname.lastIndexOf("/");
		return (
			parents.has(pathname.slice(0, cut)) && /^[A-Za-z0-9_-]{1,64}$/.test(pathname.slice(cut + 1))
		);
	};
	return {
		returnAllowed: (target: string) => {
			// The URL parser drops some of these silently; a target is judged as written.
			if (/[\s\p{Cc}]/u.test(target)) return false;
			if (targets.has(target)) return true;
			const url = URL.parse(target);
			if (!url || origin === undefined || target.includes("#")) return false;
			const known = paths.has(url.pathname) || belowParent(url.pathname);
			// Written as the public origin and the path itself, to the query: no userinfo, port or other
			// origin, and nothing the URL parser rewrites (dot segments, backslashes) on the way.
			const written = target.slice(0, target.includes("?") ? target.indexOf("?") : undefined);
			return known && written === `${origin}${url.pathname}`;
		},
	};
}
