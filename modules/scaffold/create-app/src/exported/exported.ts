/** Whether a package's `exports` gives a subpath node would load for an app's import, read as node's resolver reads it. */

type Json = Record<string, unknown>;
const isObject = (value: unknown): value is Json =>
	value !== null && typeof value === "object" && !Array.isArray(value);

/** The conditions an app's import of a module meets, in node: the first of these a target names is taken. */
const conditions = new Set(["node", "import", "module-sync", "node-addons", "default"]);

/** A key node takes for an array index: conditions holding one are an invalid package configuration. */
const arrayIndex = (key: string) => /^(0|[1-9][0-9]*)$/.test(key) && Number(key) < 2 ** 32 - 1;

/** A segment node refuses in a target's path: empty, `.`, `..` or `node_modules`, written plainly or %-encoded (its own rule). */
const invalidSegment =
	/(^|\\|\/)((\.|%2e)(\.|%2e)?|(n|%6e|%4e)(o|%6f|%4f)(d|%64|%44)(e|%65|%45)(_|%5f)(m|%6d|%4d)(o|%6f|%4f)(d|%64|%44)(u|%75|%55)(l|%6c|%4c)(e|%65|%45)(s|%73|%53))?(\\|\/|$)/i;

/** Where a target is resolved from: the package's directory, as a URL. */
const packageRoot = "file:///package";

/**
 * What node makes of an export's target for an app's import, as its resolver does: a path inside
 * the package (`./`, no segment it refuses, inside it once normalized; its path decoding, with no encoded separator), a target blocked (null, a path
 * it refuses, or conditions with an array index's key, which node refuses whole), or none met
 * (conditions none of which apply, so node goes on to the next). An array is refused.
 */
function targetOf(target: unknown): "usable" | "blocked" | "unmet" {
	if (typeof target === "string") {
		if (!target.startsWith("./") || invalidSegment.test(target.slice(2))) return "blocked";
		// As node resolves it, under the package: it stays there once normalized (a tab or a line
		// break is dropped, and may make a `..`), its path holds no encoded separator, and decodes.
		const { pathname } = new URL(target, `${packageRoot}/`);
		if (!pathname.startsWith(`${new URL(packageRoot).pathname}/`)) return "blocked";
		if (/%2f|%5c/i.test(pathname)) return "blocked";
		try {
			decodeURIComponent(pathname);
		} catch {
			return "blocked";
		}
		return "usable";
	}
	if (!isObject(target) || Object.keys(target).some(arrayIndex)) return "blocked";
	for (const [condition, inner] of Object.entries(target)) {
		if (!conditions.has(condition)) continue;
		const met = targetOf(inner);
		if (met !== "unmet") return met;
	}
	return "unmet";
}

/** Whether `exports` (a package manifest's) maps `subpath` to a target node loads for an app's import. No package code is run. */
export function loadsSubpath(exports: unknown, subpath: string): boolean {
	if (!isObject(exports)) return false;
	// Subpaths and conditions together at the top are a configuration node refuses whole.
	const keys = Object.keys(exports);
	if (keys.some((key) => key.startsWith(".")) && keys.some((key) => !key.startsWith(".")))
		return false;
	return targetOf(exports[subpath]) === "usable";
}
