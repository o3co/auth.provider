import { existsSync, readFileSync, realpathSync, statSync } from "node:fs";
import { builtinModules } from "node:module";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

/** Why a specifier names no target this layer can tell (the card says each). */
export type Unresolved = "computed" | "private-import" | "scheme" | "missing" | "unsupported";

/** Where a specifier leads, classified; a file's owner is the caller's to tell. */
export type Target =
	| { readonly kind: "builtin"; readonly name: string }
	| { readonly kind: "package"; readonly name: string; readonly subpath: string }
	| { readonly kind: "file"; readonly url: string; readonly path: string }
	| {
			readonly kind: "unresolved";
			readonly reason: Unresolved;
			readonly fragment?: string;
			readonly path?: string;
	  };

/** A path with its links followed, as far as it exists; the rest as written. */
export function realOf(path: string): string {
	try {
		return realpathSync(path);
	} catch {
		const up = dirname(path);
		return up === path ? path : join(realOf(up), basename(path));
	}
}

const isBuiltin = (specifier: string) =>
	specifier.startsWith("node:") || builtinModules.includes(specifier);

/** A bare specifier's package and subpath: `@scope/name` or `name`, then the rest. */
export function packageOf(specifier: string): { name: string; subpath: string } | undefined {
	if (specifier.startsWith(".") || specifier.startsWith("/") || isBuiltin(specifier)) {
		return undefined;
	}
	const parts = specifier.split("/");
	const scoped = specifier.startsWith("@");
	const name = scoped ? parts.slice(0, 2).join("/") : (parts[0] ?? "");
	const subpath = parts.slice(scoped ? 2 : 1).join("/");
	return name === "" ? undefined : { name, subpath };
}

const relativeOrAbsolute = (specifier: string) =>
	specifier === "." ||
	specifier === ".." ||
	specifier.startsWith("./") ||
	specifier.startsWith("../") ||
	specifier.startsWith("/");
const schemeOf = (specifier: string) => /^([a-zA-Z][a-zA-Z0-9+.-]*):/.exec(specifier)?.[1];

const isFile = (path: string) => existsSync(path) && statSync(path).isFile();
const isDirectory = (path: string) => existsSync(path) && statSync(path).isDirectory();

/** A found file as a target: its real path, and its runtime URL with the specifier's query and fragment. */
function fileTarget(found: string, identity = { search: "", hash: "" }): Target {
	const path = realOf(found);
	return {
		kind: "file",
		url: `${pathToFileURL(path).href}${identity.search}${identity.hash}`,
		path,
	};
}

/** Where an ESM specifier leads from the file at `from`, as Node's loader reads it: a URL from its real place. */
export function esmTarget(specifier: string, from: string): Target {
	if (specifier.startsWith("#")) return { kind: "unresolved", reason: "private-import" };
	const scheme = schemeOf(specifier);
	if (scheme === "node") return { kind: "builtin", name: specifier };
	if (scheme !== undefined && scheme !== "file") return { kind: "unresolved", reason: "scheme" };
	if (scheme === "file" || relativeOrAbsolute(specifier)) {
		let physical: string;
		const identity = { search: "", hash: "" };
		try {
			const url = new URL(specifier, pathToFileURL(realOf(from)));
			identity.search = url.search;
			identity.hash = url.hash;
			url.search = "";
			url.hash = "";
			physical = fileURLToPath(url);
		} catch {
			// A URL Node cannot read as a path (another host, an encoded slash).
			return { kind: "unresolved", reason: "unsupported" };
		}
		const path = realOf(physical);
		// ESM loads a file as named, never a directory nor an extension tried.
		if (isDirectory(path)) return { kind: "unresolved", reason: "unsupported" };
		if (!isFile(path)) return { kind: "unresolved", reason: "missing", path };
		return fileTarget(path, identity);
	}
	if (isBuiltin(specifier)) return { kind: "builtin", name: specifier };
	const named = packageOf(specifier);
	return named ? { kind: "package", ...named } : { kind: "unresolved", reason: "scheme" };
}

/** The extensions CommonJS tries on a file, and the index files it tries in a directory. */
const extensions = [".js", ".json", ".node"];

/** CommonJS's file then directory: the file, with an extension, or the directory's main, then its index. */
function requireFound(base: string, only = { directory: false }): string | undefined {
	const asFile = (p: string) => [p, ...extensions.map((e) => `${p}${e}`)].find(isFile);
	const asIndex = (p: string) => extensions.map((e) => join(p, `index${e}`)).find(isFile);
	const found = only.directory ? undefined : asFile(base);
	if (found || !isDirectory(base)) return found;
	let main: unknown;
	try {
		main = JSON.parse(readFileSync(join(base, "package.json"), "utf8")).main;
	} catch {}
	if (typeof main === "string") {
		const entry = resolve(base, main);
		const viaMain = asFile(entry) ?? asIndex(entry);
		if (viaMain) return viaMain;
	}
	return asIndex(base);
}

/** Where a `require` specifier leads from a directory (`undefined` where its loader's base is not known), as Node's CommonJS loader reads it: a path, not a URL. */
export function requireTarget(specifier: string, dir: string | undefined): Target {
	if (specifier.startsWith("#")) return { kind: "unresolved", reason: "private-import" };
	if (isBuiltin(specifier)) return { kind: "builtin", name: specifier };
	if (schemeOf(specifier) !== undefined) return { kind: "unresolved", reason: "scheme" };
	if (relativeOrAbsolute(specifier)) {
		if (dir === undefined) return { kind: "unresolved", reason: "unsupported" };
		const base = resolve(dir, specifier);
		// Ending in /, or in a . or .. segment, it names a directory alone: no file of that name is tried.
		const found = /(^|\/)(\.\.?)?$/.test(specifier)
			? requireFound(base, { directory: true })
			: requireFound(base);
		return found
			? fileTarget(found)
			: { kind: "unresolved", reason: "missing", path: realOf(base) };
	}
	const named = packageOf(specifier);
	return named ? { kind: "package", ...named } : { kind: "unresolved", reason: "scheme" };
}
