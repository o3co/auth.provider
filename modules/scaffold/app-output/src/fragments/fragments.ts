/** The boundary between the modules' sections and the project's environment: fragments mapped to env and the local layer. */
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { parse } from "@o3co/ts.hocon";

/** The file beside a package's manifest that holds its section's example. */
export const fragmentFile = "config.example";

export type Tree = { readonly [key: string]: unknown };

/** One section's example, as its owner wrote it: placeholders only. */
export interface Fragment {
	readonly section: string;
	readonly tree: { readonly [key: string]: unknown };
}

/** A scalar key of a fragment, read from the environment variable named for it. */
export interface Setting {
	readonly key: string;
	readonly env: string;
	readonly placeholder: string;
}

/** A key written in a local layer: a list, a value the operator writes, or one of several lines. */
export interface Written {
	readonly key: string;
	readonly example: string;
	/** Whether it spans sections: the fragment's value is for its schema only, and the operator writes it. */
	readonly spansSections: boolean;
	/** Whether its example is several lines: still read from env, but never in a one-line env file. */
	readonly severalLines?: boolean;
}

/** A scalar its owner's example gives in several lines, as a PEM key is. */
const severalLines = (value: unknown) => typeof value === "string" && value.includes("\n");

/** Values spanning sections, in a fragment for its schema only: copied, they would boot; the operator writes them. */
const spanningSections: ReadonlyMap<string, string> = new Map([
	["audit.receivers", "[REPLACE-RECEIVER-NAMES]"],
]);

export const isTree = (value: unknown): value is Tree =>
	typeof value === "object" && value !== null && !Array.isArray(value);

/** The most a fragment's text may hold, and its keys and values together (what reaches the examples). */
const textBytes = 64 * 1024;
const treeBytes = 32 * 1024;

/** An include, refused in words no missing file's error has: the library skips a missing include unsaid. */
const noInclude = (): never => {
	throw new Error("an include, which a section example never holds");
};

/** A backtick or a control character but a line break: either would reach the guide's tables or the env example as more than text. */
const unwritten = (text: string) =>
	[...text].some((c) => c === "`" || c === "\u007f" || (c < " " && c !== "\n"));
const written = (value: unknown): boolean =>
	Array.isArray(value)
		? value.every(written)
		: isTree(value)
			? Object.entries(value).every(([key, inner]) => !unwritten(key) && written(inner))
			: typeof value !== "string" || !unwritten(value);

/** One fragment's tree, read as data: no substitution resolved or kept, no file included, nothing over its bounds. */
export function treeOf(from: string, text: string): unknown {
	if (Buffer.byteLength(text) > textBytes) throw new Error(`${from}: over ${textBytes} bytes`);
	const refuse = {
		readFileSync: noInclude,
		readFile: async () => noInclude(),
		packageResolver: noInclude,
	};
	let config: ReturnType<typeof parse>;
	try {
		config = parse(text, { resolveSubstitutions: false, env: {}, ...refuse });
	} catch (error) {
		throw new Error(`${from}: ${(error as Error).message}`);
	}
	if (!config.isResolved()) {
		throw new Error(`${from}: a substitution, which a section example never holds`);
	}
	const tree = config.toObject();
	if (!written(tree))
		throw new Error(`${from}: a backtick or a control character in a key or a value`);
	if (Buffer.byteLength(JSON.stringify(tree)) > treeBytes) {
		throw new Error(`${from}: its keys and values come to over ${treeBytes} bytes`);
	}
	return tree;
}

/** The fragments beside the packages in `dirs`, in that order; a package without one is skipped. */
export async function fragmentsIn(dirs: readonly string[]): Promise<Fragment[]> {
	const read: { from: string; text: string }[] = [];
	for (const dir of dirs) {
		const file = join(dir, fragmentFile);
		const text = await readFile(file, "utf8").catch((error: NodeJS.ErrnoException) => {
			if (error.code === "ENOENT") return undefined;
			throw error;
		});
		if (text !== undefined) read.push({ from: file, text });
	}
	return fragmentsOf(read);
}

/** Fragments from their texts, each of exactly one section, no section twice, each read as `treeOf` reads it; `from` names it in a refusal. */
export function fragmentsOf(texts: readonly { readonly from: string; readonly text: string }[]) {
	const fragments: Fragment[] = [];
	for (const { from, text } of texts) {
		const tree = treeOf(from, text);
		const roots = isTree(tree) ? Object.entries(tree) : [];
		const [root] = roots;
		if (roots.length !== 1 || root === undefined || !isTree(root[1])) {
			throw new Error(`${from} does not hold exactly one section`);
		}
		if (fragments.some((f) => f.section === root[0])) {
			throw new Error(`${from}: a second fragment for ${root[0]}`);
		}
		fragments.push({ section: root[0], tree: root[1] });
	}
	return fragments;
}

/** Each leaf of a tree with its path: objects are walked into, lists and scalars are leaves. */
function leaves(tree: Tree, path: readonly string[]): [string[], unknown][] {
	return Object.entries(tree).flatMap(([key, value]) =>
		isTree(value) ? leaves(value, [...path, key]) : [[[...path, key], value]],
	);
}

const scalar = (value: unknown) =>
	typeof value === "string" || typeof value === "number" || typeof value === "boolean";

/** The environment variable a key reads: the path joined by `_`, upper-cased, `-` as `_`. */
const envOf = (path: readonly string[]) => path.join("_").toUpperCase().replaceAll("-", "_");

export const envName = (key: string) => envOf(key.split("."));

/** The fragments' scalar keys with their variables; refuses two keys reading one, naming both, and an unnameable one. */
export function settingsOf(fragments: readonly Fragment[]): Setting[] {
	const settings = fragments.flatMap((f) =>
		leaves(f.tree, [f.section])
			.filter(([path, value]) => scalar(value) && !spanningSections.has(path.join(".")))
			.map(([path, value]) => ({
				key: path.join("."),
				env: envOf(path),
				placeholder: String(value),
			})),
	);
	const refusals = settings.flatMap((s, i) => {
		if (!/^[A-Z][A-Z0-9_]*$/.test(s.env)) return [`${s.key}: no environment variable name`];
		const first = settings.findIndex((other) => other.env === s.env);
		return first < i ? [`${settings[first]?.key} and ${s.key} both read ${s.env}`] : [];
	});
	if (refusals.length > 0) throw new Error(refusals.join("; "));
	return settings;
}

/** The keys the operator writes in a local layer: the fragments' lists, the values that span sections, and those of several lines. */
export function writtenOf(fragments: readonly Fragment[]): Written[] {
	return fragments.flatMap((f) =>
		leaves(f.tree, [f.section]).flatMap(([path, value]): Written[] => {
			// Each element quoted where HOCON would read it otherwise, so a key with a dot stays one key.
			const key = path.map(hoconKey).join(".");
			const noted = spanningSections.get(path.join("."));
			if (noted !== undefined) return [{ key, example: noted, spansSections: true }];
			if (severalLines(value)) {
				return [{ key, example: `"""${value}"""`, spansSections: false, severalLines: true }];
			}
			return Array.isArray(value)
				? [{ key, example: JSON.stringify(value, null, "\t"), spansSections: false }]
				: [];
		}),
	);
}

export const hoconKey = (key: string) => (/^[A-Za-z0-9_-]+$/.test(key) ? key : JSON.stringify(key));

/** HOCON for the fragments, nested as they nest: `line` writes each leaf it keeps; a block keeping none is left out. */
function render(
	header: string,
	fragments: readonly Fragment[],
	line: (key: string, name: string) => string | undefined,
): string {
	const block = (tree: Tree, path: readonly string[]): string[] =>
		Object.entries(tree).flatMap(([name, value]) => {
			const at = [...path, name];
			if (!isTree(value)) return line(at.join("."), hoconKey(name))?.split("\n") ?? [];
			const inner = block(value, at).map((l) => `\t${l}`);
			return inner.length === 0 ? [] : [`${hoconKey(name)} {`, ...inner, "}"];
		});
	const tree = Object.fromEntries(fragments.map((f) => [f.section, f.tree]));
	return `${[header, ...block(tree, [])].join("\n")}\n`;
}

/** Every scalar key reads its environment variable, and holds no value. */
export function applicationConf(fragments: readonly Fragment[]): string {
	const env = new Map(settingsOf(fragments).map((s) => [s.key, s.env]));
	return render(
		"# Each key reads its environment variable (see .env.example); this file holds no values.",
		fragments,
		(key, name) => (env.has(key) ? `${name} = \${?${env.get(key)}}` : undefined),
	);
}

/** No live line in an example: `## ` opens prose, `# ` a value, so a copy sets nothing. */
const prose = "## ";
const commented = (text: string) => text.replace(/^/gm, "# ");
const example = (header: string, values: readonly string[]) =>
	`${[`${prose}${header}`, ...values.map(commented)].join("\n")}\n`;

/** Each list with its placeholders, each value that spans sections, by its dotted key, then each entry sample under its map. */
export function localConfExample(
	fragments: readonly Fragment[],
	samples: readonly string[] = [],
): string {
	return example(
		"Copy to config/local.conf, uncomment each key and replace its placeholders; git and the image leave that file out.",
		[...writtenOf(fragments).map((w) => `${w.key} = ${w.example}`), ...samples],
	);
}

export function envExample(settings: readonly Setting[]): string {
	const quoted = (value: string) => (/^[^\s"'#\\]*$/.test(value) ? value : JSON.stringify(value));
	return example(
		"Copy to .env, uncomment each line you set and replace its placeholder; a value of several lines, such as a PEM key, goes in the local layer instead. Git and the image leave .env out.",
		settings
			.filter((s) => !severalLines(s.placeholder))
			.map((s) => `${s.env}=${quoted(s.placeholder)}`),
	);
}
