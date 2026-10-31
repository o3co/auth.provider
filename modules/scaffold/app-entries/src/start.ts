/** The app's entry that `start` runs, and what every entry of a generated app shares. */
import { readFile } from "node:fs/promises";
import { join } from "node:path";

export const kernel = "@mod/kernel";
/** Where an app's entry reads its configuration files from. */
export const configFiles = "@mod/config-files";

/** Fills a file of `templates/` by its `{{name}}` marks; a mark with no value stays as written. */
export async function filled(template: string, fill: Readonly<Record<string, string>>) {
	const text = await readFile(join(import.meta.dirname, "..", "templates", template), "utf8");
	return text.replace(/\{\{(\w+)\}\}/g, (all, key: string) => fill[key] ?? all);
}

/** The app's entry, importing each module under what `importOf` names it (the workspace's name, unless published). */
/** Where the operator writes the keys the configuration reads: each one's variable, those of several lines, and the local layer. */
export interface KeysWritten {
	readonly read: Readonly<Record<string, string>>;
	readonly severalLines: readonly string[];
	readonly local: string;
}

const noKeys: KeysWritten = { read: {}, severalLines: [], local: "config/local.conf" };

/**
 * An entry's answer to a refused boot, with `written`, which waits for what it writes to be handed
 * on, and where to write each key it reads: every entry's mark `refused`.
 */
export const refusedPart = (keys: KeysWritten = noKeys) =>
	filled("refused.ts.part", {
		keysRead: JSON.stringify(keys.read),
		severalLines: JSON.stringify(keys.severalLines),
		local: keys.local,
	});

export const mainSource = async (
	modules: readonly string[],
	importOf = (name: string) => name,
	keys: KeysWritten = noKeys,
) =>
	filled("main.ts.template", {
		refused: await refusedPart(keys),
		kernel: importOf(kernel),
		configFiles: importOf(configFiles),
		imports: modules.map((name, i) => `import m${i} from "${importOf(name)}/module";`).join("\n"),
		modules: modules.map((_, i) => `m${i}`).join(", "),
	});
