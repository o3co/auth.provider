/** In what order the release packs what `pnpm bundles` built, so the index is sealed over the rest before its own bundle is packed. */

/** What one bundle manifest of the workspace declares: its directory, its index file if any, and its entrances' names. */
export interface Declared {
	readonly dir: string;
	readonly index?: string;
	readonly entrances: readonly string[];
}

/**
 * The built directories packed first (every bundle but the index's), the index's bundle and file,
 * and the directories packed last (the index's bundle, then the entrances); or why not, where no
 * bundle or more than one declares the index, or a declared one was not built.
 */
export function packOrder(
	built: readonly string[],
	declared: readonly Declared[],
): { first: string[]; index: { dir: string; file: string }; last: string[] } | { problem: string } {
	const indexed = declared.filter((d) => typeof d.index === "string");
	if (indexed.length !== 1)
		return { problem: `${indexed.length} bundles declare the index, where one does` };
	const [holder] = indexed as [Declared];
	const entrances = declared
		.flatMap((d) => d.entrances)
		.map((name) => name.split("/").pop() as string);
	const missing = [holder.dir, ...entrances].filter((dir) => !built.includes(dir));
	if (missing.length > 0) return { problem: `${missing.join(", ")}: declared, but not built` };
	const later = new Set([holder.dir, ...entrances]);
	return {
		first: built.filter((dir) => !later.has(dir)).sort(),
		index: { dir: holder.dir, file: holder.index as string },
		last: [holder.dir, ...entrances],
	};
}
