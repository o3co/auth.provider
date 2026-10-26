/** In what order the release packs what `pnpm bundles` built, so the index is sealed over the rest before its own bundle is packed. */

/** What one bundle manifest of the workspace declares: its directory, whether it ships, its index file if any, and its entrances' names. */
export interface Declared {
	readonly dir: string;
	readonly shipped: boolean;
	readonly index?: string;
	readonly entrances: readonly string[];
}

/**
 * The directories packed first (every shipped bundle but the index's), the index's bundle and file,
 * and the directories packed last (the index's bundle, then the entrances), all from what ships;
 * or why not, where no shipped bundle or more than one declares the index, one shipped (an entrance
 * included) was not built, or one built is not declared to ship.
 */
export function packOrder(
	built: readonly string[],
	declared: readonly Declared[],
): { first: string[]; index: { dir: string; file: string }; last: string[] } | { problem: string } {
	const shipped = declared.filter((d) => d.shipped);
	const indexed = shipped.filter((d) => typeof d.index === "string");
	if (indexed.length !== 1)
		return { problem: `${indexed.length} bundles declare the index, where one does` };
	const [holder] = indexed as [Declared];
	const entrances = shipped
		.flatMap((d) => d.entrances)
		.map((name) => name.split("/").pop() as string);
	const expected = [...shipped.map((d) => d.dir), ...entrances];
	const missing = expected.filter((dir) => !built.includes(dir));
	if (missing.length > 0) return { problem: `${missing.join(", ")}: declared, but not built` };
	const unexpected = built.filter((dir) => !expected.includes(dir));
	if (unexpected.length > 0)
		return { problem: `${unexpected.join(", ")}: built, but not declared to ship` };
	const later = new Set([holder.dir, ...entrances]);
	return {
		first: shipped
			.map((d) => d.dir)
			.filter((dir) => !later.has(dir))
			.sort(),
		index: { dir: holder.dir, file: holder.index as string },
		last: [holder.dir, ...entrances],
	};
}
