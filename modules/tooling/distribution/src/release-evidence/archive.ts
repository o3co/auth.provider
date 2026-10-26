/** What a ZIP archive holds, read from its central directory before anything is unpacked. */
export interface Entry {
	readonly name: string;
	readonly link: boolean;
}

export function entriesOf(
	zip: Buffer,
): { readonly entries: Entry[] } | { readonly problem: string } {
	let end = -1;
	for (let i = zip.length - 22; i >= Math.max(0, zip.length - 22 - 0xffff); i--) {
		if (zip.readUInt32LE(i) === 0x06054b50) {
			end = i;
			break;
		}
	}
	if (end < 0) return { problem: "no ZIP archive" };
	const count = zip.readUInt16LE(end + 10);
	let at = zip.readUInt32LE(end + 16);
	if (count === 0xffff || at === 0xffffffff) return { problem: "a ZIP64 archive, not read here" };
	const entries: Entry[] = [];
	for (let n = 0; n < count; n++) {
		if (at + 46 > zip.length || zip.readUInt32LE(at) !== 0x02014b50) {
			return { problem: "a broken ZIP directory" };
		}
		const host = zip.readUInt8(at + 5);
		const nameLength = zip.readUInt16LE(at + 28);
		const skip = nameLength + zip.readUInt16LE(at + 30) + zip.readUInt16LE(at + 32);
		const mode = zip.readUInt32LE(at + 38) >>> 16;
		const name = zip.subarray(at + 46, at + 46 + nameLength).toString("utf8");
		// Unix (3) and macOS (19) keep the file's mode in the high half of the external attributes.
		entries.push({ name, link: (host === 3 || host === 19) && (mode & 0o170000) === 0o120000 });
		at += 46 + skip;
	}
	return { entries };
}

/** Each entry that would land outside the directory it is unpacked into, or that is a link. */
export function archiveProblems(entries: readonly Entry[]): string[] {
	return entries.flatMap((e) => {
		if (e.link) return [`${e.name} is a link`];
		const parts = e.name.split("/");
		return e.name === "" ||
			e.name.startsWith("/") ||
			/^[A-Za-z]:/.test(e.name) ||
			e.name.includes("\\") ||
			parts.includes("..")
			? [`${JSON.stringify(e.name)} would land outside the directory`]
			: [];
	});
}
