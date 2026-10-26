/** What a ZIP archive holds, read from its central directory before anything is unpacked. */
export interface Entry {
	readonly name: string;
	readonly link: boolean;
	/** Its local header names it otherwise, or an extra field (Info-ZIP's Unicode Path) would. */
	readonly renamed?: boolean;
}

/** Whether a header's extra fields hold Info-ZIP's Unicode Path, which an unpacker takes for the name. */
const renames = (extra: Buffer) => {
	for (let i = 0; i + 4 <= extra.length; i += 4 + extra.readUInt16LE(i + 2)) {
		if (extra.readUInt16LE(i) === 0x7075) return true;
	}
	return false;
};

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
		const extraLength = zip.readUInt16LE(at + 30);
		const skip = nameLength + extraLength + zip.readUInt16LE(at + 32);
		const mode = zip.readUInt32LE(at + 38) >>> 16;
		const name = zip.subarray(at + 46, at + 46 + nameLength).toString("utf8");
		const local = zip.readUInt32LE(at + 42);
		if (local + 30 > zip.length || zip.readUInt32LE(local) !== 0x04034b50) {
			return { problem: "a broken ZIP entry" };
		}
		const localName = local + 30 + zip.readUInt16LE(local + 26);
		const renamed =
			zip.subarray(local + 30, localName).toString("utf8") !== name ||
			renames(zip.subarray(at + 46 + nameLength, at + 46 + nameLength + extraLength)) ||
			renames(zip.subarray(localName, localName + zip.readUInt16LE(local + 28)));
		// Unix (3) and macOS (19) keep the file's mode in the high half of the external attributes.
		const link = (host === 3 || host === 19) && (mode & 0o170000) === 0o120000;
		entries.push({ name, link, ...(renamed ? { renamed } : {}) });
		at += 46 + skip;
	}
	return { entries };
}

/** Each entry that would land outside the directory it is unpacked into, or that is a link. */
export function archiveProblems(entries: readonly Entry[]): string[] {
	return entries.flatMap((e) => {
		if (e.link) return [`${e.name} is a link`];
		if (e.renamed) return [`${e.name} is named otherwise by its local header or an extra field`];
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
