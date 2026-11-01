/** What a ZIP archive holds, read from its central directory before anything is unpacked. */
export interface Entry {
	readonly name: string;
	/** A file or a directory, as MS-DOS (host 0) or Unix (host 3) mark one; anything else is `other`. */
	readonly kind: "file" | "directory" | "other";
	/** Its local header names it otherwise, or an extra field (Info-ZIP's Unicode Path) would. */
	readonly renamed?: boolean;
}

/** The end of central directory record (APPNOTE 4.3.16); `zip64` marks a value ZIP64's record holds (4.4.1.4). */
const endOfCentralDirectory = {
	signature: 0x06054b50,
	size: 22,
	largestComment: 0xffff,
	entries: 10,
	directoryAt: 16,
	zip64: { entries: 0xffff, directoryAt: 0xffffffff },
} as const;

/** A central directory file header (APPNOTE 4.3.12); `host` is the high byte of "version made by". */
const centralFileHeader = {
	signature: 0x02014b50,
	size: 46,
	host: 5,
	nameLength: 28,
	extraLength: 30,
	commentLength: 32,
	externalAttributes: 38,
	localHeaderAt: 42,
} as const;

/** A local file header (APPNOTE 4.3.7). */
const localFileHeader = {
	signature: 0x04034b50,
	size: 30,
	nameLength: 26,
	extraLength: 28,
} as const;

/** An extra field's header (APPNOTE 4.5.1), and the id of Info-ZIP's Unicode Path (4.6.9). */
const extraField = { size: 4, id: 0, dataLength: 2, unicodePath: 0x7075 } as const;

/** The hosts of "version made by" read (APPNOTE 4.4.2.2), and Unix's file type mask and types taken. */
const madeBy = {
	msDos: { host: 0 },
	unix: { host: 3, typeMask: 0o170000, file: 0o100000, directory: 0o040000 },
} as const;

/** Whether a header's extra fields hold Info-ZIP's Unicode Path, which an unpacker takes for the name. */
const renames = (extra: Buffer) => {
	for (
		let i = 0;
		i + extraField.size <= extra.length;
		i += extraField.size + extra.readUInt16LE(i + extraField.dataLength)
	) {
		if (extra.readUInt16LE(i + extraField.id) === extraField.unicodePath) return true;
	}
	return false;
};

export function entriesOf(
	zip: Buffer,
): { readonly entries: Entry[] } | { readonly problem: string } {
	const eocd = endOfCentralDirectory;
	const central = centralFileHeader;
	const header = localFileHeader;
	let end = -1;
	for (
		let i = zip.length - eocd.size;
		i >= Math.max(0, zip.length - eocd.size - eocd.largestComment);
		i--
	) {
		if (zip.readUInt32LE(i) === eocd.signature) {
			end = i;
			break;
		}
	}
	if (end < 0) return { problem: "no ZIP archive" };
	const count = zip.readUInt16LE(end + eocd.entries);
	let at = zip.readUInt32LE(end + eocd.directoryAt);
	if (count === eocd.zip64.entries || at === eocd.zip64.directoryAt) {
		return { problem: "a ZIP64 archive, not read here" };
	}
	const entries: Entry[] = [];
	for (let n = 0; n < count; n++) {
		if (at + central.size > zip.length || zip.readUInt32LE(at) !== central.signature) {
			return { problem: "a broken ZIP directory" };
		}
		const host = zip.readUInt8(at + central.host);
		const nameLength = zip.readUInt16LE(at + central.nameLength);
		const extraLength = zip.readUInt16LE(at + central.extraLength);
		const skip = nameLength + extraLength + zip.readUInt16LE(at + central.commentLength);
		const mode = zip.readUInt32LE(at + central.externalAttributes) >>> 16;
		const nameAt = at + central.size;
		const name = zip.subarray(nameAt, nameAt + nameLength).toString("utf8");
		const local = zip.readUInt32LE(at + central.localHeaderAt);
		if (local + header.size > zip.length || zip.readUInt32LE(local) !== header.signature) {
			return { problem: "a broken ZIP entry" };
		}
		const localName = local + header.size + zip.readUInt16LE(local + header.nameLength);
		const renamed =
			zip.subarray(local + header.size, localName).toString("utf8") !== name ||
			renames(zip.subarray(nameAt + nameLength, nameAt + nameLength + extraLength)) ||
			renames(zip.subarray(localName, localName + zip.readUInt16LE(local + header.extraLength)));
		// Taken alone: what CI's own archives hold. Unix keeps the mode in the attributes' high half.
		const type = mode & madeBy.unix.typeMask;
		const kind =
			host === madeBy.msDos.host
				? name.endsWith("/")
					? "directory"
					: "file"
				: host === madeBy.unix.host && type === madeBy.unix.file
					? "file"
					: host === madeBy.unix.host && type === madeBy.unix.directory
						? "directory"
						: "other";
		entries.push({ name, kind, ...(renamed ? { renamed } : {}) });
		at += central.size + skip;
	}
	return { entries };
}

/** Each entry that is no plain file or directory, or is named otherwise, or would land outside its directory. */
export function archiveProblems(entries: readonly Entry[]): string[] {
	return entries.flatMap((e) => {
		if (e.kind === "other")
			return [`${e.name} is neither a file nor a directory as this check takes them`];
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
