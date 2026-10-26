import { crc32 } from "node:zlib";

/** One file of a ZIP archive: its name, and what its headers may say otherwise. */
export interface ZipFile {
	readonly name: string;
	readonly data: string;
	readonly mode?: number;
	readonly host?: number;
	/** The name its local header gives, where it differs from the directory's. */
	readonly localName?: string;
	readonly centralExtra?: Buffer;
	readonly localExtra?: Buffer;
}

/** Info-ZIP's Unicode Path extra field, naming the entry `path` for an unpacker that reads it. */
export function unicodePath(written: string, path: string): Buffer {
	const name = Buffer.from(path, "utf8");
	const field = Buffer.alloc(9);
	field.writeUInt16LE(0x7075, 0);
	field.writeUInt16LE(5 + name.length, 2);
	field.writeUInt8(1, 4);
	field.writeUInt32LE(crc32(Buffer.from(written, "utf8")), 5);
	return Buffer.concat([field, name]);
}

/** A ZIP archive of stored files, each with the host and mode its central directory gives. */
export function zipOf(files: readonly ZipFile[]): Buffer {
	const locals: Buffer[] = [];
	const centrals: Buffer[] = [];
	let offset = 0;
	for (const f of files) {
		const name = Buffer.from(f.name, "utf8");
		const localName = Buffer.from(f.localName ?? f.name, "utf8");
		const centralExtra = f.centralExtra ?? Buffer.alloc(0);
		const localExtra = f.localExtra ?? Buffer.alloc(0);
		const data = Buffer.from(f.data, "utf8");
		const crc = crc32(data);
		const local = Buffer.alloc(30);
		local.writeUInt32LE(0x04034b50, 0);
		local.writeUInt16LE(20, 4);
		local.writeUInt16LE(0x0800, 6);
		local.writeUInt32LE(crc, 14);
		local.writeUInt32LE(data.length, 18);
		local.writeUInt32LE(data.length, 22);
		local.writeUInt16LE(localName.length, 26);
		local.writeUInt16LE(localExtra.length, 28);
		const central = Buffer.alloc(46);
		central.writeUInt32LE(0x02014b50, 0);
		central.writeUInt16LE(((f.host ?? 3) << 8) | 20, 4);
		central.writeUInt16LE(20, 6);
		central.writeUInt16LE(0x0800, 8);
		central.writeUInt32LE(crc, 16);
		central.writeUInt32LE(data.length, 20);
		central.writeUInt32LE(data.length, 24);
		central.writeUInt16LE(name.length, 28);
		central.writeUInt16LE(centralExtra.length, 30);
		central.writeUInt32LE(((f.mode ?? 0o100644) << 16) >>> 0, 38);
		central.writeUInt32LE(offset, 42);
		locals.push(local, localName, localExtra, data);
		centrals.push(central, name, centralExtra);
		offset += local.length + localName.length + localExtra.length + data.length;
	}
	const directory = Buffer.concat(centrals);
	const end = Buffer.alloc(22);
	end.writeUInt32LE(0x06054b50, 0);
	end.writeUInt16LE(files.length, 8);
	end.writeUInt16LE(files.length, 10);
	end.writeUInt32LE(directory.length, 12);
	end.writeUInt32LE(offset, 16);
	return Buffer.concat([...locals, directory, end]);
}
