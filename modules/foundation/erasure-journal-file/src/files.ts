import { constants } from "node:fs";
import { open, readFile, unlink } from "node:fs/promises";
import { dirname } from "node:path";

/** The file operations the journal is kept by; each durable before it answers. */
export interface JournalFiles {
	/** The file's bytes; throws with `code` `ENOENT` where there is none. */
	read(path: string): Promise<Buffer>;
	/** Writes a new file, refusing one that exists (`code` `EEXIST`), then syncs it and its directory. */
	create(path: string, bytes: Buffer): Promise<void>;
	/** Appends and syncs; where the write fails, cuts the file back to its length before. */
	append(path: string, bytes: Buffer): Promise<void>;
	/** Takes the file's lock, a file beside it, refusing one held (`code` `EEXIST`); answers its release. */
	lock(path: string): Promise<() => Promise<void>>;
}

const syncDirectory = async (path: string) => {
	const directory = await open(dirname(path), constants.O_RDONLY);
	try {
		await directory.sync();
	} finally {
		await directory.close();
	}
};

/** The node's own file system. */
export const nodeFiles: JournalFiles = {
	read: (path) => readFile(path),
	create: async (path, bytes) => {
		const file = await open(path, "wx");
		try {
			await file.writeFile(bytes);
			await file.sync();
		} finally {
			await file.close();
		}
		await syncDirectory(path);
	},
	append: async (path, bytes) => {
		const file = await open(path, "r+");
		try {
			const { size } = await file.stat();
			try {
				await file.write(bytes, 0, bytes.length, size);
				await file.sync();
			} catch (error) {
				// Nothing half written is left: the journal reads as it was.
				await file.truncate(size);
				await file.sync();
				throw error;
			}
		} finally {
			await file.close();
		}
	},
	lock: async (path) => {
		const lockPath = `${path}.lock`;
		const held = await open(lockPath, "wx");
		await held.close();
		return () => unlink(lockPath);
	},
};
