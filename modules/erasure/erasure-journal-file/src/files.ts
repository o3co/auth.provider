import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { link, open, readFile, unlink } from "node:fs/promises";
import { dirname } from "node:path";

/** The file operations the journal is kept by; each durable before it answers. */
export interface JournalFiles {
	/** The file's bytes; throws with `code` `ENOENT` where there is none. */
	read(path: string): Promise<Buffer>;
	/** Writes a new file, refusing one that exists (`code` `EEXIST`), then syncs it and its directory. */
	create(path: string, bytes: Buffer): Promise<void>;
	/** Appends and syncs; where the write fails, cuts the file back to its length before. */
	append(path: string, bytes: Buffer): Promise<void>;
	/**
	 * Takes the file's lock, a file beside it holding `holder`, this take's alone; one held refuses
	 * with `code` `EEXIST` and the holder it records. Answers its release, which removes the lock
	 * only while it still records `holder`: a read, then a removal, not one atomic step. A release
	 * finding no lock is done; one the medium fails throws, and can be made again. A take that fails
	 * after its lock stood removes it; where that fails too, the failure carries `release`.
	 */
	lock(path: string, holder: string): Promise<() => Promise<void>>;
}

const syncDirectory = async (path: string) => {
	const directory = await open(dirname(path), constants.O_RDONLY);
	try {
		await directory.sync();
	} finally {
		await directory.close();
	}
};

/** What the files sync a directory and remove a file by: the node's own, or a test's. */
export interface FileSystem {
	readonly syncDirectory: (path: string) => Promise<void>;
	readonly unlink: (path: string) => Promise<void>;
}

const gone = (error: unknown) => (error as { code?: unknown }).code === "ENOENT";

/** A file of this take's own beside the lock, named from `holder`, another name where one is taken. */
const ownFile = async (lockPath: string, holder: string) => {
	for (let attempt = 0; attempt < 8; attempt++) {
		const hash = createHash("sha256").update(`${holder}\n${attempt}`).digest("hex");
		const name = `${lockPath}.${hash.slice(0, 16)}.tmp`;
		try {
			return { name, file: await open(name, "wx") };
		} catch (error) {
			if ((error as { code?: unknown }).code !== "EEXIST") throw error;
		}
	}
	throw new Error("no free name for the lock's holder file");
};

const releaseOf = (fs: FileSystem, lockPath: string, holder: string) => async () => {
	let recorded: string;
	try {
		recorded = await readFile(lockPath, "utf8");
	} catch (error) {
		if (gone(error)) return;
		throw error;
	}
	if (recorded !== holder) return;
	await fs.unlink(lockPath).catch((error: unknown) => {
		if (!gone(error)) throw error;
	});
};

/** The journal's files on a file system: the node's own unless a test gives another. */
export const nodeFilesWith = (fs: FileSystem = { syncDirectory, unlink }): JournalFiles => ({
	read: (path) => readFile(path),
	create: async (path, bytes) => {
		const file = await open(path, "wx");
		try {
			await file.writeFile(bytes);
			await file.sync();
		} finally {
			await file.close();
		}
		await fs.syncDirectory(path);
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
	lock: async (path, holder) => {
		const lockPath = `${path}.lock`;
		// The holder is written whole and synced in a file of its own first, then published as the
		// lock in one step: a lock never stands without its holder, whatever stops the take.
		const { name: written, file } = await ownFile(lockPath, holder);
		try {
			try {
				await file.writeFile(holder);
				await file.sync();
			} finally {
				await file.close();
			}
			try {
				await link(written, lockPath);
			} catch (error) {
				if ((error as { code?: unknown }).code !== "EEXIST") throw error;
				const recorded = await readFile(lockPath, "utf8").catch(() => "unread");
				// Empty only where an earlier version or a hand left it so.
				throw Object.assign(new Error("held"), {
					code: "EEXIST",
					holder: recorded.trim() || "unnamed",
				});
			}
		} finally {
			await unlink(written).catch(() => {});
		}
		const release = releaseOf(fs, lockPath, holder);
		try {
			await fs.syncDirectory(lockPath);
		} catch (error) {
			// Not taken after all: this take's lock goes with it.
			try {
				await release();
			} catch {
				throw Object.assign(error as object, { release });
			}
			throw error;
		}
		return release;
	},
});

export const nodeFiles: JournalFiles = nodeFilesWith();
