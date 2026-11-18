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
	 * Takes the file's lock, a file beside it holding `holder`; one held refuses with `code` `EEXIST`
	 * and the holder it records. Answers its release, which removes the lock only while it still
	 * records `holder`: a read, then a removal, not one atomic step. A release finding no lock is
	 * done; one the medium fails throws, and can be made again.
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
	lock: async (path, holder) => {
		const lockPath = `${path}.lock`;
		// The holder is written whole and synced in a file of its own first, then published as the
		// lock in one step: a lock never stands without its holder, whatever stops the take.
		// Named by the holder, which is this take's alone.
		const written = `${lockPath}.${createHash("sha256").update(holder).digest("hex").slice(0, 16)}.tmp`;
		try {
			const file = await open(written, "wx");
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
		await syncDirectory(lockPath);
		const gone = (error: unknown) => (error as { code?: unknown }).code === "ENOENT";
		return async () => {
			let recorded: string;
			try {
				recorded = await readFile(lockPath, "utf8");
			} catch (error) {
				// Gone already: nothing to release. Any other failure is the caller's to know.
				if (gone(error)) return;
				throw error;
			}
			// Not this holder's any more (the operator removed it and another took it): left in place.
			if (recorded !== holder) return;
			await unlink(lockPath).catch((error: unknown) => {
				if (!gone(error)) throw error;
			});
		};
	},
};
