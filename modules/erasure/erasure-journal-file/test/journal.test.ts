import { mkdtemp, stat, truncate, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ErasureJournal } from "@mod/erasure-journal";
import { journalContract } from "@mod/erasure-journal/testing";
import { quietRuntime } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import { type JournalFiles, nodeFiles } from "../src/files.ts";
import { framed, journalFileWith, readRecords } from "../src/journal.ts";

/** Each journal the harness opened, with its path and its files, so the harness reaches them again. */
const opened = new WeakMap<ErasureJournal, { path: string; failing: { next: boolean } }>();
const runtime = quietRuntime();

const at = (path: string) => {
	const failing = { next: false };
	const files: JournalFiles = {
		...nodeFiles,
		append: async (p, bytes) => {
			if (failing.next) {
				failing.next = false;
				throw Object.assign(new Error("no space left"), { code: "ENOSPC" });
			}
			return nodeFiles.append(p, bytes);
		},
	};
	const journal = journalFileWith({ path, files, clock: runtime.clock, random: runtime.random });
	opened.set(journal, { path, failing });
	return journal;
};
const placeOf = (journal: ErasureJournal) => {
	const place = opened.get(journal);
	if (!place) throw new Error("a journal the harness did not open");
	return place;
};

journalContract("file", {
	open: async () => at(join(await mkdtemp(join(tmpdir(), "erasure-journal-")), "journal")),
	reopen: async (journal) => at(placeOf(journal).path),
	tear: async (journal) => {
		const { path } = placeOf(journal);
		await truncate(path, (await stat(path)).size - 3);
	},
	failNextWrite: async (journal) => {
		placeOf(journal).failing.next = true;
	},
});

it("reads a record that does not match, with more after it, as corrupt, and one with none after as torn", () => {
	const header = framed({ type: "header", format: 1, id: "a" });
	const first = framed({ type: "begun", n: 1, subject: "s", requestedBy: "o", at: 0 });
	const second = framed({ type: "finished", n: 2, subject: "s" });
	const bad = Buffer.from(first.toString().replace('"s"', '"t"'));
	expect(readRecords(Buffer.concat([header, bad, second]))).toEqual({
		kind: "unusable",
		reason: "corrupt",
	});
	expect(readRecords(Buffer.concat([header, first, bad]))).toEqual({
		kind: "unusable",
		reason: "torn",
	});
});

it("reads records out of their numbering as corrupt", () => {
	const header = framed({ type: "header", format: 1, id: "a" });
	const skipped = framed({ type: "begun", n: 2, subject: "s", requestedBy: "o", at: 0 });
	expect(readRecords(Buffer.concat([header, skipped]))).toEqual({
		kind: "unusable",
		reason: "corrupt",
	});
});

it("throws unavailable while another holds the journal's lock, and appends once it is released", async () => {
	const path = join(await mkdtemp(join(tmpdir(), "erasure-journal-")), "journal");
	const journal = at(path);
	await journal.create();
	const release = await nodeFiles.lock(path, '{"pid":1}');
	try {
		await expect(journal.begun("s", "o")).rejects.toMatchObject({ name: "Unavailable" });
	} finally {
		await release();
	}
	expect(await journal.begun("s", "o")).toEqual({ number: 1 });
});

it("names the lock path and its holder where a lock a crash left behind holds every append, and appends once it is removed", async () => {
	const path = join(await mkdtemp(join(tmpdir(), "erasure-journal-")), "journal");
	const journal = at(path);
	await journal.create();
	await writeFile(`${path}.lock`, '{"pid":4242,"host":"gone","at":0}');
	const held = await journal.begun("s", "o").catch((error: unknown) => error);
	expect(held).toMatchObject({ name: "Unavailable" });
	expect(String((held as Error).message)).toContain(`${path}.lock`);
	expect(String((held as Error).message)).toContain('"pid":4242');
	await unlink(`${path}.lock`);
	expect(await journal.begun("s", "o")).toEqual({ number: 1 });
});
