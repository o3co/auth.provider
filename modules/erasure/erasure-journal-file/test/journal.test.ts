import { spawn } from "node:child_process";
import {
	mkdir,
	mkdtemp,
	open,
	readdir,
	readFile,
	rmdir,
	stat,
	truncate,
	unlink,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { ErasureJournal } from "@mod/erasure-journal";
import { journalContract } from "@mod/erasure-journal/testing";
import { quietRuntime } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import { type JournalFiles, nodeFiles, nodeFilesWith } from "../src/files.ts";
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

const fresh = async () => join(await mkdtemp(join(tmpdir(), "erasure-journal-")), "journal");

it("answers busy, naming the holder, to every hold after its holder was killed, and holds once the operator removes the lock", async () => {
	const path = await fresh();
	const child = spawn(
		process.execPath,
		[join(import.meta.dirname, "fixtures", "holding.ts"), path],
		{
			stdio: ["ignore", "pipe", "inherit"],
		},
	);
	// A child that ends without a word fails the test, never leaves it waiting.
	const said = await new Promise<string>((resolve) => {
		child.stdout.once("data", (d) => resolve(String(d)));
		child.once("exit", (code) => resolve(`ended (${code})`));
	});
	expect(said.trim()).toBe("held");
	const ended = new Promise((resolve) => child.once("exit", resolve));
	child.kill("SIGKILL");
	await ended;
	// A crash leaves the hold: nothing breaks it on a guess.
	for (let i = 0; i < 2; i++) {
		const busy = await at(path).hold();
		expect(busy).toMatchObject({
			kind: "busy",
			holder: expect.stringContaining(`"pid":${child.pid}`),
		});
	}
	await unlink(`${path}.lock`);
	const held = await at(path).hold();
	expect(held.kind).toBe("held");
	if (held.kind === "held") await held.release();
});

it("queues the holder's appends one after another under its hold, taking no lock for each", async () => {
	const path = await fresh();
	const journal = at(path);
	const held = await journal.hold();
	await journal.create();
	const lockedBefore = await readFile(`${path}.lock`, "utf8");
	const numbers = await Promise.all(["a", "b", "c"].map((s) => journal.begun(s, "o")));
	expect(numbers).toEqual([{ number: 1 }, { number: 2 }, { number: 3 }]);
	expect(await readFile(`${path}.lock`, "utf8")).toBe(lockedBefore);
	if (held.kind === "held") await held.release();
	await expect(stat(`${path}.lock`)).rejects.toMatchObject({ code: "ENOENT" });
});

it("leaves another holder's lock in place where a holder whose lock the operator removed releases late", async () => {
	const path = await fresh();
	const first = await at(path).hold();
	await unlink(`${path}.lock`);
	const second = await at(path).hold();
	expect([first.kind, second.kind]).toEqual(["held", "held"]);
	if (first.kind === "held") await first.release();
	const third = await at(path).hold();
	expect(third.kind).toBe("busy");
	if (second.kind === "held") await second.release();
	expect((await at(path).hold()).kind).toBe("held");
});

it("takes no append under a hold once its release began, finishing those it took before it lets the lock go", async () => {
	const path = await fresh();
	let openGate: () => void = () => {};
	const gate = new Promise<void>((resolve) => {
		openGate = resolve;
	});
	let first = true;
	const files: JournalFiles = {
		...nodeFiles,
		append: async (p, bytes) => {
			// The first append waits at the gate, as a slow disk would.
			if (first) {
				first = false;
				await gate;
			}
			return nodeFiles.append(p, bytes);
		},
	};
	const journal = journalFileWith({ path, files, clock: runtime.clock, random: runtime.random });
	await journal.create();
	const held = await journal.hold();
	if (held.kind !== "held") throw new Error("not held");
	const taken = journal.begun("a", "o");
	const released = held.release();
	// Asked once the release began: not taken under the hold, and the lock is still there.
	await expect(journal.begun("b", "o")).rejects.toMatchObject({ name: "Unavailable" });
	await expect(stat(`${path}.lock`)).resolves.toBeDefined();
	openGate();
	expect(await taken).toEqual({ number: 1 });
	await released;
	await expect(stat(`${path}.lock`)).rejects.toMatchObject({ code: "ENOENT" });
	expect(await journal.begun("b", "o")).toEqual({ number: 2 });
	expect((await journal.list()) as unknown[]).toHaveLength(2);
});

it("throws unavailable where the medium fails a release, keeping the lock, and releases when made again", async () => {
	const path = await fresh();
	let failures = 1;
	const files: JournalFiles = {
		...nodeFiles,
		lock: async (p, holder) => {
			const release = await nodeFiles.lock(p, holder);
			return async () => {
				if (failures-- > 0) throw Object.assign(new Error("i/o error"), { code: "EIO" });
				return release();
			};
		},
	};
	const journal = journalFileWith({ path, files, clock: runtime.clock, random: runtime.random });
	const held = await journal.hold();
	if (held.kind !== "held") throw new Error("not held");
	await expect(held.release()).rejects.toMatchObject({ name: "Unavailable" });
	await expect(stat(`${path}.lock`)).resolves.toBeDefined();
	await held.release();
	await expect(stat(`${path}.lock`)).rejects.toMatchObject({ code: "ENOENT" });
});

it("finds a lock already gone done, and throws where the lock cannot be read", async () => {
	const path = await fresh();
	const gone = await nodeFiles.lock(path, "one");
	await unlink(`${path}.lock`);
	await gone();
	const unread = await nodeFiles.lock(path, "two");
	await unlink(`${path}.lock`);
	await mkdir(`${path}.lock`);
	await expect(unread()).rejects.toMatchObject({ code: "EISDIR" });
	await rmdir(`${path}.lock`);
});

it("never shows a lock without its holder: one take of many holds, every other answers busy naming it, and no take leaves a file", async () => {
	const path = await fresh();
	const answers = await Promise.all(Array.from({ length: 20 }, () => at(path).hold()));
	const held = answers.filter((a) => a.kind === "held");
	expect(held).toHaveLength(1);
	const recorded = await readFile(`${path}.lock`, "utf8");
	expect(recorded).not.toBe("");
	for (const answer of answers) {
		if (answer.kind === "busy") expect(answer.holder).toBe(recorded);
	}
	expect(await readdir(dirname(path))).toEqual(["journal.lock"]);
});

it("names an empty lock, as an earlier version could leave one, with a fixed word", async () => {
	const path = await fresh();
	await writeFile(`${path}.lock`, "");
	expect(await at(path).hold()).toEqual({ kind: "busy", holder: "unnamed" });
});

/** The node's files, the next `syncs` directory syncs and the next `unlinks` removals failing as an I/O error. */
const failing = (counts: { syncs: number; unlinks: number }) => {
	const eio = () => Object.assign(new Error("i/o error"), { code: "EIO" });
	return nodeFilesWith({
		syncDirectory: async (p) => {
			if (counts.syncs-- > 0) throw eio();
			const directory = await open(dirname(p), "r");
			try {
				await directory.sync();
			} finally {
				await directory.close();
			}
		},
		unlink: async (p) => {
			if (counts.unlinks-- > 0) throw eio();
			await unlink(p);
		},
	});
};

it("removes its own lock where a take's directory sync fails, so the next take holds", async () => {
	const path = await fresh();
	const files = failing({ syncs: 1, unlinks: 0 });
	const journal = journalFileWith({ path, files, clock: runtime.clock, random: runtime.random });
	await expect(journal.hold()).rejects.toMatchObject({ name: "Unavailable" });
	await expect(stat(`${path}.lock`)).rejects.toMatchObject({ code: "ENOENT" });
	expect((await journal.hold()).kind).toBe("held");
});

it("removes the lock a failed take could not, before the same journal's next take", async () => {
	const path = await fresh();
	const files = failing({ syncs: 1, unlinks: 1 });
	const journal = journalFileWith({ path, files, clock: runtime.clock, random: runtime.random });
	await expect(journal.hold()).rejects.toMatchObject({ name: "Unavailable" });
	// Left, naming this journal's failed take: another journal finds it held.
	expect((await at(path).hold()).kind).toBe("busy");
	const held = await journal.hold();
	expect(held.kind).toBe("held");
	if (held.kind === "held") await held.release();
	await expect(stat(`${path}.lock`)).rejects.toMatchObject({ code: "ENOENT" });
});
