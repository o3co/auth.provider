import { Unavailable } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import type { ErasureJournal } from "./contract.ts";

export interface JournalHarness {
	/** A journal over a fresh place: not created yet. */
	open(): Promise<ErasureJournal>;
	/** Another journal over the same place as `journal`, as a later process opens it. */
	reopen(journal: ErasureJournal): Promise<ErasureJournal>;
	/** Cuts the last record of `journal`'s place short, as a crash during its write leaves it. */
	tear(journal: ErasureJournal): Promise<void>;
	/** Makes the next write to `journal`'s place fail at the medium, as a full or failing disk does. */
	failNextWrite(journal: ErasureJournal): Promise<void>;
}

/** The erasure journal's contract, run against any implementation. */
export function journalContract(name: string, harness: JournalHarness): void {
	const created = async () => {
		const journal = await harness.open();
		const made = await journal.create();
		if (made.kind !== "created") throw new Error("a fresh journal was not created");
		return { journal, id: made.id };
	};

	describe(`erasure journal contract: ${name}`, () => {
		it("answers missing before it is created, to every call", async () => {
			const journal = await harness.open();
			const missing = { kind: "unusable", reason: "missing" };
			expect(await journal.header()).toEqual(missing);
			expect(await journal.begun("alice", "operator")).toEqual(missing);
			expect(await journal.finished("alice")).toEqual(missing);
			expect(await journal.list()).toEqual(missing);
		});

		it("is created once, with a header holding a new id and no record", async () => {
			const { journal, id } = await created();
			expect(id).not.toBe("");
			expect(await journal.create()).toEqual({ kind: "exists" });
			expect(await journal.header()).toEqual({ id, number: 0 });
			expect((await created()).id).not.toBe(id);
		});

		it("numbers each record one more than the last, and the header follows", async () => {
			const { journal, id } = await created();
			expect(await journal.begun("alice", "operator")).toEqual({ number: 1 });
			expect(await journal.begun("bob", "operator")).toEqual({ number: 2 });
			expect(await journal.finished("alice")).toEqual({ number: 3 });
			expect(await journal.header()).toEqual({ id, number: 3 });
		});

		it("lists each subject begun once, in the order begun, with whether it finished since", async () => {
			const { journal } = await created();
			await journal.begun("alice", "ops-1");
			await journal.begun("bob", "ops-2");
			await journal.finished("alice");
			await journal.begun("carol", "ops-1");
			await journal.finished("carol");
			await journal.begun("carol", "ops-3");
			const list = await journal.list();
			if (!Array.isArray(list)) throw new Error("unusable");
			expect(list.map((e) => [e.subject, e.requestedBy, e.finished, e.number])).toEqual([
				["alice", "ops-1", true, 3],
				["bob", "ops-2", false, 2],
				["carol", "ops-3", false, 6],
			]);
			for (const entry of list) expect(typeof entry.begunAt).toBe("number");
		});

		it("keeps what it answered for a later process that opens it", async () => {
			const { journal, id } = await created();
			await journal.begun("alice", "operator");
			await journal.finished("alice");
			const later = await harness.reopen(journal);
			expect(await later.header()).toEqual({ id, number: 2 });
			expect(await later.list()).toEqual(await journal.list());
			expect(await later.begun("bob", "operator")).toEqual({ number: 3 });
		});

		it("answers torn, to every call, once its last record was cut short", async () => {
			const { journal } = await created();
			await journal.begun("alice", "operator");
			await journal.begun("bob", "operator");
			await harness.tear(journal);
			const later = await harness.reopen(journal);
			const torn = { kind: "unusable", reason: "torn" };
			expect(await later.header()).toEqual(torn);
			expect(await later.list()).toEqual(torn);
			expect(await later.begun("carol", "operator")).toEqual(torn);
		});

		it("throws unavailable where the medium fails a write, appending nothing", async () => {
			const { journal } = await created();
			await journal.begun("alice", "operator");
			await harness.failNextWrite(journal);
			await expect(journal.begun("bob", "operator")).rejects.toBeInstanceOf(Unavailable);
			const later = await harness.reopen(journal);
			expect((await later.list()) as unknown[]).toHaveLength(1);
			expect(await later.begun("bob", "operator")).toEqual({ number: 2 });
		});
	});
}
