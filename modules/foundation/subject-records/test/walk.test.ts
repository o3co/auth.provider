import type { SetReading, SubjectReading, Walk } from "@mod/erasure-extensions";
import type { Key, Space } from "@mod/store";
import { expect, it } from "vitest";
import { eraseSubject, migrateRecords, migrateSets } from "../src/subject-records.ts";
import { placed } from "./placed.ts";

// A walk whose server changes starts over and finishes: it never ends at the change (#2826's walk).
const g = ["durable"] as const;
const records: Space = { name: "walk-records", guarantees: g, subjectData: "online-indexed" };
const sets: Space = { name: "walk-sets", guarantees: g, subjectData: "online-indexed" };
const subjects = ["alice", "bob", "carol", "dave"];
const byValue: SubjectReading = async (_key, value) => ({
	kind: "subject",
	subject: (value as { owner: string }).owner,
});
const byKey: SetReading = async (key) => ({ kind: "subject", subject: key.slice(6) });

async function opened() {
	const { s, at } = await placed([records, sets]);
	/** Every key of a space, one to a page; `serverOf` names the server of each page asked. */
	const walk = (serverOf: (asked: number) => string): Walk => {
		let asked = 0;
		// The keys in one order, taken once: a store's own scan order may move as values change.
		let all: Key[] | undefined;
		return {
			sweep: async (name, cursor) => {
				const space = name === records.name ? records : sets;
				if (all === undefined) {
					all = [];
					let on: string | undefined;
					do {
						const page = await s.scan(space, on);
						all.push(...page.keys);
						on = page.cursor;
					} while (on !== undefined);
					all.sort((a, b) => (String(a.partition) < String(b.partition) ? -1 : 1));
				}
				const at = cursor === undefined ? 0 : Number(cursor);
				const server = serverOf(asked++);
				const keys = all.slice(at, at + 1);
				return at + 1 < all.length ? { keys, cursor: String(at + 1), server } : { keys, server };
			},
		};
	};
	/** The raw values left in a space: what no envelope holds, of its records or sets alone. */
	const rawLeft = async (space: Space) => {
		const left: string[] = [];
		const name = space === records ? "record" : "set";
		let on: string | undefined;
		do {
			const page = await s.scan(space, on);
			for (const key of page.keys.filter((one) => one.name === name)) {
				const value = (await s.get(key)).entry?.value as { "records:v"?: number } | undefined;
				if (value !== undefined && value["records:v"] !== 1) left.push(String(key.partition));
			}
			on = page.cursor;
		} while (on !== undefined);
		return left;
	};
	for (const subject of subjects) {
		await s.putIfAbsent(
			{ space: records, partition: subject, name: "record" },
			{ owner: subject },
			{
				expiry: { kind: "never" },
			},
		);
		await s.putIfAbsent(
			{ space: sets, partition: `login:${subject}`, name: "set" },
			[["m", 9e15]],
			{
				expiry: { kind: "never" },
			},
		);
	}
	return { at, walk, rawLeft };
}

for (const space of [records, sets]) {
	it(`finishes a walk of ${space.name} whose server changes at its second page, and erasure then removes each`, async () => {
		const { at, walk, rawLeft } = await opened();
		const changing = walk((asked) => (asked === 0 ? "A" : "B"));
		const report =
			space === records
				? await migrateRecords(at(space), changing, byValue)
				: await migrateSets(at(space), changing, byKey);
		expect(report).toEqual({ kind: "migrated", space: space.name, indexed: 4, removed: 0 });
		expect(await rawLeft(space)).toEqual([]);
		for (const subject of subjects) {
			expect(await eraseSubject(at(space), subject)).toMatchObject({ kind: "erased", removed: 1 });
		}
	});
}

it("stops as walk-unsteady, never migrated, where the server changes at every page", async () => {
	const { at, walk } = await opened();
	const every = walk((asked) => String(asked));
	expect(await migrateRecords(at(records), every, byValue)).toMatchObject({
		kind: "stopped",
		reason: "walk-unsteady",
	});
});
