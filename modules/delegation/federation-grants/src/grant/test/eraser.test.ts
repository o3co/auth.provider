import type { SetReading, SpaceReport, SubjectReading, Walk } from "@mod/erasure-extensions";
import { expect, it } from "vitest";
import type { StoredGrant } from "../../store.ts";
import { grantSubjectOf, grantsEraser, pairSubjectOf } from "../eraser.ts";
import type { Grant } from "../grant.ts";
import type { ErasedStores } from "../ports.ts";

const signal = new AbortController().signal;
const walk: Walk = { sweep: async () => ({ keys: [], server: "one" }) };
const grantOf = (stored: StoredGrant | undefined) =>
	(stored as { subject?: string } | undefined)?.subject === undefined
		? undefined
		: (stored as unknown as Grant);

it("reads a grant's subject from its record, and a pending pair's from its key, anything else unreadable", async () => {
	const reading = grantSubjectOf(grantOf);
	expect(await reading("g", { subject: "alice" })).toEqual({ kind: "subject", subject: "alice" });
	expect((await reading("g", { other: 1 })).kind).toBe("unreadable");
	expect(await pairSubjectOf("app\nalice")).toEqual({ kind: "subject", subject: "alice" });
	for (const key of ["alice", "\nalice", "app\n"])
		expect((await pairSubjectOf(key)).kind).toBe("unreadable");
});

it("states it cannot erase without the stores' ports, and erases and migrates each space through them", async () => {
	const none = { grants: {}, pending: {}, subjects: {} } as unknown as ErasedStores;
	expect(grantsEraser(none, grantOf)).toMatchObject({ name: "federation-grants", erasable: false });
	const asked: string[] = [];
	const store = (space: string) => ({
		erase: async (subject: string) => {
			asked.push(`${space}:${subject}`);
			return { kind: "erased", space } as unknown as SpaceReport;
		},
		migrate: async (_walk: Walk, reading: SubjectReading | SetReading) => {
			const read =
				space === "grants"
					? await (reading as SubjectReading)("g", { subject: "a" })
					: await (reading as SetReading)("app\na");
			asked.push(`${space}:${read.kind}`);
			return { kind: "migrated", space } as never;
		},
	});
	const stores = {
		grants: store("grants"),
		pending: store("pending"),
		subjects: store("subjects"),
	};
	const eraser = grantsEraser(stores as unknown as ErasedStores, grantOf);
	expect(eraser.erasable).toBe(true);
	expect((await eraser.online("alice", signal)).reports).toHaveLength(3);
	expect((await eraser.window(["bob"], walk, signal)).reports).toHaveLength(3);
	expect(await eraser.migrate(walk, signal)).toHaveLength(3);
	// The listing's reading is never one that indexes: keyed by its subject, it has none to read.
	expect(asked.slice(-3)).toEqual(["grants:subject", "pending:subject", "subjects:unreadable"]);
});
