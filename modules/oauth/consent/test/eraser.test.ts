import type { MigrationReport, SpaceReport, Walk } from "@mod/erasure-extensions";
import { describe, expect, it } from "vitest";
import { consentEraser } from "../src/eraser.ts";
import { grantSubjectOf } from "../src/grants/grants.ts";
import type { AskStore, GrantStore } from "../src/store.ts";

const signal = new AbortController().signal;
const walk: Walk = { sweep: async () => ({ keys: [], server: "one" }) };
const plain = {
	save: async () => "created" as const,
	read: async () => undefined,
	update: async () => undefined,
};
const reported = (space: string) =>
	({ kind: "erased", space, removed: 1 }) as unknown as SpaceReport;

describe("consent's eraser", () => {
	it("reads a grant's subject from its key, and proves nothing from a key of another shape", async () => {
		expect(await grantSubjectOf(JSON.stringify(["alice", "app"]), {})).toEqual({
			kind: "subject",
			subject: "alice",
		});
		for (const key of ["alice", JSON.stringify(["alice"]), JSON.stringify([1, "app"])]) {
			expect((await grantSubjectOf(key, {})).kind).toBe("unreadable");
		}
	});

	it("states that it cannot erase where a Store lacks the ports, answering empty reports", async () => {
		const eraser = consentEraser(plain as GrantStore, plain as AskStore);
		expect([eraser.name, eraser.erasable]).toEqual(["consent", false]);
		expect(await eraser.online("alice", signal)).toEqual({ reports: [], logoutGaps: 0 });
		expect(await eraser.migrate(walk, signal)).toEqual([]);
	});

	it("passes on its Stores' reports, grants then asks, each subject in a window, and migrates grants by their keys", async () => {
		const asked: string[] = [];
		const store = (space: string) => ({
			...plain,
			erase: async (subject: string) => {
				asked.push(`${space} ${subject}`);
				return reported(space);
			},
			migrate: async (_walk: Walk, reading: typeof grantSubjectOf) => {
				const read = await reading(JSON.stringify(["bob", "app"]), {}).then(
					(one) => one.kind,
					() => "refused to read",
				);
				asked.push(`${space} ${read}`);
				return { kind: "migrated", space, indexed: 0, removed: 0 } as unknown as MigrationReport;
			},
		});
		const eraser = consentEraser(store("grants") as GrantStore, store("asks") as AskStore);
		expect(eraser.erasable).toBe(true);
		expect((await eraser.online("alice", signal)).reports).toEqual([
			reported("grants"),
			reported("asks"),
		]);
		expect((await eraser.window(["bob", "carol"], walk, signal)).reports).toHaveLength(4);
		expect(await eraser.migrate(walk, signal)).toHaveLength(2);
		expect(asked).toEqual([
			"grants alice",
			"asks alice",
			"grants bob",
			"asks bob",
			"grants carol",
			"asks carol",
			"grants subject",
			"asks refused to read",
		]);
	});
});
