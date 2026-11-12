import type { MigrationReport, SpaceReport, Walk } from "@mod/erasure-extensions";
import { Unavailable } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import { listKeyOf, storedList } from "../../records/records.ts";
import type { FactorStore, StoredFactors } from "../../store.ts";
import { factorEraser, factorSubjectOf } from "../eraser.ts";

const signal = new AbortController().signal;
const walk: Walk = { sweep: async () => ({ keys: [], server: "one" }) };
const factor = (id: string) => ({ id, kind: "card", secret: "", state: null });
const ann = storedList("ann", [factor("f1")]);
const claim = (factorId: string, listKey = listKeyOf("ann")) => ({ listKey, factor: factorId });
const readOf =
	(held: Record<string, StoredFactors | Error>) =>
	async (key: string): Promise<StoredFactors | undefined> => {
		const found = held[key];
		if (found instanceof Error) throw found;
		return found;
	};

describe("mfa's eraser", () => {
	it("reads a list by the subject it holds where its key is that subject's, and a 0.18.0-rc.1 list as unreadable with its remedy", async () => {
		const read = factorSubjectOf({ read: readOf({}) });
		expect(await read(listKeyOf("ann"), ann)).toEqual({ kind: "subject", subject: "ann" });
		expect((await read(listKeyOf("bob"), ann)).kind).toBe("unreadable");
		const rc = await read(listKeyOf("ann"), { factors: [factor("f1")] });
		expect(rc).toMatchObject({
			kind: "unreadable",
			reason: expect.stringMatching(/0\.18\.0-rc\.1.*mfa-reset/),
		});
	});

	it("reads a claim by its list: the list's subject where it holds the factor, an orphan where it does not, unreadable where gone or unread", async () => {
		const held = { [listKeyOf("ann")]: ann, [listKeyOf("dan")]: new Unavailable("store") };
		const read = factorSubjectOf({ read: readOf(held) });
		expect(await read("u-x", claim("f1"))).toEqual({ kind: "subject", subject: "ann" });
		expect(await read("u-x", claim("gone-factor"))).toEqual({ kind: "orphan" });
		for (const value of [
			claim("f1", listKeyOf("cy")),
			claim("f1", listKeyOf("dan")),
			{ ...claim("f1"), x: 1 },
			null,
		]) {
			expect((await read("u-x", value)).kind).toBe("unreadable");
		}
		expect((await read("z-x", ann)).kind).toBe("unreadable");
	});

	it("erases through the store's ports, each subject in a window, and states that it cannot where the store offers none", async () => {
		const asked: string[] = [];
		const report = { kind: "erased", space: "factors", removed: 1 } as unknown as SpaceReport;
		const store = {
			read: readOf({}),
			erase: async (subject: string) => {
				asked.push(subject);
				return report;
			},
			migrate: async () =>
				({ kind: "migrated", space: "factors", indexed: 0, removed: 0 }) as MigrationReport,
		} as unknown as FactorStore;
		const eraser = factorEraser(store);
		expect([eraser.name, eraser.erasable, eraser.after]).toEqual(["mfa", true, undefined]);
		expect(await eraser.online("ann", signal)).toEqual({ reports: [report], logoutGaps: 0 });
		expect((await eraser.window(["bob", "cy"], walk, signal)).reports).toEqual([report, report]);
		expect(await eraser.migrate(walk, signal)).toHaveLength(1);
		expect(asked).toEqual(["ann", "bob", "cy"]);
		const none = factorEraser({ read: readOf({}) } as unknown as FactorStore);
		expect([none.erasable, await none.migrate(walk, signal)]).toEqual([false, []]);
	});
});
