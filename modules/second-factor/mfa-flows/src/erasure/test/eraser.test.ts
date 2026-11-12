import type { MigrationReport, SpaceReport, Walk } from "@mod/erasure-extensions";
import { describe, expect, it } from "vitest";
import type { TransactionListings, TransactionStore } from "../../store.ts";
import { flowsEraser, listingSubjectOf } from "../eraser.ts";
import { portsRefused } from "../ports.ts";

const signal = new AbortController().signal;
const walk: Walk = { sweep: async () => ({ keys: [], server: "one" }) };
const plainStore = {
	save: async () => "created",
	read: async () => undefined,
	update: async () => undefined,
} as unknown as TransactionStore;
const plainListings = {
	add: async () => ({ pushedOut: [] }),
	members: async () => [],
	remove: async () => {},
} as unknown as TransactionListings;
const report = (kind: string, space: string) => ({ kind, space }) as unknown as SpaceReport;
const migrated = (space: string) =>
	({ kind: "migrated", space, indexed: 0, removed: 0 }) as unknown as MigrationReport;

describe("mfa-flows' eraser", () => {
	it("reads a listing's subject from its key: a login's as named, a session's through subjectOf, else unreadable", async () => {
		const read = listingSubjectOf(async (handle) => (handle === "h1" ? "alice" : undefined));
		expect(await read("login:bob")).toEqual({ kind: "subject", subject: "bob" });
		expect(await read("login:a:b")).toEqual({ kind: "subject", subject: "a:b" });
		expect(await read("session:h1")).toEqual({ kind: "subject", subject: "alice" });
		for (const key of ["session:gone", "login:", "session:", "other:x", "x"]) {
			expect((await read(key)).kind).toBe("unreadable");
		}
	});

	it("refuses a part of the four ports, and states that it cannot erase where the stores offer none", async () => {
		expect(portsRefused(plainStore, plainListings)).toBeUndefined();
		const part = { ...plainStore, erase: async () => report("fenced", "t") } as TransactionStore;
		expect(portsRefused(part, plainListings)).toMatch(/part of erase and migrate/);
		const eraser = flowsEraser(plainStore, plainListings, () => ({}));
		expect([eraser.name, eraser.erasable, eraser.after]).toEqual(["mfa-flows", false, undefined]);
		expect(await eraser.online("alice", signal)).toEqual({ reports: [], logoutGaps: 0 });
		expect(await eraser.migrate(walk, signal)).toEqual([]);
	});

	it("fences transactions then erases listings, each subject in a window, and migrates the listings by session", async () => {
		const asked: string[] = [];
		const store = {
			...plainStore,
			erase: async (subject: string) => {
				asked.push(`transactions:${subject}`);
				return report("fenced", "transactions");
			},
			// A bounded space's reading is never asked; one asked is a defect, and says so.
			migrate: async (_: Walk, reading: (key: string, value: unknown) => Promise<unknown>) => {
				await expect(reading("t", {})).rejects.toThrow(/bounded/);
				return migrated("transactions");
			},
		} as unknown as TransactionStore;
		const listings = {
			...plainListings,
			erase: async (subject: string) => {
				asked.push(`listings:${subject}`);
				return report("erased", "listings");
			},
			migrate: async (_: Walk, reading: (key: string) => Promise<{ kind: string }>) => {
				asked.push(`migrate:${(await reading("session:h1")).kind}`);
				return migrated("listings");
			},
		} as unknown as TransactionListings;
		const subjectOf = async () => "alice";
		const eraser = flowsEraser(store, listings, () => ({ subjectOf }));
		expect(eraser.erasable).toBe(true);
		expect(await eraser.online("alice", signal)).toEqual({
			reports: [report("fenced", "transactions"), report("erased", "listings")],
			logoutGaps: 0,
		});
		expect((await eraser.window(["bob", "carol"], walk, signal)).reports).toHaveLength(4);
		expect(await eraser.migrate(walk, signal)).toEqual([
			migrated("transactions"),
			migrated("listings"),
		]);
		expect(asked).toEqual([
			"transactions:alice",
			"listings:alice",
			"transactions:bob",
			"listings:bob",
			"transactions:carol",
			"listings:carol",
			"migrate:subject",
		]);
		// Where `session` offers no subjectOf, the listings stop as the owner's; the transactions still run.
		const without = await flowsEraser(store, listings, () => ({})).migrate(walk, signal);
		expect(without).toEqual([
			migrated("transactions"),
			expect.objectContaining({ kind: "owner-stopped" }),
		]);
	});
});
