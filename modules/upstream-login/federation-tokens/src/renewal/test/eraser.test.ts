import type { MigrationReport, SpaceReport, SubjectReading, Walk } from "@mod/erasure-extensions";
import { Unavailable } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import type { UpstreamTokenStore } from "../../store.ts";
import { tokensEraser, tokensSubjectOf } from "../eraser.ts";

const signal = new AbortController().signal;
const walk: Walk = { sweep: async () => ({ keys: [], server: "one" }) };
const nothing = async () => undefined;
const plain = {
	save: async () => "created" as const,
	read: nothing,
	update: nothing,
	remove: nothing,
	scan: async () => ({ keys: [] }),
};
const erased = { kind: "erased", space: "tokens", removed: 1 } as unknown as SpaceReport;
const migrated = { kind: "migrated", space: "tokens", indexed: 1, removed: 0 } as MigrationReport;

describe("federation-tokens' eraser", () => {
	it("reads a record's subject through its session's record, and one with none as unreadable", async () => {
		const asked: string[] = [];
		const reading = tokensSubjectOf(async (handle) => {
			asked.push(handle);
			return handle === "s-1" ? "alice" : undefined;
		});
		expect(await reading("s-1", {})).toEqual({ kind: "subject", subject: "alice" });
		expect((await reading("s-2", {})).kind).toBe("unreadable");
		expect(asked).toEqual(["s-1", "s-2"]);
		// A session that cannot tell throws, which stops the space; it is never an orphan.
		const failing = tokensSubjectOf(async () => {
			throw new Unavailable("session");
		});
		await expect(failing("s-1", {})).rejects.toBeInstanceOf(Unavailable);
	});

	it("states that it cannot erase where the store lacks the ports, answering empty reports", async () => {
		const eraser = tokensEraser(plain as unknown as UpstreamTokenStore, () => ({}));
		expect([eraser.name, eraser.erasable]).toEqual(["federation-tokens", false]);
		expect(await eraser.online("alice", signal)).toEqual({ reports: [], logoutGaps: 0 });
		expect(await eraser.migrate(walk, signal)).toEqual([]);
	});

	it("passes on the store's report, each subject in a window, and migrates by the session's subjectOf", async () => {
		const asked: string[] = [];
		const store = {
			...plain,
			erase: async (subject: string) => {
				asked.push(subject);
				return erased;
			},
			migrate: async (_walk: Walk, reading: SubjectReading) => {
				asked.push((await reading("s-1", {})).kind);
				return migrated;
			},
		};
		const eraser = tokensEraser(store as unknown as UpstreamTokenStore, () => ({
			subjectOf: async () => "alice",
		}));
		expect(eraser.erasable).toBe(true);
		expect(await eraser.online("alice", signal)).toEqual({ reports: [erased], logoutGaps: 0 });
		expect((await eraser.window(["bob", "carol"], walk, signal)).reports).toEqual([erased, erased]);
		expect(await eraser.migrate(walk, signal)).toEqual([migrated]);
		expect(asked).toEqual(["alice", "bob", "carol", "subject"]);
	});

	it("stops its migration as the owner, reading no record, where session offers no subjectOf", async () => {
		let read = 0;
		const store = {
			...plain,
			erase: async () => erased,
			migrate: async () => {
				read += 1;
				return migrated;
			},
		};
		const eraser = tokensEraser(store as unknown as UpstreamTokenStore, () => ({}));
		expect(await eraser.migrate(walk, signal)).toEqual([
			{
				kind: "owner-stopped",
				reason:
					"session offers no subjectOf: records kept by session handle cannot be read; 0.22 requires it",
			},
		]);
		expect(read).toBe(0);
	});
});
