import type { MigrationReport, SpaceReport, SubjectReading, Walk } from "@mod/erasure-extensions";
import type { Entry } from "@mod/session";
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
const entered = (subject: string): Entry =>
	({ kind: "entered", session: { id: "s", context: { subject } }, endsAt: 1 }) as unknown as Entry;

describe("federation-tokens' eraser", () => {
	it("reads a record's subject from its session, at no requirement, and a session that no longer enters as unreadable", async () => {
		const asked: unknown[] = [];
		const reading = tokensSubjectOf({
			entryOf: async (handle, level) => {
				asked.push([handle, level]);
				return handle === "s-1" ? entered("alice") : { kind: "absent" };
			},
		});
		expect(await reading("s-1", {})).toEqual({ kind: "subject", subject: "alice" });
		expect((await reading("s-2", {})).kind).toBe("unreadable");
		expect(asked).toEqual([
			["s-1", "none"],
			["s-2", "none"],
		]);
	});

	it("states that it cannot erase where the store lacks the ports, answering empty reports", async () => {
		const eraser = tokensEraser(plain as unknown as UpstreamTokenStore, {
			entryOf: nothing as never,
		});
		expect([eraser.name, eraser.erasable]).toEqual(["federation-tokens", false]);
		expect(await eraser.online("alice", signal)).toEqual({ reports: [], logoutGaps: 0 });
		expect(await eraser.migrate(walk, signal)).toEqual([]);
	});

	it("passes on the store's report, each subject in a window, and migrates by the session's subject", async () => {
		const asked: string[] = [];
		const store = {
			...plain,
			erase: async (subject: string) => {
				asked.push(subject);
				return erased;
			},
			migrate: async (_walk: Walk, reading: SubjectReading) => {
				asked.push((await reading("s-1", {})).kind);
				return { kind: "migrated", space: "tokens", indexed: 1, removed: 0 } as MigrationReport;
			},
		};
		const eraser = tokensEraser(store as unknown as UpstreamTokenStore, {
			entryOf: async () => entered("alice"),
		});
		expect(eraser.erasable).toBe(true);
		expect(await eraser.online("alice", signal)).toEqual({ reports: [erased], logoutGaps: 0 });
		expect((await eraser.window(["bob", "carol"], walk, signal)).reports).toEqual([erased, erased]);
		expect(await eraser.migrate(walk, signal)).toHaveLength(1);
		expect(asked).toEqual(["alice", "bob", "carol", "subject"]);
	});
});
