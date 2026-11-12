import type { MigrationReport, SpaceReport, Walk } from "@mod/erasure-extensions";
import { describe, expect, it } from "vitest";
import type { SessionStore, StoredSession, SubjectSessions } from "../../store.ts";
import { sessionEraser, sessionSubjectOf } from "../eraser.ts";
import { portsRefused } from "../ports.ts";

const signal = new AbortController().signal;
const now = 1_800_000_000_000;
const lifetime = { clock: { now: () => now }, lifetimeMs: 3_600_000 };
const walk: Walk = { sweep: async () => ({ keys: [], server: "one" }) };
const kept = {
	save: async () => "created",
	read: async () => undefined,
	update: async () => undefined,
};
const listed = {
	add: async () => ({ pushedOut: [] }),
	members: async () => [],
	remove: async () => {},
};
const report = (space: string) => ({ kind: "erased", space, removed: 0 }) as unknown as SpaceReport;
const migrated = (space: string) =>
	({ kind: "migrated", space, indexed: 0, removed: 0 }) as unknown as MigrationReport;
const record = (state: string, openedAt = now) => ({
	format: 2,
	state,
	subject: "alice",
	amr: ["pwd"],
	authenticatedAt: openedAt,
	openedAt,
});
const stored = (value: unknown) => value as StoredSession;

describe("session-lifecycle's eraser", () => {
	it("reads a record's subject from it, a closed mark as an orphan, and anything else as unreadable", async () => {
		expect(await sessionSubjectOf("h", record("open"))).toEqual({
			kind: "subject",
			subject: "alice",
		});
		expect(await sessionSubjectOf("h", record("closed"))).toEqual({
			kind: "subject",
			subject: "alice",
		});
		expect(await sessionSubjectOf("h", { format: 2, state: "closed" })).toEqual({ kind: "orphan" });
		for (const value of [
			{ format: 2, state: "closed", extra: 1 },
			null,
			{ ...record("open"), x: 1 },
		]) {
			expect((await sessionSubjectOf("h", value)).kind).toBe("unreadable");
		}
	});

	it("refuses a part of the four ports, and states that it cannot erase where the stores offer none", async () => {
		const erase = async () => report("x");
		expect(
			portsRefused(kept as unknown as SessionStore, listed as unknown as SubjectSessions),
		).toBeUndefined();
		const part = { ...kept, erase, migrate: async () => migrated("x") };
		expect(
			portsRefused(part as unknown as SessionStore, listed as unknown as SubjectSessions),
		).toMatch(/part of erase and migrate/);
		const eraser = sessionEraser(
			kept as unknown as SessionStore,
			listed as unknown as SubjectSessions,
			lifetime,
		);
		expect([eraser.name, eraser.erasable]).toEqual(["session-lifecycle", false]);
		expect(await eraser.online("alice", signal)).toEqual({ reports: [], logoutGaps: 0 });
		expect(await eraser.migrate(walk, signal)).toEqual([]);
	});

	it("erases sessions then the listing, counting each open, closing or unreadable session removed as a logout gap", async () => {
		const asked: string[] = [];
		// An open session past the lifetime in force is owed no logout: no participant is called on its end alone.
		const expired = record("open", now - lifetime.lifetimeMs);
		const removed = [
			record("open"),
			expired,
			record("closing"),
			record("closed"),
			{ format: 9 },
		].map(stored);
		const sessions = {
			...kept,
			erase: async (subject: string, _: AbortSignal, each?: (r: StoredSession) => void) => {
				asked.push(`sessions:${subject}`);
				for (const one of removed) each?.(one);
				return report("sessions");
			},
			migrate: async (
				_: Walk,
				reading: (key: string, value: unknown) => Promise<{ kind: string }>,
			) => {
				asked.push(`migrate:${(await reading("h", record("open"))).kind}`);
				return migrated("sessions");
			},
		};
		const listing = {
			...listed,
			erase: async (subject: string) => {
				asked.push(`listing:${subject}`);
				return report("subjects");
			},
			migrate: async () => migrated("subjects"),
		};
		const eraser = sessionEraser(
			sessions as unknown as SessionStore,
			listing as unknown as SubjectSessions,
			lifetime,
		);
		expect(eraser.erasable).toBe(true);
		expect(await eraser.online("alice", signal)).toEqual({
			reports: [report("sessions"), report("subjects")],
			logoutGaps: 3,
		});
		const window = await eraser.window(["bob", "carol"], walk, signal);
		expect([window.reports.length, window.logoutGaps]).toEqual([4, 6]);
		expect(await eraser.migrate(walk, signal)).toEqual([
			migrated("sessions"),
			migrated("subjects"),
		]);
		expect(asked).toEqual([
			"sessions:alice",
			"listing:alice",
			"sessions:bob",
			"listing:bob",
			"sessions:carol",
			"listing:carol",
			"migrate:subject",
		]);
	});
});
