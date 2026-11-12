import type { SetReading } from "@mod/erasure-extensions";
import type { Json, Space } from "@mod/store";
import { expect, it } from "vitest";
import { migrateSets, subjectKeyedSetsIn } from "../src/subject-records.ts";
import { bucketOf, envelope, placed } from "./placed.ts";

const g = ["durable"] as const;
const indexed: Space = { name: "sets-test", guarantees: g, subjectData: "online-indexed" };
const keyed: Space = { name: "sets-keyed", guarantees: g, subjectData: "online-keyed" };
const refuse = (where: string, reason: string): never => {
	throw new Error(`${where}: ${reason}`);
};
const now = 1_000_000;

/** The owner's reading from the key alone: `login:<subject>` a subject's, `gone:` an orphan, else unreadable. */
const byKey: SetReading = async (key) => {
	const [form, subject] = key.split(":");
	if (form === "login" && subject) return { kind: "subject", subject };
	if (form === "gone") return { kind: "orphan" };
	return { kind: "unreadable", reason: "a key of another form" };
};

/** The helper's place, its sets' clock at `now`, values written and read as sets. */
async function opened() {
	const p = await placed([indexed, keyed]);
	return {
		...p,
		at: (space: Space, phase: "reader" | "indexed" = "indexed") => p.at(space, phase, now),
		put: (space: Space, partition: string, value: Json) =>
			p.put(space, partition, value, 600_000, "set"),
		raw: (space: Space, partition: string) => p.raw(space, partition, "set"),
	};
}

it("indexes each raw set its owner reads by key as a subject's, whole with every member's end and its own end, and removes each proven an orphan", async () => {
	const { at, walk, put, raw, index } = await opened();
	// Kept as both formats keep them: an ended member and one awaiting included, and over the cap.
	const full = {
		held: Array.from({ length: 12 }, (_, i) => [`m${i}`, now + i * 1000]),
		awaiting: [["out", now - 5]],
	};
	await put(indexed, "login:alice", full);
	await put(indexed, "login:bob", [["b1", now + 10]]);
	await put(indexed, "gone:x", [["x1", now + 10]]);
	const ends = (await raw(indexed, "login:alice"))?.expiresAt;
	expect(await migrateSets(at(indexed), walk(), byKey)).toEqual({
		kind: "migrated",
		space: indexed.name,
		indexed: 2,
		removed: 1,
	});
	// Wrapped whole: nothing rebuilt through an add, so no cap applied again, and its end kept.
	expect((await raw(indexed, "login:alice"))?.value).toEqual(envelope("alice", full));
	expect((await raw(indexed, "login:alice"))?.expiresAt).toBe(ends);
	expect((await raw(indexed, "login:bob"))?.value).toEqual(envelope("bob", [["b1", now + 10]]));
	expect(await index(indexed, "alice", bucketOf("login:alice"))).toEqual([["login:alice", "set"]]);
	expect(await raw(indexed, "gone:x")).toBeNull();
	// What the owner reads once indexed is the set as it was: its live members, `m0` ended at `now`.
	const sets = subjectKeyedSetsIn(at(indexed), "w", refuse);
	expect((await sets.members("login:alice")).map((m) => m.member)).toHaveLength(11);
	expect(await sets.awaiting("login:alice")).toEqual([]);
	// Again, a key met twice in a walk too: every set is migrated already.
	expect(await migrateSets(at(indexed), walk(true), byKey)).toMatchObject({
		kind: "migrated",
		indexed: 0,
		removed: 0,
	});
});

it("stops the space at a set with any malformed part, or one its owner cannot read, removing nothing more", async () => {
	const { at, walk, put, raw } = await opened();
	await put(indexed, "login:alice", { held: [["a", now], ["b"]] });
	const malformed = await migrateSets(at(indexed), walk(), byKey);
	expect(malformed).toMatchObject({ kind: "stopped", space: indexed.name });
	expect((malformed as { reason: string }).reason).toMatch(/^unreadable: /);
	expect((await raw(indexed, "login:alice"))?.value).toEqual({ held: [["a", now], ["b"]] });
	const { at: at2, walk: walk2, put: put2, raw: raw2 } = await opened();
	await put2(indexed, "session:h", [["a", now]]);
	await put2(indexed, "gone:y", [["y", now]]);
	const unread = await migrateSets(at2(indexed), walk2(), byKey);
	expect((unread as { reason: string }).reason).toBe("unreadable: a key of another form");
	expect(await raw2(indexed, "session:h")).not.toBeNull();
});

it("stops where sets are not indexed, and finds none to index in an online-keyed space", async () => {
	const { at, walk, put } = await opened();
	await put(keyed, "alice", [["a", now]]);
	expect(await migrateSets(at(indexed, "reader"), walk(), byKey)).toMatchObject({
		kind: "stopped",
		reason: "not-indexed",
	});
	// Erasing a subject removes what is under its key, raw or not; the next add envelopes it.
	expect(await migrateSets(at(keyed), walk(), byKey)).toEqual({
		kind: "migrated",
		space: keyed.name,
		indexed: 0,
		removed: 0,
	});
});

it("reads a set changed while its owner read it again, and wraps the value it then holds whole", async () => {
	const { s, at, walk, put, raw } = await opened();
	const both: Json = [
		["a", now + 10],
		["b", now + 20],
	];
	await put(indexed, "login:alice", [["a", now + 10]]);
	let added = false;
	const meanwhile: SetReading = async (key) => {
		if (!added) {
			added = true;
			const version = (await raw(indexed, key))?.version ?? "";
			const at = { space: indexed, partition: key, name: "set" };
			await s.replaceIf(at, version, both, { expiry: { kind: "keep" } });
		}
		return byKey(key);
	};
	expect(await migrateSets(at(indexed), walk(), meanwhile)).toMatchObject({ indexed: 1 });
	expect((await raw(indexed, "login:alice"))?.value).toEqual(envelope("alice", both));
});
