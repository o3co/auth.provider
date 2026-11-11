import type { Elsewhere, SubjectReading } from "@mod/erasure-extensions";
import { isUnavailable } from "@mod/kernel";
import { expect, it } from "vitest";
import { contactSubjectOf } from "../../ledger.ts";
import { linkSubjectOf } from "../../links/reading.ts";
import { isNameKey, nameSubjectOf, namesKept } from "../../names/elsewhere.ts";
import type { ContactStore, LinkStore, NameStore, StoredName } from "../../store.ts";
import { memoryUsersStores } from "../../testing.ts";
import { type ErasureReadings, usersEraser } from "../eraser.ts";

/** The readings as the package composes them, each from the module owning its records. */
const readings: ErasureReadings = {
	links: async (key, value) => (isNameKey(key) ? nameSubjectOf(value) : linkSubjectOf(value)),
	contacts: async (key, value) => contactSubjectOf(key, value),
	namesKept,
};
const walk = { sweep: async () => ({ keys: [], server: "s" }) };
const signal = new AbortController().signal;

/** Stores offering every port, noting what each erase and migrate was given. */
function ported() {
	const memory = memoryUsersStores({ names: true });
	const seen: { erased: string[]; readings: SubjectReading[]; elsewhere?: Elsewhere } = {
		erased: [],
		readings: [],
	};
	const report = (space: string) => ({ kind: "erased", space, removed: 0 }) as never;
	const links = {
		...(memory.links.store as unknown as LinkStore),
		names: memory.names.store,
		unowned: async () => "created" as const,
		remove: async () => "removed" as const,
		erase: async (subject: string) => {
			seen.erased.push(`links ${subject}`);
			return report("users-store.links");
		},
		migrate: async (_w: unknown, reading: SubjectReading, _s: unknown, elsewhere?: Elsewhere) => {
			seen.readings.push(reading);
			if (elsewhere) seen.elsewhere = elsewhere;
			return { kind: "migrated", space: "users-store.links", indexed: 0, removed: 0 } as never;
		},
	} as LinkStore;
	const contacts = {
		...(memory.contacts.store as unknown as ContactStore),
		erase: async (subject: string) => {
			seen.erased.push(`contacts ${subject}`);
			return report("users-store.contacts");
		},
		migrate: async (_w: unknown, reading: SubjectReading) => {
			seen.readings.push(reading);
			return { kind: "migrated", space: "users-store.contacts", indexed: 0, removed: 0 } as never;
		},
	} as ContactStore;
	return { memory, links, contacts, seen };
}

it("is erasable only where the link store offers its whole set and the contact store its erase and migrate", async () => {
	const memory = memoryUsersStores({ names: true });
	const bare = usersEraser(
		memory.links.store as unknown as LinkStore,
		memory.contacts.store,
		readings,
	);
	expect([bare.name, bare.erasable]).toEqual(["users", false]);
	expect(await bare.online("s-a", signal)).toEqual({ reports: [], logoutGaps: 0 });
	const { links, contacts } = ported();
	expect(usersEraser(links, contacts, readings).erasable).toBe(true);
	const { names: _dropped, ...withoutNames } = links;
	expect(usersEraser(withoutNames, contacts, readings).erasable).toBe(false);
});

it("erases a subject's links and contacts through the stores' ports, for each subject of a window", async () => {
	const { links, contacts, seen } = ported();
	const eraser = usersEraser(links, contacts, readings);
	expect((await eraser.online("s-a", signal)).reports).toHaveLength(2);
	await eraser.window(["s-b", "s-c"], walk, signal);
	expect(seen.erased).toEqual([
		"links s-a",
		"contacts s-a",
		"links s-b",
		"contacts s-b",
		"links s-c",
		"contacts s-c",
	]);
});

it("reads a link as its subject's, a trace and a name's record as orphans, a contact list as its key's, and any other shape as proving nothing", async () => {
	const { links, contacts, seen } = ported();
	await usersEraser(links, contacts, readings).migrate(walk, signal);
	const [inLinks, inContacts] = seen.readings;
	const link = JSON.stringify(["corp", "u-1"]);
	const name = JSON.stringify({ idp: "corp" });
	expect(await inLinks?.(link, { subject: "s-a" })).toEqual({ kind: "subject", subject: "s-a" });
	expect(await inLinks?.(link, { subject: null })).toEqual({ kind: "orphan" });
	expect(await inLinks?.(name, { issuer: "https://a.example" })).toEqual({ kind: "orphan" });
	expect((await inLinks?.(link, { subject: 7 }))?.kind).toBe("unreadable");
	expect((await inLinks?.(name, { issuer: 7 }))?.kind).toBe("unreadable");
	// A name's key holding more than its issuer may hold a subject's data: it proves nothing, so nothing is copied out.
	const carrying = { issuer: "A", subject: "s-a", email: "a@example.com" };
	expect((await inLinks?.(name, carrying))?.kind).toBe("unreadable");
	expect(await inContacts?.("s-a", [])).toEqual({ kind: "subject", subject: "s-a" });
	expect((await inContacts?.("s-a", { list: [] }))?.kind).toBe("unreadable");
});

it("keeps a name's record in the name store before it goes, as the link space holds it, and nothing for a trace", async () => {
	const { links, contacts, seen, memory } = ported();
	await usersEraser(links, contacts, readings).migrate(walk, signal);
	const name = JSON.stringify({ idp: "corp" });
	const kept = { issuer: "https://a.example" };
	await seen.elsewhere?.(name, kept);
	expect(await memory.names.store.read(name)).toEqual(kept);
	// The link space is the authority: a differing copy is rewritten to it.
	await memory.names.store.update(name, () => ({ value: { issuer: "x" } as never }));
	await seen.elsewhere?.(name, kept);
	expect(await memory.names.store.read(name)).toEqual(kept);
	await seen.elsewhere?.(JSON.stringify(["corp", "u-1"]), { subject: null });
	expect(await memory.names.store.read(JSON.stringify(["corp", "u-1"]))).toBeUndefined();
});

it("does not let a name's record go where the name store does not read back what it kept", async () => {
	const forgetting: NameStore = {
		save: async () => "created",
		read: async () => undefined,
		update: async () => undefined,
	};
	const step = namesKept(forgetting);
	const kept = { issuer: "https://a.example" } as unknown as StoredName;
	await expect(step(JSON.stringify({ idp: "corp" }), kept)).rejects.toSatisfy(isUnavailable);
});
