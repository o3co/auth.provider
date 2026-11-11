import { isUnavailable } from "@mod/kernel";
import { expect, it } from "vitest";
import { keptLinks } from "../../links/kept.ts";
import { none, type UserSource } from "../../registered.ts";
import type { ContactStore, LinkStore, NameStore, StoredLink } from "../../store.ts";
import { keptFor } from "../kept-for.ts";
import { portsRefused } from "../ports.ts";

const nothing = async () => undefined;
const base = { save: async () => "created" as const, read: nothing, update: nothing };
const ports = {
	remove: async () => "removed" as const,
	erase: async () => ({}) as never,
	migrate: async () => ({}) as never,
};
const names = base as unknown as NameStore;
const unowned = async () => "created" as const;

it("takes a link store's remove, erase and migrate as one set, with names, and a contact store's erase and migrate together", () => {
	const contacts = base as ContactStore;
	const links = (more: object) => ({ ...base, ...more }) as LinkStore;
	expect(portsRefused(links({}), contacts)).toBeUndefined();
	expect(portsRefused(links({ ...ports, names, unowned }), contacts)).toBeUndefined();
	expect(portsRefused(links({ remove: ports.remove, names, unowned }), contacts)).toBe(
		"the link store offers part of remove, erase and migrate: it offers all three, or none",
	);
	expect(portsRefused(links(ports), contacts)).toBe(
		"the link store offers erase and migrate without names: names would stay in the link space",
	);
	expect(portsRefused(links({}), { ...contacts, erase: ports.erase })).toBe(
		"the contact store offers one of erase and migrate: it offers both, or neither",
	);
});

/** A link store holding links in a map, removing only where the check holds, as one write. */
function removing() {
	const held = new Map<string, StoredLink>();
	const links: LinkStore = {
		save: async (key, record) => {
			if (held.has(key)) return "exists";
			held.set(key, record);
			return "created";
		},
		read: async (key) => held.get(key),
		update: async (key, change) => {
			const before = held.get(key);
			if (before === undefined) return undefined;
			const after = change(before)?.value ?? before;
			held.set(key, after);
			return { before, after };
		},
		remove: async (key, when) => {
			const record = held.get(key);
			if (record === undefined) return "missing";
			if (!when(record)) return "left";
			held.delete(key);
			return "removed";
		},
	};
	return { links, held };
}
const source: UserSource = {
	verify: async () => none,
	bySubject: async (subject) => ({ kind: "user", user: { subject, attributes: {} } }) as never,
	byUpstream: async () => none,
};

it("unlinks by removing the link while it is still the subject's, leaving no trace and never another's link", async () => {
	const { links, held } = removing();
	const linking = keptLinks(source, links);
	const upstream = { idp: "corp", subject: "u-1" };
	expect(await linking.link("s-a", upstream)).toBe("linked");
	expect(await linking.unlink("s-a", upstream)).toBe("unlinked");
	expect(held.size).toBe(0);
	// A's unlink, late, after B linked the identity: B's link stays.
	expect(await linking.link("s-b", upstream)).toBe("linked");
	expect(await linking.unlink("s-a", upstream)).toBe("none");
	expect([...held.values()]).toEqual([{ subject: "s-b" }]);
});

it("is unavailable where the store answers that the subject is erased, never another's answer", async () => {
	const erased = { ...base, save: async () => "erased" as const };
	await expect(keptFor(erased, "k", 1, () => undefined, "s-gone")).rejects.toSatisfy(isUnavailable);
});
