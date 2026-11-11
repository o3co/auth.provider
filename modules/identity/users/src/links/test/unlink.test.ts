import { expect, it } from "vitest";
import { none, type UserSource } from "../../registered.ts";
import type { LinkStore, StoredLink } from "../../store.ts";
import { keptLinks } from "../kept.ts";

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
