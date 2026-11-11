import { isUnavailable } from "@mod/kernel";
import { expect, it } from "vitest";
import type { ContactStore, LinkStore, NameStore } from "../../store.ts";
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
	expect(portsRefused(links({ ...ports, issuers: names, unowned }), contacts)).toBeUndefined();
	// Names may be copied apart with no erasure ports: issuers and unowned alone.
	expect(portsRefused(links({ issuers: names, unowned }), contacts)).toBeUndefined();
	expect(portsRefused(links({ issuers: names }), contacts)).toBe(
		"the link store offers one of issuers and unowned: it offers both, for names to be copied apart, or neither",
	);
	expect(portsRefused(links({ remove: ports.remove, issuers: names, unowned }), contacts)).toBe(
		"the link store offers part of remove, erase and migrate: it offers all three, or none",
	);
	expect(portsRefused(links(ports), contacts)).toBe(
		"the link store offers erase and migrate without issuers: names would stay in the link space",
	);
	expect(portsRefused(links({}), { ...contacts, erase: ports.erase })).toBe(
		"the contact store offers one of erase and migrate: it offers both, or neither",
	);
});

it("is unavailable where the store answers that the subject is erased, never another's answer", async () => {
	const erased = { ...base, save: async () => "erased" as const };
	await expect(keptFor(erased, "k", 1, () => undefined, "s-gone")).rejects.toSatisfy(isUnavailable);
});
