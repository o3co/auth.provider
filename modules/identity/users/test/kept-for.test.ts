import { assemble, isUnavailable, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import secretHashModule from "@mod/secret-hash/module";
import { expect, it, vi } from "vitest";
import { users } from "../src/contract.ts";
import { keptFor } from "../src/kept-for.ts";
import usersModule from "../src/module.ts";
import type { SubjectRecordStore } from "../src/store.ts";
import { memoryUsersStores, testUser, usersConfig } from "../src/testing.ts";

it("saves a link and a verified contact with the subject they are kept for", async () => {
	const stores = memoryUsersStores();
	const linkSave = vi.spyOn(stores.links.store, "save");
	const contactSave = vi.spyOn(stores.contacts.store, "save");
	const app = await assemble({
		modules: [usersModule, secretHashModule, stores.module],
		config: { ...kernelConfig(), ...usersConfig([testUser("alice", "pw")]) },
		runtime: quietRuntime(),
	});
	const people = app.get(users);
	expect(await people.link("s-alice", { idp: "corp", subject: "u-1" })).toBe("linked");
	await people.verifiedContact("s-alice", { kind: "email", value: "a@example.com" });
	expect(linkSave).toHaveBeenCalledWith(
		expect.any(String),
		expect.anything(),
		"endless",
		"s-alice",
	);
	expect(contactSave).toHaveBeenCalledWith("s-alice", expect.anything(), "endless", "s-alice");
});

/** A record store whose saves answer as scripted, finding nothing to change while it does. */
const scripted = (answers: ("created" | "exists")[]): SubjectRecordStore<number> => ({
	save: async () => answers.shift() ?? "created",
	read: async () => undefined,
	update: async () => undefined,
});

it("saves again a record a create met and a read then found gone, never answering it as another's", async () => {
	const kept = await keptFor(
		scripted(["exists", "exists", "created"]),
		"k",
		1,
		() => undefined,
		"s",
	);
	expect(kept).toEqual({ before: undefined, after: 1 });
});

it("is unavailable after a bounded number of such attempts", async () => {
	const always = scripted(Array.from({ length: 20 }, () => "exists" as const));
	await expect(keptFor(always, "k", 1, () => undefined, "s")).rejects.toSatisfy(isUnavailable);
});
