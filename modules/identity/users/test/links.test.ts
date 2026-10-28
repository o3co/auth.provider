import { assemble, BootRefused, defineModule, kernelConfig } from "@mod/kernel";
import { takesUnused } from "@mod/kernel/testing";
import secretHashModule from "@mod/secret-hash/module";
import { describe, expect, it } from "vitest";
import { contactStore, type Ledger, ledgers, users, type Verified } from "../src/contract.ts";
import { keptLinks } from "../src/links/kept.ts";
import { ledgerLinks } from "../src/links/ledger.ts";
import usersModule from "../src/module.ts";
import type { UserSource } from "../src/registered.ts";
import { linkStore } from "../src/store.ts";
import { memoryUsersStores } from "../src/testing.ts";

const alice = { subject: "s-alice", attributes: {} };
const none: Verified = { kind: "none" };
const device = { idp: "device", subject: "thumb-1" };

/** A source holding alice by subject, tying the device to her where `tied`. */
const sourceOf = (tied: boolean): UserSource => ({
	verify: async () => none,
	bySubject: async (subject) => (subject === alice.subject ? { kind: "user", user: alice } : none),
	byUpstream: async () => (tied ? { kind: "user", user: alice } : none),
});

describe("links kept here", () => {
	it("writes a link to the store and finds its subject's user by it", async () => {
		const stores = memoryUsersStores();
		const linking = keptLinks(sourceOf(false), stores.links.store);
		expect(await linking.link("s-alice", device)).toBe("linked");
		expect(await linking.byUpstream(device.idp, device.subject)).toEqual({
			kind: "user",
			user: alice,
		});
		expect(await linking.unlink("s-alice", device)).toBe("unlinked");
		expect(await linking.byUpstream(device.idp, device.subject)).toEqual(none);
	});

	it("answers by the source's link first, which cannot be unlinked", async () => {
		const linking = keptLinks(sourceOf(true), memoryUsersStores().links.store);
		expect(await linking.link("s-alice", device)).toBe("already");
		expect(await linking.link("s-bob", device)).toBe("conflict");
		expect(await linking.unlink("s-alice", device)).toBe("fixed");
	});
});

describe("links the ledger holds", () => {
	it("answers by the source alone, linking and unlinking nothing", async () => {
		const tied = ledgerLinks(sourceOf(true));
		expect(await tied.byUpstream(device.idp, device.subject)).toEqual({
			kind: "user",
			user: alice,
		});
		expect(await tied.link("s-alice", device)).toBe("already");
		expect(await tied.link("s-bob", device)).toBe("conflict");
		expect(await tied.unlink("s-alice", device)).toBe("fixed");
		expect(await tied.unlink("s-bob", device)).toBe("none");
		const untied = ledgerLinks(sourceOf(false));
		expect(await untied.byUpstream(device.idp, device.subject)).toEqual(none);
		expect(await untied.link("s-alice", device)).toBe("conflict");
		expect(await untied.unlink("s-alice", device)).toBe("none");
	});
});

describe("the link store users asks for", () => {
	const ledgerOf = (byUpstream?: Ledger["byUpstream"]): Ledger => ({
		verify: async () => none,
		bySubject: async () => none,
		...(byUpstream ? { byUpstream } : {}),
	});
	const contactsOnly = defineModule(
		{ name: "contacts-only", replicaSafe: false, takes: [] },
		(m) => [m.provide(contactStore).by(() => memoryUsersStores().contacts.store)],
	);
	/** A link store that keeps in memory and lists each method asked of it. */
	const countedLinks = (asked: string[]) =>
		defineModule({ name: "counted-links", replicaSafe: false, takes: [] }, (m) => [
			m.provide(linkStore).by(() => {
				const store = memoryUsersStores().links.store;
				return new Proxy(store, {
					get(target, name, receiver) {
						const value = Reflect.get(target, name, receiver);
						if (typeof value !== "function") return value;
						return (...args: unknown[]) => {
							asked.push(String(name));
							return value.apply(target, args);
						};
					},
				});
			}),
		]);
	const parts = (ledger: Ledger | undefined, links: readonly ReturnType<typeof countedLinks>[]) => [
		usersModule,
		secretHashModule,
		contactsOnly,
		...links,
		...(ledger
			? [
					defineModule({ name: "test-ledger", replicaSafe: false, takes: [] }, (m) => [
						m.contribute(ledgers).by(() => ledger),
					]),
				]
			: []),
	];
	const config = { ...kernelConfig(), users: {} };
	const boot = (ledger?: Ledger, links: readonly ReturnType<typeof countedLinks>[] = []) =>
		assemble({ modules: parts(ledger, links), config });

	it("is never asked where the ledger looks users up by upstream identity", async () => {
		const asked: string[] = [];
		const app = await boot(
			ledgerOf(async () => none),
			[countedLinks(asked)],
		);
		expect(await app.get(users).byUpstream(device.idp, device.subject)).toEqual(none);
		expect(asked).toEqual([]);
	});

	it("is needed in every composition, where users keeps the links and where the ledger does", async () => {
		for (const ledger of [ledgerOf(), undefined, ledgerOf(async () => none)]) {
			await expect(boot(ledger)).rejects.toBeInstanceOf(BootRefused);
		}
	});

	it("is taken where users keeps the links, and left untaken where the ledger keeps them", async () => {
		const kept = await takesUnused({ modules: parts(ledgerOf(), [countedLinks([])]), config });
		expect(kept.users).toBeUndefined();
		const upstream = ledgerOf(async () => none);
		const left = await takesUnused({ modules: parts(upstream, [countedLinks([])]), config });
		// Its takes name the link store in every composition; a ledger with upstream lookups never asks it.
		expect(left.users).toEqual(["users.link-store"]);
	});
});
