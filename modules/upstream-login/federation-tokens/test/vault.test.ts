import { randomBytes } from "node:crypto";
import { assemble, kernelConfig } from "@mod/kernel";
import { resealing, type Seal, seal } from "@mod/seal";
import sealModule from "@mod/seal/module";
import { describe, expect, it } from "vitest";
import type { StoredUpstreamTokens } from "../src/store.ts";
import { type Entry, vaultWith } from "../src/vault/vault.ts";
import { harness } from "./harness.ts";

type Held = { readonly format: number; readonly idps: { readonly [idp: string]: Entry } };

/** A session linked to `corp`, a receiver's token issued in it, and its record as the store keeps it. */
async function linked(ring?: Readonly<Record<string, unknown>>) {
	const h = await harness(ring ? { seal: ring } : {});
	const session = await h.login();
	await h.receive(session);
	const { token } = await h.issue(session);
	const record = (await h.stores.records.read(session.id)) as unknown as Held;
	return { ...h, session, token, record };
}

const stored = (record: unknown) => record as StoredUpstreamTokens;

describe("a session's sealed tokens", () => {
	it("open for no other session", async () => {
		const h = await linked();
		const other = await h.login("bob");
		const { token } = await h.issue(other);
		await h.stores.records.save(other.id, stored(h.record), 60_000);
		expect((await h.ask(token)).status).toBe(404);
		expect(await h.stores.records.read(other.id)).toEqual({ format: 1, idps: {} });
		expect((await h.ask(h.token)).status).toBe(200);
	});

	it("open for no other IdP", async () => {
		const h = await linked();
		const moved = { format: 1, idps: { ...h.record.idps, other: h.record.idps.corp } };
		await h.stores.records.update(h.session.id, () => ({
			value: stored(moved),
			lifetimeMs: 60_000,
		}));
		expect((await h.ask(h.token, "other")).status).toBe(404);
		expect((await h.ask(h.token)).status).toBe(200);
	});
});

describe("the vault", () => {
	// A seal that opens whatever it is given, so the vault's own reading is what is checked.
	const open: Seal = {
		seal: (plain) => plain,
		open: (sealed) => ({ kind: "opened", plain: sealed }),
	};
	const vault = vaultWith(open);
	const entry = (plain: unknown): Entry => ({ version: "v", sealed: JSON.stringify(plain) });

	it("takes an entry that opens but holds another shape as none", () => {
		const kept = { accessToken: "a", tokenType: "Bearer", granted: [], scope: [] };
		expect(vault.open("s", "corp", entry(kept))).toEqual(kept);
		for (const odd of [{ ...kept, accessToken: 5 }, { ...kept, extra: 1 }, ["a"], "a"]) {
			expect(vault.open("s", "corp", entry(odd))).toBeUndefined();
		}
	});

	it("reads no entries from a record of another format or shape", () => {
		const idps = { corp: { version: "v", sealed: "x" } };
		expect(vault.entriesOf(stored({ format: 1, idps }))).toEqual(idps);
		for (const odd of [
			{ format: 2, idps },
			{ idps },
			{ format: 1, idps, more: true },
			{ format: 1, idps: { corp: { version: "v" } } },
			undefined,
		]) {
			expect(vault.entriesOf(stored(odd))).toEqual({});
		}
	});
});

describe("a rotation", () => {
	const key = (id: string) => ({ id, key: randomBytes(32).toString("base64") });
	const [past, current, gone] = [key("past"), key("current"), key("gone")];
	/** A seal over a ring of its own, to write what another key sealed. */
	const sealOver = async (ring: Readonly<Record<string, unknown>>) =>
		(await assemble({ modules: [sealModule], config: { ...kernelConfig(), seal: ring } })).get(
			seal,
		);
	/** A linked session whose `corp` entry `by` sealed, under a ring with `past` as a previous key. */
	async function aged(by: { id: string; key: string }) {
		const h = await linked({ current, previous: [past] });
		const entry = h.record.idps.corp as Entry;
		const context = `federation-tokens\n${h.session.id}\ncorp`;
		const opened = (await sealOver({ current })).open(entry.sealed, context);
		if (opened.kind !== "opened") throw new Error("not opened");
		const sealed = (await sealOver({ current: by })).seal(opened.plain, context);
		await h.stores.records.update(h.session.id, () => ({
			value: stored({ format: 1, idps: { corp: { ...entry, sealed } } }),
		}));
		const sealedNow = async () =>
			((await h.stores.records.read(h.session.id)) as unknown as Held).idps.corp?.sealed;
		return { ...h, sealedNow };
	}

	it("seals an entry again under the current key when a read finds a past key's", async () => {
		const h = await aged(past);
		expect((await h.ask(h.token)).status).toBe(200);
		expect(await h.sealedNow()).toMatch(/^current\./);
	});

	it("answers a read whose sealing again cannot be written, leaving the past key's entry for later", async () => {
		const h = await aged(past);
		h.stores.down.failNext("update");
		expect((await h.ask(h.token)).status).toBe(200);
		expect(await h.sealedNow()).toMatch(/^past\./);
		expect((await h.ask(h.token)).status).toBe(200);
		expect(await h.sealedNow()).toMatch(/^current\./);
	});

	it("seals each stale entry again in a walk, and counts one no key opens as left", async () => {
		const h = await aged(past);
		const lost = await aged(gone);
		const counted = (resealed: number, left: number) => [
			{ name: "federation-tokens", resealed, left },
		];
		expect(await h.app.get(resealing).reseal()).toEqual(counted(1, 0));
		expect(await h.sealedNow()).toMatch(/^current\./);
		expect(await h.app.get(resealing).reseal()).toEqual(counted(0, 0));
		expect(await lost.app.get(resealing).reseal()).toEqual(counted(0, 1));
		expect(await lost.sealedNow()).toMatch(/^gone\./);
	});

	it("walks every session, page by page", async () => {
		const h = await aged(past);
		const bob = await h.login("bob");
		await h.receive(bob);
		const record = (await h.stores.records.read(bob.id)) as unknown as Held;
		const entry = record.idps.corp as Entry;
		const context = `federation-tokens\n${bob.id}\ncorp`;
		const opened = (await sealOver({ current })).open(entry.sealed, context);
		if (opened.kind !== "opened") throw new Error("not opened");
		const sealed = (await sealOver({ current: past })).seal(opened.plain, context);
		await h.stores.records.update(bob.id, () => ({
			value: stored({ format: 1, idps: { corp: { ...entry, sealed } } }),
		}));
		expect(await h.app.get(resealing).reseal()).toEqual([
			{ name: "federation-tokens", resealed: 2, left: 0 },
		]);
	});

	it("leaves an entry another write changed meanwhile, and does not count it", async () => {
		const h = await aged(past);
		const theirs = { version: "theirs", sealed: "current.x" };
		h.stores.raceNext((record) =>
			stored({ ...(record as unknown as Held), idps: { corp: theirs } }),
		);
		expect(await h.app.get(resealing).reseal()).toEqual([
			{ name: "federation-tokens", resealed: 0, left: 0 },
		]);
		expect(await h.sealedNow()).toBe("current.x");
	});
});
