import type { Seal } from "@mod/seal";
import { describe, expect, it } from "vitest";
import type { StoredUpstreamTokens } from "../src/store.ts";
import { type Entry, vaultWith } from "../src/vault/vault.ts";
import { harness } from "./harness.ts";

type Held = { readonly format: number; readonly idps: { readonly [idp: string]: Entry } };

/** A session linked to `corp`, a receiver's token issued in it, and its record as the store keeps it. */
async function linked() {
	const h = await harness();
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
