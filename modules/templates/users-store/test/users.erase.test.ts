import { type Eraser, erasers, type Walk } from "@mod/erasure-extensions";
import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import secretHashModule from "@mod/secret-hash/module";
import { type Space, store, storeControl } from "@mod/store";
import { simulatedStore } from "@mod/store/testing";
import { contactStore, linkStore, type StoredName } from "@mod/users";
import usersModule from "@mod/users/module";
import { expect, it } from "vitest";
import wiring from "../src/module.ts";

const runtime = quietRuntime({ clock: { now: () => 1_800_000_000_000 } });
const seen = contract<readonly Eraser[]>("users-store-test.erasers");
const collecting = defineModule(
	{ name: "collecting", replicaSafe: true, takes: [erasers] },
	(m) => [m.provide(seen).by((c) => c.collect(erasers))],
);

it("migrates what 0.19 and the reader phase wrote, keeping a name's record in the name store, then erases a subject's links and contacts", async () => {
	const simulated = simulatedStore();
	const base = await assemble({
		modules: [simulated.module, wiring],
		config: kernelConfig(),
		runtime,
	});
	const shared = defineModule({ name: "store", replicaSafe: true, takes: [] }, (m) => [
		m.provide(store).by(() => base.get(store)),
		m.provide(storeControl).by(() => base.get(storeControl)),
	]);
	const link = (subject: string) => JSON.stringify(["corp", subject]);
	const name = JSON.stringify({ idp: "corp" });

	// Written raw, as before records were indexed: two links, an unlink's trace, a name's record, contacts.
	const reader = await assemble({ modules: [shared, wiring], config: kernelConfig(), runtime });
	const raw = reader.get(linkStore);
	await raw.save(link("u-a"), { subject: "s-a" } as never, "endless", "s-a");
	await raw.save(link("u-b"), { subject: "s-b" } as never, "endless", "s-b");
	await raw.save(link("u-gone"), { subject: null } as never, "endless", "s-gone");
	const issuer = { issuer: "https://a.example" } as unknown as StoredName;
	expect(await raw.unowned?.(name, issuer, "endless")).toBe("created");
	await reader
		.get(contactStore)
		.save("s-a", [{ kind: "email", value: "a@example.com" }] as never, "endless", "s-a");

	// The maintenance window marks records indexed; an instance started after it migrates.
	simulated.mark("subject-records.phase", "indexed");
	const app = await assemble({
		modules: [shared, wiring, usersModule, secretHashModule, collecting],
		config: { ...kernelConfig(), users: {} },
		runtime,
	});
	const eraser = app.get(seen).find((e) => e.name === "users");
	expect(eraser?.erasable).toBe(true);
	const inner = base.get(store);
	const walk: Walk = {
		sweep: async (space, cursor) => {
			const page = await inner.scan({ name: space, guarantees: [] } as Space, cursor);
			return page.cursor === undefined
				? { keys: page.keys, server: "one" }
				: { keys: page.keys, cursor: page.cursor, server: "one" };
		},
	};
	const signal = new AbortController().signal;
	expect(await eraser?.migrate(walk, signal)).toEqual([
		{ kind: "migrated", space: "users-store.links", indexed: 2, removed: 2 },
		{ kind: "migrated", space: "users-store.contacts", indexed: 1, removed: 0 },
	]);
	const links = app.get(linkStore);
	// The name's record left the link space for the name store; the trace is gone.
	expect(await links.read(name)).toBeUndefined();
	expect(await links.issuers?.read(name)).toEqual({ issuer: "https://a.example" });
	expect(await links.read(link("u-gone"))).toBeUndefined();
	expect(await links.unowned?.(name, issuer, "endless")).toBe("closed");

	expect((await eraser?.online("s-a", signal))?.reports.map((r) => r.kind)).toEqual([
		"erased",
		"erased",
	]);
	expect(await links.read(link("u-a"))).toBeUndefined();
	expect(await app.get(contactStore).read("s-a")).toBeUndefined();
	// Another subject's link stays, and nothing is created past the erasure.
	expect(await links.read(link("u-b"))).toEqual({ subject: "s-b" });
	expect(await links.save(link("u-c"), { subject: "s-a" } as never, "endless", "s-a")).toBe(
		"erased",
	);
});
