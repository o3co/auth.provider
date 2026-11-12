import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { secretRecordsIn } from "@mod/records";
import { type Space, type Store, spaces, store } from "@mod/store";
import { simulatedStore } from "@mod/store/testing";
import { expect, it } from "vitest";
import { eraseSubject, phasedRecordsIn, subjectRecordsPhase } from "../src/subject-records.ts";
import { placed } from "./placed.ts";

const g = ["durable"] as const;
const name = "named-codes";
const bounded: Space = { name, guarantees: g, subjectData: "bounded", boundedMs: 60_000 };
const refuse = (where: string, reason: string): never => {
	throw new Error(`${where}: ${reason}`);
};
const indexed = {
	control: async () => ({
		epoch: "e",
		maintenance: false,
		requires: [],
		marks: { "subject-records.phase": { value: "indexed", epoch: "e" } },
	}),
};

/** The bounded space's records keyed by secrets, as code-grant keeps codes, at the phase read indexed. */
async function codes() {
	const p = await placed([bounded]);
	const { store: s, space, index, random } = p.at(bounded);
	const records = await phasedRecordsIn<{ n: number }>(
		{ store: s, space, index, random },
		subjectRecordsPhase.once(indexed as never),
		"w",
		refuse,
		{ secret: true },
	);
	return { ...p, records };
}

it("names a record by records' own digest, so one a 0.19 instance wrote under a secret is found by name and by secret", async () => {
	// The 0.19 path: records' secret records in a plain space of the same name.
	const plain: Space = { name, guarantees: g };
	const held = contract<Store>("test.plain-store");
	const app = await assemble({
		modules: [
			simulatedStore().module,
			defineModule({ name: "plain", replicaSafe: false, takes: [store] }, (m) => [
				m.contribute(spaces).by(() => plain),
				m.provide(held).by((c) => c.get(store)),
			]),
		],
		config: kernelConfig(),
		runtime: quietRuntime(),
	});
	const old = secretRecordsIn<{ n: number }>({
		store: app.get(held),
		space: plain,
		random: { bytes: (n) => new Uint8Array(n) },
	});
	const { records, put } = await codes();
	expect(records.nameOf("the-code")).toBe(old.nameOf("the-code"));
	await put(bounded, old.nameOf("the-code"), { n: 1 }, 60_000);
	expect((await records.changeNamed(records.nameOf("the-code"), () => undefined))?.after).toEqual({
		n: 1,
	});
	expect(await records.read("the-code")).toEqual({ n: 1 });
});

it("changes a bounded record by name through its subject's tombstone, keeping its end; only creation is fenced", async () => {
	const { records, raw, at } = await codes();
	expect(await records.create("the-code", { n: 1 }, 60_000, "alice")).toBe("created");
	const named = records.nameOf("the-code");
	const ends = (await raw(bounded, named))?.expiresAt;
	expect(await eraseSubject(at(bounded), "alice")).toMatchObject({ kind: "fenced" });
	// A void after the erasure still lands, so a reuse revokes until the code's end.
	const changed = await records.changeNamed(named, () => ({ value: { n: 2 }, lifetimeMs: 1 }));
	expect(changed).toEqual({ before: { n: 1 }, after: { n: 2 } });
	expect((await raw(bounded, named))?.expiresAt).toBe(ends);
	expect(await records.create("another", { n: 3 }, 60_000, "alice")).toBe("erased");
	// Bounded and keyed by secrets together: a create past the space's ceiling is refused.
	await expect(records.create("long", { n: 4 }, 60_001, "bob")).rejects.toThrow(TypeError);
});
