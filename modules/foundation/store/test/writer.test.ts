import { assemble, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import { checkedStore } from "../src/checks/checks.ts";
import { type Space, type Store, spaces, store } from "../src/contract.ts";
import { simulatedStore } from "../src/testing.ts";
import { subjectWriter } from "../src/writer/subject-writer.ts";

const space: Space = {
	name: "kept",
	guarantees: ["durable", "replicated", "no-eviction"],
	subjectData: "none",
};
const key = (name: string) => ({ space, partition: "p", name });
const never = { kind: "never" } as const;

/** A store below the check, keeping the options each batch reached it with. */
function spied() {
	const seen: unknown[] = [];
	const answer = async (_c: unknown, _w: unknown, options: unknown) => {
		seen.push(options);
		return { kind: "committed" as const, versions: [] };
	};
	const inner = { batch: answer, batchAcross: answer } as unknown as Store;
	return { seen, s: checkedStore(inner, [space]) };
}

it("takes the subject writer on a batch and a batch across, and hands the store below none of it", async () => {
	const { seen, s } = spied();
	const writes = [{ key: key("a"), put: 1, expiry: never }];
	await s.batch([], writes, { writer: subjectWriter, deadline: 5, idempotency: "m" });
	await s.batchAcross?.([], writes, { writer: subjectWriter });
	await s.batch([], writes);
	expect(seen).toEqual([{ deadline: 5, idempotency: "m" }, {}, {}]);
});

it("refuses any other writer, a copy of the subject writer among them, before anything is written", async () => {
	const { seen, s } = spied();
	const writes = [{ key: key("a"), put: 1, expiry: never }];
	for (const writer of [{}, structuredClone(subjectWriter), "writer"]) {
		const options = { writer } as never;
		await expect(s.batch([], writes, options)).rejects.toThrow(TypeError);
		await expect(s.batchAcross?.([], writes, options)).rejects.toThrow(TypeError);
	}
	expect(seen).toEqual([]);
});

it("keeps a batch carrying the writer through the simulated store's one check, across a restart and a failover", async () => {
	const simulated = simulatedStore();
	const owner = defineModule({ name: "owner", replicaSafe: true, takes: [] }, (m) => [
		m.contribute(spaces).by(() => space),
	]);
	const app = await assemble({
		modules: [simulated.module, owner],
		config: kernelConfig(),
		runtime: quietRuntime(),
	});
	const s = app.get(store);
	const written = await s.batch([], [{ key: key("one"), put: 1, expiry: never }], {
		writer: subjectWriter,
	});
	expect(written.kind).toBe("committed");
	const across = await s.batchAcross?.(
		[],
		[
			{ key: key("two"), put: 2, expiry: never },
			{ key: { ...key("three"), partition: "q" }, put: 3, expiry: never },
		],
		{ writer: subjectWriter },
	);
	expect(across?.kind).toBe("committed");
	await simulated.restart();
	await simulated.failover();
	for (const [k, value] of [
		[key("one"), 1],
		[key("two"), 2],
		[{ ...key("three"), partition: "q" }, 3],
	] as const) {
		expect((await s.get(k)).entry?.value, k.name).toBe(value);
	}
});

it("asks the writer of a change to a space of each category of subjects' data it holds, and of no other", async () => {
	const categories = [
		["online-indexed", true],
		["online-keyed", true],
		["bounded", true],
		["internal", true],
		["window", false],
		["none", false],
		["pseudonymous", false],
		["retained", false],
	] as const;
	const declared: Space[] = categories.map(([subjectData]) => ({
		name: `of-${subjectData}`,
		guarantees: [],
		subjectData,
	}));
	const answered = async () => ({ kind: "written" as const, version: "v" });
	const batch = async () => ({ kind: "committed" as const, versions: [] });
	const inner = { putIfAbsent: answered, batch } as unknown as Store;
	const s = checkedStore(inner, declared);
	for (const [i, [subjectData, held]] of categories.entries()) {
		const at = { space: declared[i] as Space, partition: "p", name: "k" };
		const single = s.putIfAbsent(at, 1, { expiry: never });
		const unmarked = s.batch([], [{ key: at, put: 1, expiry: never }]);
		if (held) {
			await expect(single, subjectData).rejects.toThrow(TypeError);
			await expect(unmarked, subjectData).rejects.toThrow(TypeError);
		} else {
			await expect(single, subjectData).resolves.toMatchObject({ kind: "written" });
			await expect(unmarked, subjectData).resolves.toMatchObject({ kind: "committed" });
		}
		const marked = await s.batch([], [{ key: at, put: 1, expiry: never }], {
			writer: subjectWriter,
		});
		expect(marked.kind, subjectData).toBe("committed");
	}
});
