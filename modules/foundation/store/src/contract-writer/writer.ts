import { describe, expect, it } from "vitest";
import { mutate, type Store } from "../contract.ts";
import type { ContractKit, StoreHarness } from "../contract-harness/harness.ts";
import { subjectWriter } from "../writer/subject-writer.ts";

/** The store contract's subject writer: a change to a space of subjects' data carries it. */
export function writerContract(harness: StoreHarness, kit: ContractKit): void {
	const { space, subjects, fresh, never } = kit;
	const writer = { writer: subjectWriter } as const;
	describe("the subject writer", () => {
		it("refuses any change to a space of subjects' data without the writer, as a TypeError, before anything is written", async () => {
			const s = await harness.open();
			const held = fresh(subjects)("k");
			const plain = fresh(space)("k");
			const put = { key: held, put: 1, ...never };
			const refused: (() => Promise<unknown>)[] = [
				() => s.putIfAbsent(held, 1, never),
				() => s.replaceIf(held, "v", 1, never),
				() => s.removeIf(held, { version: "v" }),
				() => s.take(held),
				() => s.count(held, { ms: 10_000, limit: 10 }),
				() => mutate(s, held, () => ({ kind: "write", value: 1, ...never })),
				() => s.batch([], [put]),
				// A key the batch only reads is held too.
				() => s.batch([{ key: held, absent: true }], [{ key: plain, put: 1, ...never }]),
				...(s.batchAcross
					? [
							() => (s.batchAcross as Store["batch"])([], [put]),
							() =>
								(s.batchAcross as Store["batch"])(
									[{ key: held, absent: true }],
									[{ key: { ...plain, partition: `${plain.partition}-b` }, put: 1, ...never }],
								),
						]
					: []),
			];
			for (const change of refused) await expect(change()).rejects.toThrow(TypeError);
			expect((await s.get(held)).entry).toBeNull();
			expect((await s.get(plain)).entry).toBeNull();
		});

		it("takes a batch carrying the writer, in a space of subjects' data and in any other", async () => {
			const s = await harness.open();
			const held = fresh(subjects)("k");
			const plain = fresh(space)("k");
			for (const key of [held, plain]) {
				expect((await s.batch([], [{ key, put: 1, ...never }], writer)).kind).toBe("committed");
				expect((await s.get(key)).entry?.value).toBe(1);
			}
			if (s.batchAcross) {
				const across = [held, plain].map((k) => ({ ...k, partition: `${k.partition}-b` }));
				const answer = await s.batchAcross(
					[],
					across.map((key) => ({ key, put: 2, ...never })),
					writer,
				);
				expect(answer.kind).toBe("committed");
			}
		});
	});
}
