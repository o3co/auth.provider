import { describe, expect, it } from "vitest";
import { refusalsOf } from "../../../test/refusals.ts";
import { assemble, contract, defineModule, kernelConfig, type Refusal } from "../../contract.ts";

const single = kernelConfig();

describe("a refusal signal, as assembly records it", () => {
	it("never lets a refusing build pass with no refusal, whatever becomes of the list or the signal", async () => {
		/** A module whose factory refuses, then does `after` to the list given or the signal thrown. */
		const refusing = (after: (reasons: Refusal[], signal: unknown) => unknown, before = false) =>
			defineModule({ name: "a", takes: [] }, (m) => [
				m.provide(contract("p")).by((c) => {
					const reasons: Refusal[] = [{ where: "a.x", reason: "must refuse" }];
					if (before) unreadableWhere(reasons);
					try {
						c.refuseAll(reasons);
					} catch (signal) {
						throw after(reasons, signal);
					}
				}),
			]);
		const unreadableWhere = (reasons: Refusal[]) =>
			Object.defineProperty(reasons[0], "where", {
				get: () => {
					throw new Error("trap");
				},
			});
		const failed = [{ where: "a", reason: "failed during assembly" }];
		const cases: [string, (reasons: Refusal[], signal: unknown) => unknown, readonly Refusal[]][] =
			[
				[
					"the list emptied",
					(reasons, signal) => {
						reasons.length = 0;
						return signal;
					},
					[{ where: "a.x", reason: "must refuse" }],
				],
				[
					"the signal's list unreadable",
					(_, signal) =>
						new Proxy(signal as object, {
							get: (target, key) => {
								if (key === "refusals") throw new Error("trap");
								return Reflect.get(target, key);
							},
						}),
					failed,
				],
				[
					"the signal's list read empty",
					(_, signal) =>
						new Proxy(signal as object, {
							get: (target, key) => (key === "refusals" ? [] : Reflect.get(target, key)),
						}),
					failed,
				],
				[
					"a refusal in it made unreadable once given",
					(reasons, signal) => {
						unreadableWhere(reasons);
						return signal;
					},
					[{ where: "a.x", reason: "must refuse" }],
				],
			];
		for (const [label, after, expected] of cases) {
			expect(
				await refusalsOf(assemble({ modules: [refusing(after)], config: single })),
				label,
			).toEqual(expected);
		}
		// One unreadable as it is given: no refusal of its words, but never a pass.
		expect(
			await refusalsOf(
				assemble({ modules: [refusing((_, signal) => signal, true)], config: single }),
			),
		).toEqual(failed);
	});
});
