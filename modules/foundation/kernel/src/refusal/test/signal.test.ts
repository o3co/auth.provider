import { describe, expect, it } from "vitest";
import { refusalsOf } from "../../../test/refusals.ts";
import {
	assemble,
	BootRefused,
	contract,
	defineModule,
	kernelConfig,
	type Refusal,
} from "../../contract.ts";

const single = kernelConfig();

describe("a refusal signal, as assembly records it", () => {
	it("never lets a refusing build pass with no refusal, whatever becomes of the list or the signal", async () => {
		/** A module whose factory refuses, then does `after` to the list given or the signal thrown. */
		const refusing = (after: (reasons: Refusal[], signal: unknown) => unknown, before = false) =>
			defineModule({ name: "a", replicaSafe: false, takes: [] }, (m) => [
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

	it("reads a rethrown signal's refusals one at a time, by index, keeping only each where and reason that is a string", async () => {
		/** A module whose factory refuses, then rethrows its signal with `list` for its refusals. */
		const rethrowing = (list: unknown) =>
			defineModule({ name: "a", replicaSafe: true, takes: [] }, (m) => [
				m.provide(contract("p")).by((c) => {
					try {
						c.refuse("a.x", "must refuse");
					} catch (signal) {
						throw new Proxy(signal as object, {
							get: (target, key) => (key === "refusals" ? list : Reflect.get(target, key)),
						});
					}
				}),
			]);
		const one = { where: "a.x", reason: "must refuse" };
		const failed = [{ where: "a", reason: "failed during assembly" }];
		const secret = {
			where: "a.y",
			get reason(): string {
				throw new Error("secret=abc");
			},
		};
		const cases: [string, unknown, readonly Refusal[]][] = [
			["a map of its own answering nothing", Object.assign([one], { map: () => undefined }), [one]],
			[
				"a map of its own answering a length over an empty iterator",
				Object.assign([], { map: () => ({ length: 1, *[Symbol.iterator]() {} }) }),
				failed,
			],
			// biome-ignore lint/suspicious/noSparseArray: a list with a hole is the case.
			["a list with a hole", [, one], [one]],
			[
				"a refusal whose reason throws a secret",
				Object.assign([secret, one], {
					map() {
						return this;
					},
				}),
				[one],
			],
			[
				"refusals whose words are no strings, beside one whose reason is empty",
				[{ where: 1, reason: "r" }, null, "text", { where: "a.z", reason: "" }],
				[{ where: "a.z", reason: "" }],
			],
			["no list at all", 42, failed],
		];
		for (const [label, list, expected] of cases) {
			let told: unknown;
			try {
				await assemble({ modules: [rethrowing(list)], config: single });
				told = "assembled";
			} catch (error) {
				told = BootRefused.is(error) ? error.refusals : `raw: ${String(error)}`;
			}
			expect(told, label).toEqual(expected);
		}
	});
});
