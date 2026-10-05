/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * `attemptCounterContract` run over core's in-process counter, on a fake
 * clock and on the real one, and the proof that each case is not vacuous: a
 * counter with one fault each, refused by the case that names it.
 */

import {
	type AttemptCount,
	type AttemptCounter,
	type AttemptSpec,
	createMemoryAttemptCounter,
} from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import {
	type AttemptCounterContractInput,
	type AttemptCounterHarness,
	attemptCounterContract,
} from "#/index.mjs";

/** A clock the harness moves by hand. */
const fakeClock = () => {
	let now = Date.parse("2026-10-03T00:00:00.000Z");
	return {
		now: () => now,
		advance: (ms: number) => {
			now += ms;
		},
	};
};

/** Core's counter on a fake clock, two instances over one backend being one counter here. */
const memoryHarness = async (): Promise<AttemptCounterHarness> => {
	const clock = fakeClock();
	return { counter: createMemoryAttemptCounter({ now: clock.now }), clock };
};

const run = (name: string, input: AttemptCounterContractInput): void => {
	describe(name, () => {
		for (const contractCase of attemptCounterContract(input)) {
			it(contractCase.name, contractCase.run);
		}
	});
};

run("attemptCounterContract over core's in-process counter on a fake clock", {
	build: memoryHarness,
});

run("attemptCounterContract over core's in-process counter on the real clock", {
	build: async () => ({ counter: createMemoryAttemptCounter() }),
});

describe("attemptCounterContract's outage case", () => {
	it("runs when declared, against a counter that cannot reach its backend", async () => {
		const cases = attemptCounterContract({
			build: async () => ({
				...(await memoryHarness()),
				unreachable: () => ({
					consume: async () => {
						throw new Error("backend down");
					},
				}),
			}),
			supports: { unreachable: true },
		});
		const outage = cases.find((c) => c.name === CASE.outage);
		expect(outage).toBeDefined();
		await outage?.run();
	});

	it("is named as not run when undeclared", () => {
		const names = attemptCounterContract({ build: memoryHarness }).map((c) => c.name);
		expect(names).toContain("not run: the outage case (supports.unreachable not declared)");
		expect(names).not.toContain(CASE.outage);
	});

	it("fails when declared and the harness lacks the hook", async () => {
		const outage = attemptCounterContract({
			build: memoryHarness,
			supports: { unreachable: true },
		}).find((c) => c.name === CASE.outage);
		await expect(outage?.run()).rejects.toThrow();
	});
});

const CASE = {
	window:
		"allows limit attempts in a window and refuses the rest, remaining counting down to 0, every answer naming the window's end",
	reset: "a window ends windowSeconds after its first attempt, and the next attempt starts another",
	keys: "keys are counted apart",
	spec: "each key is counted against the spec handed in with its attempt",
	concurrent: "concurrent attempts on one key are counted exactly, across instances",
	badInput: "a key or spec it cannot count is rejected, and counts nothing",
	outage: "a counter that cannot reach its backend rejects, never answering a count",
	lowered:
		"a limit lowered on a live key applies at once: limit 5, then limit 2, allows the second attempt with nothing remaining and refuses the third",
	raised:
		"a limit raised on a live key applies at once, and the refused attempts counted nothing: limit 2 spent, then limit 5, allows the next attempt with 2 remaining",
	shortened:
		"a window shortened on a live key keeps its end: window 60, then window 1, answers the same resetAt",
	lengthened:
		"a window lengthened on a live key keeps its end: window 1, then window 60, answers the same resetAt",
} as const;

/** The names of the cases that refuse the counter `make` builds over core's, on a fake clock. */
async function refusedBy(
	make: (inner: AttemptCounter, clock: ReturnType<typeof fakeClock>) => AttemptCounter,
	extra: Partial<AttemptCounterHarness> = {},
	supports: AttemptCounterContractInput["supports"] = {},
): Promise<string[]> {
	const refused: string[] = [];
	const build = async (): Promise<AttemptCounterHarness> => {
		const clock = fakeClock();
		return {
			counter: make(createMemoryAttemptCounter({ now: clock.now }), clock),
			clock,
			...extra,
		};
	};
	for (const contractCase of attemptCounterContract({ build, supports })) {
		try {
			await contractCase.run();
		} catch {
			refused.push(contractCase.name);
		}
	}
	return refused;
}

/** A counter that answers `answer`'s rewrite of core's answer. */
const rewriting =
	(answer: (count: AttemptCount, spec: AttemptSpec) => unknown) =>
	(inner: AttemptCounter): AttemptCounter => ({
		consume: async (key, spec) => answer(await inner.consume(key, spec), spec) as AttemptCount,
	});

describe("attemptCounterContract refuses a broken counter", () => {
	it("passes core's counter, with every case named", async () => {
		expect(await refusedBy((inner) => inner)).toEqual([]);
		const names = attemptCounterContract({ build: memoryHarness }).map((c) => c.name);
		expect(names).toEqual(
			expect.arrayContaining(Object.values(CASE).filter((name) => name !== CASE.outage)),
		);
	});

	it("refuses a counter that applies a limit of its own", async () => {
		const refused = await refusedBy((inner) => ({
			consume: (key, spec) => inner.consume(key, { ...spec, limit: 3 }),
		}));
		expect(refused).toContain(CASE.spec);
	});

	it("refuses a counter that counts every key as one", async () => {
		const refused = await refusedBy((inner) => ({
			consume: (_key, spec) => inner.consume("shared", spec),
		}));
		expect(refused).toContain(CASE.keys);
	});

	it("refuses a counter that counts only the part of a key before its first colon", async () => {
		const refused = await refusedBy((inner) => ({
			consume: (key, spec) => inner.consume(key.split(":")[0] || key, spec),
		}));
		expect(refused).toContain(CASE.keys);
	});

	it("refuses a counter whose window never ends", async () => {
		const refused = await refusedBy((_inner, clock) => {
			const start = clock.now();
			const frozen = createMemoryAttemptCounter({ now: () => start });
			return { consume: (key, spec) => frozen.consume(key, spec) };
		});
		expect(refused).toContain(CASE.reset);
	});

	it("refuses a counter whose window ends late", async () => {
		const refused = await refusedBy((_inner, clock) => {
			const late = createMemoryAttemptCounter({ now: clock.now });
			return {
				consume: (key, spec) =>
					late.consume(key, { ...spec, windowSeconds: spec.windowSeconds + 1 }),
			};
		});
		expect(refused).toContain(CASE.window);
	});

	it("refuses a counter that is not atomic", async () => {
		const refused = await refusedBy((_inner, clock) => {
			const counts = new Map<string, number>();
			return {
				consume: async (key, spec) => {
					const seen = counts.get(key) ?? 0;
					await new Promise((r) => setImmediate(r));
					counts.set(key, seen + 1);
					const allowed = seen < spec.limit;
					return {
						allowed,
						remaining: allowed ? spec.limit - seen - 1 : 0,
						resetAt: new Date(clock.now() + spec.windowSeconds * 1000),
					};
				},
			};
		});
		expect(refused).toContain(CASE.concurrent);
	});

	it("refuses a counter whose remaining is one off", async () => {
		const refused = await refusedBy(
			rewriting((count) => ({ ...count, remaining: count.allowed ? count.remaining + 1 : 0 })),
		);
		expect(refused).toContain(CASE.window);
	});

	it("refuses a counter that answers a refusal with attempts remaining", async () => {
		const refused = await refusedBy(
			rewriting((count, spec) => (count.allowed ? count : { ...count, remaining: spec.limit })),
		);
		expect(refused).toContain(CASE.window);
	});

	it("refuses a counter that answers resetAt as a number", async () => {
		const refused = await refusedBy(
			rewriting((count) => ({ ...count, resetAt: count.resetAt.getTime() })),
		);
		expect(refused).toContain(CASE.window);
	});

	it("refuses a counter that counts a key or spec it should reject", async () => {
		const refused = await refusedBy((inner) => ({
			consume: (key, spec) =>
				inner.consume(typeof key === "string" && key !== "" ? key : "fallback", {
					limit: Number.isSafeInteger(spec?.limit) && spec.limit > 0 ? spec.limit : 1,
					windowSeconds:
						Number.isSafeInteger(spec?.windowSeconds) && spec.windowSeconds > 0
							? Math.min(spec.windowSeconds, 60)
							: 60,
				}),
		}));
		expect(refused).toContain(CASE.badInput);
	});

	it("refuses a counter that rejects bad input only after counting it", async () => {
		const refused = await refusedBy((inner) => ({
			consume: async (key, spec) => {
				const valid = Number.isSafeInteger(spec?.limit) && spec.limit > 0;
				const counted = await inner.consume(key, valid ? spec : { limit: 5, windowSeconds: 60 });
				if (!valid) throw new RangeError("bad spec");
				return counted;
			},
		}));
		expect(refused).toContain(CASE.badInput);
	});

	it("refuses a counter that keeps the limit a key's window started with", async () => {
		const refused = await refusedBy((inner) => {
			const first = new Map<string, AttemptSpec>();
			return {
				consume: (key, spec) => {
					if (!first.has(key)) first.set(key, spec);
					return inner.consume(key, first.get(key) as AttemptSpec);
				},
			};
		});
		expect(refused).toContain(CASE.lowered);
		expect(refused).toContain(CASE.raised);
	});

	it("refuses a counter that starts a new window when a spec changes the window", async () => {
		const refused = await refusedBy((inner) => ({
			consume: (key, spec) => inner.consume(`${key}#${spec.windowSeconds}`, spec),
		}));
		expect(refused).toContain(CASE.shortened);
	});

	it("refuses a counter that keeps a running window's end only when a spec shortens it", async () => {
		const refused = await refusedBy((inner) => {
			const started = new Map<string, number>();
			return {
				consume: (key, spec) => {
					const first = started.get(key) ?? spec.windowSeconds;
					started.set(key, first);
					return inner.consume(
						spec.windowSeconds > first ? `${key}#${spec.windowSeconds}` : key,
						spec,
					);
				},
			};
		});
		expect(refused).toContain(CASE.lengthened);
		expect(refused).not.toContain(CASE.shortened);
	});

	it("refuses a counter that counts refused attempts", async () => {
		const refused = await refusedBy((_inner, clock) => {
			const windows = new Map<string, { count: number; resetAt: number }>();
			return {
				consume: async (key, spec) => {
					const now = clock.now();
					let window = windows.get(key);
					if (window === undefined || window.resetAt <= now) {
						window = { count: 0, resetAt: now + spec.windowSeconds * 1000 };
						windows.set(key, window);
					}
					window.count += 1;
					const allowed = window.count <= spec.limit;
					return {
						allowed,
						remaining: allowed ? spec.limit - window.count : 0,
						resetAt: new Date(window.resetAt),
					};
				},
			};
		});
		expect(refused).toContain(CASE.raised);
	});

	it("refuses a counter that takes a key past 512 characters", async () => {
		const refused = await refusedBy((inner) => ({
			consume: (key, spec) =>
				inner.consume(typeof key === "string" && key.length > 512 ? key.slice(0, 512) : key, spec),
		}));
		expect(refused).toContain(CASE.badInput);
	});

	it("refuses a counter whose window ends far later than its spec's", async () => {
		const refused = await refusedBy((_inner, clock) => {
			const late = createMemoryAttemptCounter({ now: clock.now });
			return {
				consume: (key, spec) =>
					late.consume(key, { ...spec, windowSeconds: spec.windowSeconds * 10 }),
			};
		});
		expect(refused).toContain(CASE.window);
	});

	it("refuses a counter that answers an outage as an allowed attempt", async () => {
		const refused = await refusedBy(
			(inner) => inner,
			{
				unreachable: () => ({
					consume: async (_key, spec) => ({
						allowed: true,
						remaining: spec.limit - 1,
						resetAt: new Date(),
					}),
				}),
			},
			{ unreachable: true },
		);
		expect(refused).toEqual([CASE.outage]);
	});
});
