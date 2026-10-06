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
 * The `csrfGuard` slot is held to core's `CsrfGuard` contract once, where
 * boot fills it: whatever fills it — a host's bootstrap or override value,
 * or a module's `provides` — its `middleware` must be a request handler (a
 * function of at most three parameters) and its `check` a function, and a
 * member whose read throws is refused, naming the slot's member. Every
 * reader of the slot then receives one frozen snapshot, each member read
 * once, so a getter cannot hand a reader something other than what was
 * checked.
 */

import type { NextFunction, Request, Response } from "express";
import { describe, expect, it } from "vitest";
import type { CsrfGuard, CsrfVerdict } from "#/browser-session/types.mjs";
import { BootError, createApp, defineModule } from "#/index.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";
import { createTestCsrfGuard } from "#/testing/slots/csrfGuard.mjs";
import { fakeRequest, fakeResponse, runMiddleware } from "#/testing/slots/fake-http.mjs";

declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		csrfGuardSlotProbe?: { readonly probed: true };
	}
}

const host = () => ({ config: makeValidCoreConfig(), pathResolver: (p: string) => p });

/** A module that reads the slot when it is materialised, recording what it was handed. */
const reader = (seen: unknown[]) =>
	defineModule({
		name: "test:csrf-guard-reader",
		optional: ["csrfGuard"],
		provides: {
			csrfGuardSlotProbe: (deps) => {
				seen.push(deps.csrfGuard);
				return { probed: true } as const;
			},
		},
		lifecycle: { csrfGuardSlotProbe: { eager: true } },
	});

/** A module that provides `guard` in the slot, recording its cleanups. */
const owner = (guard: () => unknown, cleaned: unknown[] = []) =>
	defineModule({
		name: "test:csrf-guard-owner",
		provides: { csrfGuard: () => guard() as CsrfGuard },
		lifecycle: { csrfGuard: { eager: true, cleanup: (v) => void cleaned.push(v) } },
	});

const bootWithHostGuard = (guard: unknown, seen: unknown[] = []) =>
	createApp({
		modules: [reader(seen)],
		bootstrapComponents: { ...host(), csrfGuard: guard } as never,
	});

const failureOf = (boot: Promise<unknown>): Promise<unknown> =>
	boot.then(
		() => undefined,
		(err: unknown) => err,
	);

const throwing = {
	get: () => {
		throw new Error("adapter unavailable");
	},
};

/** A four-parameter function: Express takes it for an error handler and skips it on every request. */
const errorHandler = (_err: unknown, _req: unknown, _res: unknown, next: () => void) => next();

/** Guards the slot's check refuses, each with the refusal it names. */
const BROKEN: ReadonlyArray<readonly [string, () => unknown, RegExp]> = [
	[
		"a middleware that is absent",
		() => ({ ...createTestCsrfGuard(), middleware: undefined }),
		/csrfGuard\.middleware is not a request handler.*sessionModule/s,
	],
	[
		"a middleware that is not a function",
		() => ({ ...createTestCsrfGuard(), middleware: "middleware" }),
		/csrfGuard\.middleware is not a request handler.*sessionModule/s,
	],
	[
		"a middleware of four parameters",
		() => ({ ...createTestCsrfGuard(), middleware: errorHandler }),
		/csrfGuard\.middleware is not a request handler.*sessionModule/s,
	],
	[
		"a check that is absent",
		() => ({ ...createTestCsrfGuard(), check: undefined }),
		/csrfGuard\.check is not a function.*sessionModule/s,
	],
	[
		"a check that is not a function",
		() => ({ ...createTestCsrfGuard(), check: { outcome: "accepted" } }),
		/csrfGuard\.check is not a function.*sessionModule/s,
	],
	["no guard object at all", () => null, /csrfGuard must be the guard object.*null/s],
];

/** Guards one of whose reads throws, each with the member the refusal names. */
const UNREADABLE: ReadonlyArray<readonly [string, () => unknown, string]> = [
	[
		"middleware",
		() => Object.defineProperty({ ...createTestCsrfGuard() }, "middleware", throwing),
		"middleware",
	],
	[
		"middleware's arity",
		() => ({
			...createTestCsrfGuard(),
			middleware: Object.defineProperty(() => undefined, "length", throwing),
		}),
		"middleware",
	],
	["check", () => Object.defineProperty({ ...createTestCsrfGuard() }, "check", throwing), "check"],
	[
		"cookieName",
		() => Object.defineProperty({ ...createTestCsrfGuard() }, "cookieName", throwing),
		"cookieName",
	],
];

describe("the csrfGuard slot is held to core's contract where boot fills it", () => {
	it.each(BROKEN)(
		"refuses a host's guard with %s, before any provider runs",
		async (_, guard, rule) => {
			const seen: unknown[] = [];
			const err = await failureOf(bootWithHostGuard(guard(), seen));
			expect(err).toBeInstanceOf(RangeError);
			expect((err as Error).message).toMatch(rule);
			expect(seen).toEqual([]);
		},
	);

	it("refuses an overriding host's guard the same way", async () => {
		const seen: unknown[] = [];
		await expect(
			createApp({
				modules: [reader(seen)],
				bootstrapComponents: host() as never,
				overrideComponents: {
					csrfGuard: { ...createTestCsrfGuard(), middleware: errorHandler } as never,
				},
			}),
		).rejects.toThrow(/csrfGuard\.middleware is not a request handler/);
		expect(seen).toEqual([]);
	});

	it.each(UNREADABLE)(
		"refuses a host's guard whose %s cannot be read, naming the member, with the read's error as the cause",
		async (_, guard, member) => {
			const err = await failureOf(bootWithHostGuard(guard()));
			expect(err).toBeInstanceOf(RangeError);
			expect(err).toMatchObject({
				message: expect.stringMatching(new RegExp(`csrfGuard\\.${member} could not be read`)),
				cause: { message: "adapter unavailable" },
			});
		},
	);

	it.each(BROKEN)(
		"refuses a module's guard with %s as it is materialised, naming the module, and cleans up",
		async (_, guard, rule) => {
			const seen: unknown[] = [];
			const cleaned: unknown[] = [];
			const provided = guard();
			const err = await failureOf(
				createApp({
					modules: [owner(() => provided, cleaned), reader(seen)],
					bootstrapComponents: host() as never,
				}),
			);
			expect(err).toBeInstanceOf(BootError);
			expect(err).toMatchObject({
				reason: "provides-factory-failed",
				stage: "materializeComponents",
				details: { module: "test:csrf-guard-owner", componentKey: "csrfGuard" },
			});
			expect((err as BootError).cause).toBeInstanceOf(RangeError);
			expect((err as BootError).message).toMatch(rule);
			expect(seen).toEqual([]);
			expect(cleaned).toEqual([provided]);
		},
	);

	it("leaves a slot a host fills with undefined unfilled", async () => {
		const seen: unknown[] = [];
		const handle = await bootWithHostGuard(undefined, seen);
		expect(seen).toEqual([undefined]);
		await handle.dispose();
	});
});

describe("every reader of the csrfGuard slot receives one snapshot of what was checked", () => {
	/**
	 * A guard whose members are getters, counting each read, whose
	 * `middleware` answers an error handler from its second read on: a reader
	 * that read the guard itself again would mount what was never checked.
	 */
	const countingGuard = () => {
		const base = createTestCsrfGuard();
		const reads = new Map<string, number>();
		const guard = {};
		for (const [member, value] of Object.entries(base)) {
			Object.defineProperty(guard, member, {
				enumerable: true,
				get: () => {
					const count = (reads.get(member) ?? 0) + 1;
					reads.set(member, count);
					return member === "middleware" && count > 1 ? errorHandler : value;
				},
			});
		}
		return { guard, reads, base };
	};

	const expectSnapshot = (
		seen: readonly unknown[],
		held: unknown,
		raw: unknown,
		base: CsrfGuard,
	) => {
		expect(seen).toHaveLength(1);
		const [handed] = seen;
		expect(handed).toBe(held);
		expect(handed).not.toBe(raw);
		expect(Object.isFrozen(handed)).toBe(true);
		const snapshot = handed as CsrfGuard;
		// Core's own request handler in front of the guard's: three parameters, frozen.
		expect(typeof snapshot.middleware).toBe("function");
		expect(snapshot.middleware.length).toBe(3);
		expect(Object.isFrozen(snapshot.middleware)).toBe(true);
		expect(snapshot.cookieName).toBe(base.cookieName);
		expect(snapshot.headerName).toBe(base.headerName);
		expect(snapshot.bodyField).toBe(base.bodyField);
	};

	it("holds a module's guard as a frozen snapshot, each member read once", async () => {
		const { guard, reads, base } = countingGuard();
		const seen: unknown[] = [];
		const handle = await createApp({
			modules: [owner(() => guard), reader(seen)],
			bootstrapComponents: host() as never,
		});
		// Counted before any assertion here, which may read the guard to describe it.
		const counts = Object.fromEntries(reads);
		expectSnapshot(seen, handle.components.csrfGuard, guard, base);
		expect(counts).toEqual(Object.fromEntries(Object.keys(base).map((member) => [member, 1])));
		await handle.dispose();
	});

	it("holds a host's guard as the same snapshot", async () => {
		const { guard, reads, base } = countingGuard();
		const seen: unknown[] = [];
		const handle = await bootWithHostGuard(guard, seen);
		const counts = Object.fromEntries(reads);
		expectSnapshot(seen, handle.components.csrfGuard, guard, base);
		expect(counts).toEqual(Object.fromEntries(Object.keys(base).map((member) => [member, 1])));
		await handle.dispose();
	});

	it("keeps the guard's methods its own: a guard written as a class, its methods using this, answers through the snapshot", async () => {
		const verdicts: CsrfVerdict[] = [];
		class ClassGuard implements CsrfGuard {
			readonly cookieName = "csrf";
			readonly headerName = "x-csrf-token";
			readonly #verdict: CsrfVerdict = { outcome: "refused", reason: "token_absent" };
			check(_req: Request): CsrfVerdict {
				verdicts.push(this.#verdict);
				return this.#verdict;
			}
			checkNavigation(_req: Request) {
				return this.#verdict.outcome === "accepted"
					? ({ outcome: "accepted" } as const)
					: ({ outcome: "refused", reason: "origin_absent" } as const);
			}
			readonly #status = 403;
			middleware(_req: Request, res: Response, _next: NextFunction): void {
				res.status(this.#status).end();
			}
			issue(_res: Response): string {
				return this.cookieName;
			}
		}
		const seen: unknown[] = [];
		const handle = await bootWithHostGuard(new ClassGuard(), seen);
		const snapshot = seen[0] as CsrfGuard;
		const { req } = fakeRequest();
		expect(snapshot.check(req)).toEqual({ outcome: "refused", reason: "token_absent" });
		expect(snapshot.checkNavigation(req)).toEqual({ outcome: "refused", reason: "origin_absent" });
		expect(snapshot.issue(fakeResponse().res)).toBe("csrf");
		expect(verdicts).toHaveLength(1);
		const { response } = await runMiddleware(snapshot.middleware, req);
		expect(response.status).toBe(403);
		await handle.dispose();
	});
});

describe("the snapshot cannot be changed under its readers", () => {
	it("hands on a request handler of three parameters, which a later change to the guard's middleware cannot make an error handler", async () => {
		const calls: unknown[] = [];
		function middleware(this: unknown, _req: Request, _res: Response, next: NextFunction) {
			calls.push(this);
			next();
		}
		const guard = { ...createTestCsrfGuard(), middleware };
		let lengthSeenLater: number | undefined;
		const handle = await createApp({
			modules: [
				owner(() => guard),
				defineModule({
					name: "test:csrf-guard-arity-flipper",
					requires: ["csrfGuard"],
					provides: {
						csrfGuardSlotProbe: (deps) => {
							// A later provider makes the guard's function look like an error handler.
							Object.defineProperty(middleware, "length", { value: 4 });
							lengthSeenLater = deps.csrfGuard.middleware.length;
							return { probed: true } as const;
						},
					},
					lifecycle: { csrfGuardSlotProbe: { eager: true } },
				}),
			],
			bootstrapComponents: host() as never,
		});
		const held = handle.components.csrfGuard as CsrfGuard;
		expect(lengthSeenLater).toBe(3);
		expect(held.middleware.length).toBe(3);
		expect(() => Object.defineProperty(held.middleware, "length", { value: 4 })).toThrow(TypeError);
		const { next } = await runMiddleware(held.middleware, fakeRequest().req);
		expect(next).toBe(1);
		// The guard's own function runs, on the guard it was read from.
		expect(calls).toEqual([guard]);
		await handle.dispose();
	});

	it("calls the guard's methods through core's own binding, never a bind, call or apply the method carries", async () => {
		const refused: CsrfVerdict = { outcome: "refused", reason: "token_absent" };
		const acceptAll = () => ({ outcome: "accepted" }) as const;
		const check = Object.assign(() => refused, {
			bind: () => acceptAll,
			call: acceptAll,
			apply: acceptAll,
		});
		const issue = Object.assign(() => "issued", {
			bind: () => () => "forged",
			call: () => "forged",
			apply: () => "forged",
		});
		const seen: unknown[] = [];
		const handle = await bootWithHostGuard({ ...createTestCsrfGuard(), check, issue }, seen);
		const snapshot = seen[0] as CsrfGuard;
		expect(snapshot.check(fakeRequest().req)).toEqual(refused);
		expect(snapshot.issue(fakeResponse().res)).toBe("issued");
		await handle.dispose();
	});

	it("disposes a module's guard through the snapshot, on the guard itself", async () => {
		const disposed: unknown[] = [];
		const guard = {
			...createTestCsrfGuard(),
			async [Symbol.asyncDispose](this: unknown) {
				disposed.push(this);
			},
		};
		const handle = await createApp({
			modules: [
				defineModule({
					name: "test:csrf-guard-owner",
					provides: { csrfGuard: () => guard as CsrfGuard },
					lifecycle: { csrfGuard: { eager: true } },
				}),
			],
			bootstrapComponents: host() as never,
		});
		expect(handle.components.csrfGuard).not.toBe(guard);
		await handle.dispose();
		expect(disposed).toEqual([guard]);
	});
});

describe("a module's component named __proto__ hands no reader an inherited guard", () => {
	it("leaves the component map's prototype alone, so a reader of the csrfGuard slot finds it empty", async () => {
		const unchecked = { ...createTestCsrfGuard(), middleware: errorHandler, check: undefined };
		const seen: unknown[] = [];
		const contributed: unknown[] = [];
		const handle = await createApp({
			modules: [
				defineModule({
					name: "test:proto-provider",
					provides: { ["__proto__"]: () => ({ csrfGuard: unchecked }) } as never,
					lifecycle: { ["__proto__"]: { eager: true } } as never,
				}),
				reader(seen),
				defineModule({
					name: "test:proto-contribution-reader",
					optional: ["csrfGuard"],
					contributes: {
						routes: [
							(deps) => {
								contributed.push(deps.csrfGuard);
								return {
									id: "test-proto-reader",
									mountPath: "/__test_proto_reader__",
									handler: (_req: Request, res: Response) => void res.end(),
								};
							},
						],
					},
				}),
			],
			bootstrapComponents: host() as never,
		});
		expect(seen).toEqual([undefined]);
		expect(contributed).toEqual([undefined]);
		expect(handle.components.csrfGuard).toBeUndefined();
		await handle.dispose();
	});
});
