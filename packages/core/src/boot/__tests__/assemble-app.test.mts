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

import { describe, expect, it, vi } from "vitest";
import { assembleApp } from "../assemble-app.mjs";
import type { CleanupRecord, CollectedRouteContribution, FrozenWorld } from "../types.mjs";
import { BootError } from "../types.mjs";

// ---------------------------------------------------------------------------
// Minimal stub helpers
// ---------------------------------------------------------------------------

/** Spy-instrumented mock Router factory. */
function makeMockRouter() {
	const useCalls: { mountPath: string; handler: unknown }[] = [];
	const router = {
		use: vi.fn((mountPath: string, handler: unknown) => {
			useCalls.push({ mountPath, handler });
		}),
		useCalls,
	};
	return router;
}

/** Build a minimal FrozenWorld with the given routes and cleanups. */
function makeFrozenWorld(
	routes: CollectedRouteContribution[],
	cleanups: CleanupRecord[] = [],
	components: Record<string, unknown> = {},
): FrozenWorld {
	const frozenComponents = Object.freeze({ ...components }) as FrozenWorld["components"];
	return {
		components: frozenComponents,
		registries: new Map(),
		routes,
		cleanups,
	};
}

// ---------------------------------------------------------------------------
// 1. Mount-order: declaration order baseline
// ---------------------------------------------------------------------------

describe("assembleApp — 1. mount-order: declaration order baseline", () => {
	it("three routes with no before/after mount in declaration order", () => {
		const handlerA = vi.fn();
		const handlerB = vi.fn();
		const handlerC = vi.fn();

		const routes: CollectedRouteContribution[] = [
			{
				contribution: { mountPath: "/a", handler: handlerA as never },
				contributedBy: "ModA",
				declarationIndex: 0,
			},
			{
				contribution: { mountPath: "/b", handler: handlerB as never },
				contributedBy: "ModB",
				declarationIndex: 1,
			},
			{
				contribution: { mountPath: "/c", handler: handlerC as never },
				contributedBy: "ModC",
				declarationIndex: 2,
			},
		];

		const mockRouter = makeMockRouter();
		const handle = assembleApp(makeFrozenWorld(routes), {
			express: { Router: () => mockRouter as never },
		});

		expect(mockRouter.useCalls).toHaveLength(3);
		expect(mockRouter.useCalls[0]?.mountPath).toBe("/a");
		expect(mockRouter.useCalls[1]?.mountPath).toBe("/b");
		expect(mockRouter.useCalls[2]?.mountPath).toBe("/c");
		expect(handle).toBeDefined();
	});
});

// ---------------------------------------------------------------------------
// 2. Mount-order: `before` token honoured
// ---------------------------------------------------------------------------

describe("assembleApp — 2. mount-order: before token honoured", () => {
	it("route X with before: ['y'] mounts before Y even when Y declared first", () => {
		const handlerX = vi.fn();
		const handlerY = vi.fn();

		// Y declared first (declarationIndex 0), X second (declarationIndex 1)
		// but X has before: ["y"] → X must mount before Y
		const routes: CollectedRouteContribution[] = [
			{
				contribution: { mountPath: "/y", handler: handlerY as never, id: "y" },
				contributedBy: "ModY",
				declarationIndex: 0,
			},
			{
				contribution: {
					mountPath: "/x",
					handler: handlerX as never,
					id: "x",
					before: ["y"],
				},
				contributedBy: "ModX",
				declarationIndex: 1,
			},
		];

		const mockRouter = makeMockRouter();
		assembleApp(makeFrozenWorld(routes), { express: { Router: () => mockRouter as never } });

		expect(mockRouter.useCalls).toHaveLength(2);
		expect(mockRouter.useCalls[0]?.mountPath).toBe("/x");
		expect(mockRouter.useCalls[1]?.mountPath).toBe("/y");
	});
});

// ---------------------------------------------------------------------------
// 3. Mount-order: `after` token honoured
// ---------------------------------------------------------------------------

describe("assembleApp — 3. mount-order: after token honoured", () => {
	it("route X with after: ['y'] mounts after Y even when X declared first", () => {
		const handlerX = vi.fn();
		const handlerY = vi.fn();

		// X declared first (declarationIndex 0), Y second (declarationIndex 1)
		// but X has after: ["y"] → X must mount after Y
		const routes: CollectedRouteContribution[] = [
			{
				contribution: {
					mountPath: "/x",
					handler: handlerX as never,
					id: "x",
					after: ["y"],
				},
				contributedBy: "ModX",
				declarationIndex: 0,
			},
			{
				contribution: { mountPath: "/y", handler: handlerY as never, id: "y" },
				contributedBy: "ModY",
				declarationIndex: 1,
			},
		];

		const mockRouter = makeMockRouter();
		assembleApp(makeFrozenWorld(routes), { express: { Router: () => mockRouter as never } });

		expect(mockRouter.useCalls).toHaveLength(2);
		expect(mockRouter.useCalls[0]?.mountPath).toBe("/y");
		expect(mockRouter.useCalls[1]?.mountPath).toBe("/x");
	});
});

// ---------------------------------------------------------------------------
// 4. Mount-order: cycle throws route-order-cycle
// ---------------------------------------------------------------------------

describe("assembleApp — 4. mount-order: cycle detection", () => {
	it("A before B and B before A throws BootError reason=route-order-cycle", () => {
		const routes: CollectedRouteContribution[] = [
			{
				contribution: { mountPath: "/a", handler: vi.fn() as never, id: "a", before: ["b"] },
				contributedBy: "ModA",
				declarationIndex: 0,
			},
			{
				contribution: { mountPath: "/b", handler: vi.fn() as never, id: "b", before: ["a"] },
				contributedBy: "ModB",
				declarationIndex: 1,
			},
		];

		const mockRouter = makeMockRouter();
		expect(() => {
			assembleApp(makeFrozenWorld(routes), { express: { Router: () => mockRouter as never } });
		}).toThrow(BootError);

		let thrown: BootError | undefined;
		try {
			assembleApp(makeFrozenWorld(routes), { express: { Router: () => mockRouter as never } });
		} catch (err) {
			thrown = err as BootError;
		}
		expect(thrown).toBeDefined();
		expect(thrown?.reason).toBe("route-order-cycle");
		expect(thrown?.stage).toBe("assembleApp");
	});
});

// ---------------------------------------------------------------------------
// 5. Mount-order: declaration-index tie-breaker
// ---------------------------------------------------------------------------

describe("assembleApp — 5. mount-order: declaration-index tie-breaker", () => {
	it("three independently-orderable routes maintain declaration order", () => {
		const handlerA = vi.fn();
		const handlerB = vi.fn();
		const handlerC = vi.fn();

		// No edges between any pair → tie-breaker should keep declaration order
		const routes: CollectedRouteContribution[] = [
			{
				contribution: { mountPath: "/c", handler: handlerC as never, id: "c" },
				contributedBy: "ModC",
				declarationIndex: 2,
			},
			{
				contribution: { mountPath: "/a", handler: handlerA as never, id: "a" },
				contributedBy: "ModA",
				declarationIndex: 0,
			},
			{
				contribution: { mountPath: "/b", handler: handlerB as never, id: "b" },
				contributedBy: "ModB",
				declarationIndex: 1,
			},
		];

		const mockRouter = makeMockRouter();
		assembleApp(makeFrozenWorld(routes), { express: { Router: () => mockRouter as never } });

		// Sorted by declarationIndex: /a (0), /b (1), /c (2)
		expect(mockRouter.useCalls[0]?.mountPath).toBe("/a");
		expect(mockRouter.useCalls[1]?.mountPath).toBe("/b");
		expect(mockRouter.useCalls[2]?.mountPath).toBe("/c");
	});
});

// ---------------------------------------------------------------------------
// 6. AppHandle.router exists
// ---------------------------------------------------------------------------

describe("assembleApp — 6. AppHandle.router exists", () => {
	it("handle.router has a use method (Express Router-like)", () => {
		const mockRouter = makeMockRouter();
		const handle = assembleApp(makeFrozenWorld([]), {
			express: { Router: () => mockRouter as never },
		});

		expect(typeof (handle.router as { use?: unknown }).use).toBe("function");
	});
});

// ---------------------------------------------------------------------------
// 7. AppHandle.dispose is single-shot
// ---------------------------------------------------------------------------

describe("assembleApp — 7. dispose is single-shot", () => {
	it("calling dispose twice runs cleanup exactly once", async () => {
		let cleanupCount = 0;
		const cleanups: CleanupRecord[] = [
			{
				module: "TestMod",
				componentKey: "config" as never,
				cleanup: () => {
					cleanupCount++;
				},
				value: {},
			},
		];

		const mockRouter = makeMockRouter();
		const handle = assembleApp(makeFrozenWorld([], cleanups), {
			express: { Router: () => mockRouter as never },
		});

		await handle.dispose();
		await handle.dispose();

		expect(cleanupCount).toBe(1);
	});
});

// ---------------------------------------------------------------------------
// 8. AppHandle.dispose aggregates cleanup errors into AggregateError
// ---------------------------------------------------------------------------

describe("assembleApp — 8. dispose aggregates cleanup errors", () => {
	it("two failing cleanups produce AggregateError with both errors", async () => {
		const err1 = new Error("cleanup-1-fail");
		const err2 = new Error("cleanup-2-fail");

		const cleanups: CleanupRecord[] = [
			{
				module: "ModA",
				componentKey: "config" as never,
				cleanup: () => {
					throw err1;
				},
				value: {},
			},
			{
				module: "ModB",
				componentKey: "pathResolver" as never,
				cleanup: () => {
					throw err2;
				},
				value: {},
			},
		];

		const mockRouter = makeMockRouter();
		const handle = assembleApp(makeFrozenWorld([], cleanups), {
			express: { Router: () => mockRouter as never },
		});

		let thrown: unknown;
		try {
			await handle.dispose();
		} catch (err) {
			thrown = err;
		}
		expect(thrown).toBeInstanceOf(AggregateError);
		const aggErr = thrown as AggregateError;
		expect(aggErr.errors).toHaveLength(2);
		expect(aggErr.errors).toContain(err1);
		expect(aggErr.errors).toContain(err2);
	});
});

// ---------------------------------------------------------------------------
// 9. AppHandle.dispose falls back to Symbol.asyncDispose
// ---------------------------------------------------------------------------

describe("assembleApp — 9. dispose falls back to Symbol.asyncDispose", () => {
	it("component with Symbol.asyncDispose (no explicit cleanup) has asyncDispose called", async () => {
		let asyncDisposeCalled = false;
		const disposableValue = {
			[Symbol.asyncDispose]: async () => {
				asyncDisposeCalled = true;
			},
		};

		// No explicit cleanups for this component key
		const mockRouter = makeMockRouter();
		const handle = assembleApp(
			makeFrozenWorld([], [], { myComp: disposableValue } as Record<string, unknown>),
			{ express: { Router: () => mockRouter as never } },
		);

		await handle.dispose();
		expect(asyncDisposeCalled).toBe(true);
	});
});

// ---------------------------------------------------------------------------
// 10. AppHandle.dispose does NOT call Symbol.asyncDispose when explicit cleanup declared
// ---------------------------------------------------------------------------

describe("assembleApp — 10. dispose skips Symbol.asyncDispose when explicit cleanup declared", () => {
	it("component with both explicit cleanup and asyncDispose: only explicit cleanup runs", async () => {
		let explicitCleanupCalled = false;
		let asyncDisposeCalled = false;

		const compKey = "config" as never;
		const disposableValue = {
			[Symbol.asyncDispose]: async () => {
				asyncDisposeCalled = true;
			},
		};

		const cleanups: CleanupRecord[] = [
			{
				module: "ModA",
				componentKey: compKey,
				cleanup: () => {
					explicitCleanupCalled = true;
				},
				value: disposableValue,
			},
		];

		const mockRouter = makeMockRouter();
		const handle = assembleApp(
			makeFrozenWorld([], cleanups, { config: disposableValue } as Record<string, unknown>),
			{ express: { Router: () => mockRouter as never } },
		);

		await handle.dispose();
		expect(explicitCleanupCalled).toBe(true);
		expect(asyncDisposeCalled).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// 11. AppHandle.components is Object.frozen
// ---------------------------------------------------------------------------

describe("assembleApp — 11. AppHandle.components is Object.frozen", () => {
	it("Object.isFrozen(handle.components) === true", () => {
		const mockRouter = makeMockRouter();
		const handle = assembleApp(makeFrozenWorld([]), {
			express: { Router: () => mockRouter as never },
		});

		expect(Object.isFrozen(handle.components)).toBe(true);
	});
});

// ---------------------------------------------------------------------------
// 12. The whole AppHandle is frozen
// ---------------------------------------------------------------------------

describe("assembleApp — 12. AppHandle itself is Object.frozen", () => {
	it("Object.isFrozen(handle) === true", () => {
		const mockRouter = makeMockRouter();
		const handle = assembleApp(makeFrozenWorld([]), {
			express: { Router: () => mockRouter as never },
		});

		expect(Object.isFrozen(handle)).toBe(true);
	});
});
