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
import { DiscoveryDocumentError } from "#/discovery/buildDocument.mjs";
import { createLifecycleRegistrar } from "../../adapters/AdapterFactory.mjs";
import { assembleApp } from "../assemble-app.mjs";
import type { CleanupRecord, CollectedRouteContribution, FrozenWorld } from "../types.mjs";
import { BootError } from "../types.mjs";

// ---------------------------------------------------------------------------
// Minimal stub helpers
// ---------------------------------------------------------------------------

/** Spy-instrumented mock Router factory. */
function makeMockRouter() {
	const allUseCalls: { mountPath: string | readonly string[]; handler: unknown }[] = [];
	const router = {
		use: vi.fn((mountPath: string | readonly string[], handler: unknown) => {
			allUseCalls.push({ mountPath, handler });
		}),
		allUseCalls,
		/**
		 * Only the mounts that came from a route contribution.
		 *
		 * `assembleApp` also mounts infrastructure middleware that no module
		 * declared — the protected-resource sender-constraint guard (#264) —
		 * across several paths at once. Route contributions always mount on a
		 * single string path, so the array shape separates the two cleanly and
		 * keeps these mount-order tests about the ordering algorithm rather
		 * than about how many middlewares boot happens to install.
		 */
		get useCalls(): { mountPath: string; handler: unknown }[] {
			return allUseCalls.filter(
				(call): call is { mountPath: string; handler: unknown } =>
					typeof call.mountPath === "string",
			);
		},
	};
	return router;
}

/** Build a minimal FrozenWorld with the given routes and cleanups. */
function makeFrozenWorld(
	routes: CollectedRouteContribution[],
	cleanups: CleanupRecord[] = [],
	components: Record<string, unknown> = {},
	externalKeys: ReadonlySet<string> = new Set(),
): FrozenWorld {
	const frozenComponents = Object.freeze({ ...components }) as FrozenWorld["components"];
	return {
		components: frozenComponents,
		registries: new Map(),
		routes,
		cleanups,
		externalKeys: externalKeys as FrozenWorld["externalKeys"],
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

describe("assembleApp — 4b. mount-order: a missing edge target names the module", () => {
	it.each([
		["before", { before: ["absent"] }],
		["after", { after: ["absent"] }],
	] as const)(
		"a %s edge to an id nobody contributes names the declaring module",
		(_label, edge) => {
			// Factory-produced routes are only known here, at stage 6, so this is
			// where an operator learns of the missing target — and the route id
			// alone does not say which module to look at.
			const routes: CollectedRouteContribution[] = [
				{
					contribution: { mountPath: "/a", handler: vi.fn() as never, id: "a", ...edge },
					contributedBy: "ModA",
					declarationIndex: 0,
				},
			];
			let thrown: BootError | undefined;
			try {
				assembleApp(makeFrozenWorld(routes), {
					express: { Router: () => makeMockRouter() as never },
				});
			} catch (err) {
				thrown = err as BootError;
			}
			expect(thrown?.reason).toBe("route-order-target-missing");
			expect(thrown?.message).toMatch(/module "ModA"/);
		},
	);
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

// ---------------------------------------------------------------------------
// 13. MUST-FIX 2 — factory-produced route validation (duplicate mountPath)
// ---------------------------------------------------------------------------

describe("assembleApp — 13. MUST-FIX 2: factory-produced route validation", () => {
	it("two factory-produced routes with the same mountPath throw duplicate-contribute(mountPath)", () => {
		const handlerA = vi.fn();
		const handlerB = vi.fn();

		// Both routes have no id and the same mountPath — simulating what
		// factory-produced routes can produce (only checked at assembleApp time).
		const routes: CollectedRouteContribution[] = [
			{
				contribution: { mountPath: "/api/users", handler: handlerA as never },
				contributedBy: "ModA",
				declarationIndex: 0,
			},
			{
				contribution: { mountPath: "/api/users", handler: handlerB as never },
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
		expect(thrown?.reason).toBe("duplicate-contribute");
		expect(thrown?.stage).toBe("assembleApp");
		if (thrown?.details.reason === "duplicate-contribute") {
			expect(thrown.details.identityKind).toBe("mountPath");
			expect(thrown.details.modules).toContain("ModA");
			expect(thrown.details.modules).toContain("ModB");
		}
	});

	it("factory-produced route with advertisement path missing leading slash throws invalid-route-advertisement-path", () => {
		const routes: CollectedRouteContribution[] = [
			{
				contribution: {
					mountPath: "/api",
					handler: vi.fn() as never,
					routes: [{ method: "GET" as never, path: "users" }], // missing leading slash
				},
				contributedBy: "ModA",
				declarationIndex: 0,
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
		expect(thrown?.reason).toBe("invalid-route-advertisement-path");
		expect(thrown?.stage).toBe("assembleApp");
		if (thrown?.details.reason === "invalid-route-advertisement-path") {
			expect(thrown.details.path).toBe("users");
			expect(thrown.details.module).toBe("ModA");
		}
	});

	it("static route and factory-produced route with same mountPath throw duplicate-contribute", () => {
		const handlerA = vi.fn();
		const handlerFactory = vi.fn();

		const routes: CollectedRouteContribution[] = [
			{
				contribution: { mountPath: "/shared", handler: handlerA as never },
				contributedBy: "StaticMod",
				declarationIndex: 0,
			},
			{
				contribution: { mountPath: "/shared", handler: handlerFactory as never },
				contributedBy: "FactoryMod",
				declarationIndex: 1,
			},
		];

		const mockRouter = makeMockRouter();
		let thrown: BootError | undefined;
		try {
			assembleApp(makeFrozenWorld(routes), { express: { Router: () => mockRouter as never } });
		} catch (err) {
			thrown = err as BootError;
		}
		expect(thrown?.reason).toBe("duplicate-contribute");
		expect(thrown?.stage).toBe("assembleApp");
	});
});

// ---------------------------------------------------------------------------
// 14. MUST-FIX 3 — Symbol.asyncDispose NOT called on override/bootstrap values
// ---------------------------------------------------------------------------

describe("assembleApp — 14. MUST-FIX 3: no asyncDispose on external (override/bootstrap) values", () => {
	it("does NOT call Symbol.asyncDispose on override values (spec §5.3 — consumer-owned)", async () => {
		const asyncDisposeSpy = vi.fn(async () => {});
		const overrideValue = {
			[Symbol.asyncDispose]: asyncDisposeSpy,
		};

		// "myService" came from overrideComponents — it is in externalKeys.
		// dispose() must NOT call asyncDispose on it.
		const mockRouter = makeMockRouter();
		const handle = assembleApp(
			makeFrozenWorld(
				[],
				[],
				{ myService: overrideValue },
				new Set(["myService"]), // externalKeys
			),
			{ express: { Router: () => mockRouter as never } },
		);

		await handle.dispose();
		expect(asyncDisposeSpy).not.toHaveBeenCalled();
	});

	it("DOES call Symbol.asyncDispose on module-provided values (not in externalKeys)", async () => {
		const asyncDisposeSpy = vi.fn(async () => {});
		const moduleValue = {
			[Symbol.asyncDispose]: asyncDisposeSpy,
		};

		// "myService" was produced by a module's provides factory — not external.
		const mockRouter = makeMockRouter();
		const handle = assembleApp(
			makeFrozenWorld(
				[],
				[],
				{ myService: moduleValue },
				new Set(), // empty — this key is NOT external
			),
			{ express: { Router: () => mockRouter as never } },
		);

		await handle.dispose();
		expect(asyncDisposeSpy).toHaveBeenCalledOnce();
	});
});

// ---------------------------------------------------------------------------
// 17. listen(): wraps router in Express app for fall-through finalhandler
// ---------------------------------------------------------------------------

describe("assembleApp — 17. listen() wraps router in Express app", () => {
	// ---------------------------------------------------------------------------
	// 14. D-5 LifecycleRegistrar drain (Step 3 in buildDispose)
	// ---------------------------------------------------------------------------

	describe("assembleApp — 14. dispose drains LifecycleRegistrar (D-5)", () => {
		it("registered cleanups run in LIFO order during AppHandle.dispose", async () => {
			const order: string[] = [];
			const reg = createLifecycleRegistrar();
			reg.register(async () => {
				order.push("first");
			});
			reg.register(async () => {
				order.push("second");
			});

			const mockRouter = makeMockRouter();
			const handle = assembleApp(makeFrozenWorld([]), {
				express: { Router: () => mockRouter as never },
				lifecycleReg: reg,
			});

			await handle.dispose();
			// LIFO: second-registered runs first.
			expect(order).toEqual(["second", "first"]);
		});

		it("LifecycleRegistrar drain errors accumulate into the dispose AggregateError", async () => {
			const reg = createLifecycleRegistrar();
			reg.register(async () => {
				throw new Error("registrar-cleanup-boom");
			});

			const mockRouter = makeMockRouter();
			const handle = assembleApp(makeFrozenWorld([]), {
				express: { Router: () => mockRouter as never },
				lifecycleReg: reg,
			});

			await expect(handle.dispose()).rejects.toThrow(/lifecycle-registrar/);
		});
	});

	// ---------------------------------------------------------------------------
	// 15. listen() — 404 fallthrough
	// ---------------------------------------------------------------------------

	it("returns 404 (not crash with 'next is not a function') for unmatched paths", async () => {
		// Regression: passing a bare Express Router to http.createServer means
		// fall-through requests cause "TypeError: next is not a function"
		// (Router is middleware expecting an outer (req, res, next) caller).
		// listen() must wrap router in a real Express app so the standard
		// finalhandler returns a 404 response.
		const { default: express } = await import("express");
		const handle = assembleApp(makeFrozenWorld([]), {
			express: { Router: () => express.Router() },
		});

		const server = await handle.listen(0);
		try {
			const address = server.address();
			if (address === null || typeof address === "string") {
				throw new Error("listen() returned an unexpected address");
			}
			const response = await fetch(`http://127.0.0.1:${address.port}/nonexistent`, {
				signal: AbortSignal.timeout(2000),
			});
			expect(response.status).toBe(404);
			await response.text();
		} finally {
			await new Promise<void>((resolve, reject) => {
				server.close((err) => (err ? reject(err) : resolve()));
			});
			await handle.dispose();
		}
	});
});

// ---------------------------------------------------------------------------
// 18. discovery: only the document's own error is converted (#626 F4)
// ---------------------------------------------------------------------------

describe("assembleApp — 18. discovery: only the document's own error is converted (#626 F4)", () => {
	/** A contribution that assembles into a valid document. */
	const providerRoot = {
		providerRoot: true,
		endpoints: {
			authorization_endpoint: "/oauth/authorize",
			token_endpoint: "/oauth/token",
			jwks_uri: "/.well-known/jwks.json",
		},
		metadata: {
			response_types_supported: ["code"],
			subject_types_supported: ["public"],
		},
	};

	const worldWith = (contribution: object): FrozenWorld => ({
		...makeFrozenWorld([], [], {
			config: { oauth: { jwt: { issuer: "https://auth.example.com" } } },
			keyStore: { algorithm: "HS256" },
		}),
		registries: new Map([
			["discoveryMetadata", { values: () => [contribution].values() }],
		]) as FrozenWorld["registries"],
	});

	const thrownBy = (run: () => unknown): unknown => {
		try {
			run();
		} catch (err) {
			return err;
		}
		return undefined;
	};

	it("does not convert a router-factory failure, even one that is a DiscoveryDocumentError (#650)", () => {
		// The conversion into `reason: "discovery-document-invalid"` is for a
		// document that did not assemble. The router factory is called after
		// the document is planned and outside the conversion, so what it throws
		// arrives as itself — including an error whose TYPE says "document",
		// which a `try` around the whole planner call would have relabelled.
		const routerFailure = new DiscoveryDocumentError("thrown by the router factory");

		const thrown = thrownBy(() =>
			assembleApp(worldWith(providerRoot), {
				express: {
					Router: () => {
						throw routerFailure;
					},
				},
			}),
		);

		expect(thrown).toBe(routerFailure);
		expect(thrown).not.toBeInstanceOf(BootError);
	});

	it.each([
		[
			"a key store whose algorithm getter throws",
			(failure: Error): FrozenWorld => {
				const base = worldWith(providerRoot);
				return {
					...base,
					// Through `unknown`: a host's own object in the slot is not a
					// `KeyStore`, which is the case under test.
					components: Object.freeze({
						...base.components,
						keyStore: {
							get algorithm(): never {
								throw failure;
							},
						},
					}) as unknown as FrozenWorld["components"],
				};
			},
		],
		[
			"a collector whose values() throws",
			(failure: Error): FrozenWorld => ({
				...worldWith(providerRoot),
				registries: new Map([
					[
						"discoveryMetadata",
						{
							values: () => {
								throw failure;
							},
						},
					],
				]) as FrozenWorld["registries"],
			}),
		],
	])("does not convert %s, even with a DiscoveryDocumentError (#650)", (_label, world) => {
		// Host-supplied code outside the document builder. `assembleApp` has
		// no `try` around the planner any more — only the builder's own error
		// comes back as a value to convert — so what these throw arrives as
		// itself whatever its type.
		const failure = new DiscoveryDocumentError("thrown by host code, not by the builder");

		const thrown = thrownBy(() =>
			assembleApp(world(failure), { express: { Router: () => ({}) as never } }),
		);

		expect(thrown).toBe(failure);
		expect(thrown).not.toBeInstanceOf(BootError);
	});

	it("does not iterate the collector when no issuer is configured (#650)", () => {
		// Before #626 F4 the planner returned before touching the collector
		// when the issuer was missing. Building the collector into an argument
		// would run it first — host code, on a deployment that serves no
		// document — so the call site passes a reader, and this pins that it
		// is not called.
		let iterated = false;
		const world: FrozenWorld = {
			...makeFrozenWorld([], [], {
				config: { oauth: { jwt: {} } },
				keyStore: { algorithm: "HS256" },
			}),
			registries: new Map([
				[
					"discoveryMetadata",
					{
						values: () => {
							iterated = true;
							throw new Error("the collector must not be read without an issuer");
						},
					},
				],
			]) as FrozenWorld["registries"],
		};

		expect(() =>
			assembleApp(world, { express: { Router: () => makeMockRouter() as never } }),
		).not.toThrow();
		expect(iterated).toBe(false);
	});

	it("re-raises a failure while planning the document that is not the document's own error", () => {
		// A contribution is host data. One whose getter throws fails inside
		// document planning, and that is not a document that failed to
		// validate — so it too arrives as itself rather than as a
		// `discovery-document-invalid` boot error.
		const readFailure = new TypeError("contribution getter failed");
		const hostile = {
			providerRoot: true,
			get endpoints(): never {
				throw readFailure;
			},
		};

		const thrown = thrownBy(() =>
			assembleApp(worldWith(hostile), { express: { Router: () => ({}) as never } }),
		);

		expect(thrown).toBe(readFailure);
		expect(thrown).not.toBeInstanceOf(BootError);
	});
});
