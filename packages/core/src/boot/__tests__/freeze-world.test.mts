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

import { describe, expect, it } from "vitest";
import { GrantRegistry } from "../../grants/registry.mjs";
import { freezeWorld } from "../freeze-world.mjs";
import type {
	CollectedRouteContribution,
	ContributionKind,
	FrozenWorld,
	ListCollector,
	NameKeyedCollector,
	RegistryWorld,
	RouteCollector,
} from "../types.mjs";

// ---------------------------------------------------------------------------
// Helpers — minimal RegistryWorld builder
// ---------------------------------------------------------------------------

function makeMinimalRegistryWorld(
	registries: ReadonlyMap<ContributionKind, unknown> = new Map(),
): RegistryWorld {
	return {
		material: {
			plan: {
				validated: {
					modules: [],
					byName: new Map(),
					providers: new Map(),
					usedKinds: new Set(),
				},
				initOrder: [],
				providerActivations: [],
				depsBlueprint: new Map(),
			},
			components: {} as never,
			cleanups: [],
		},
		registries,
		routes: [],
	};
}

// ---------------------------------------------------------------------------
// Stub collectors
// ---------------------------------------------------------------------------

function makeStubNameKeyedCollector<V = unknown>(opts?: {
	withFreeze?: boolean;
}): NameKeyedCollector<V> & {
	freezeCalled: boolean;
} {
	const m = new Map<string, V>();
	let frozen = false;
	const collector = {
		kind: "name-keyed" as const,
		freezeCalled: false,
		register(name: string, value: V): void {
			if (frozen) throw new Error(`frozen; cannot register "${name}"`);
			if (m.has(name)) throw new Error(`duplicate "${name}"`);
			m.set(name, value);
		},
		replace(name: string, value: V): void {
			if (frozen) throw new Error(`frozen; cannot replace "${name}"`);
			if (!m.has(name)) throw new Error(`unknown "${name}"`);
			m.set(name, value);
		},
		get(name: string): V | undefined {
			return m.get(name);
		},
		entries(): IterableIterator<readonly [string, V]> {
			return m.entries() as IterableIterator<readonly [string, V]>;
		},
	} as NameKeyedCollector<V> & { freezeCalled: boolean };

	if (opts?.withFreeze !== false) {
		(collector as unknown as { freeze(): void }).freeze = () => {
			collector.freezeCalled = true;
			frozen = true;
		};
	}

	return collector;
}

function makeStubRouteCollector(): RouteCollector & { freezeCalled: boolean } {
	const items: CollectedRouteContribution[] = [];
	let frozen = false;
	return {
		kind: "list-routes" as const,
		freezeCalled: false,
		append(value: CollectedRouteContribution): void {
			if (frozen) throw new Error("RouteCollector is frozen");
			items.push(value);
		},
		freeze(): void {
			(this as { freezeCalled: boolean }).freezeCalled = true;
			frozen = true;
		},
		values(): IterableIterator<CollectedRouteContribution> {
			return items.values();
		},
	};
}

function makeStubListCollectorNoFreeze<V = unknown>(): ListCollector<V> & {
	freezeCalled: boolean;
} {
	const items: V[] = [];
	return {
		kind: "list" as const,
		freezeCalled: false,
		append(value: V): void {
			items.push(value);
		},
		values(): IterableIterator<V> {
			return items.values();
		},
		// No freeze() — deliberately omitted
	};
}

// ---------------------------------------------------------------------------
// 1. Object.freeze on the component map
// ---------------------------------------------------------------------------

describe("freezeWorld — 1. Object.freeze on component map", () => {
	it("components is Object.frozen after freezeWorld", () => {
		const world = makeMinimalRegistryWorld();
		const frozen: FrozenWorld = freezeWorld(world);
		expect(Object.isFrozen(frozen.components)).toBe(true);
	});

	it("adding a property to the frozen component map has no effect (strict mode would throw)", () => {
		const world = makeMinimalRegistryWorld();
		const frozen: FrozenWorld = freezeWorld(world);
		// In strict ESM modules, assigning to a frozen object throws.
		// In non-strict mode it silently fails. Either way the key must not be added.
		try {
			(frozen.components as Record<string, unknown>).newKey = 1;
		} catch {
			// expected in strict mode
		}
		expect((frozen.components as Record<string, unknown>).newKey).toBeUndefined();
	});
});

// ---------------------------------------------------------------------------
// 2. GrantRegistry.freeze() invoked
// ---------------------------------------------------------------------------

describe("freezeWorld — 2. GrantRegistry.freeze() invoked via name-keyed collector", () => {
	it("after freezeWorld, calling register on GrantRegistry throws reason=frozen", () => {
		const grantRegistry = new GrantRegistry();
		// Wrap it so it satisfies NameKeyedCollector<GrantHandler> interface.
		// GrantRegistry already exposes register/replace/freeze/get/entries.
		const registries: Map<ContributionKind, unknown> = new Map([["grants", grantRegistry]]);

		const world = makeMinimalRegistryWorld(registries);
		freezeWorld(world);

		// Post-freeze: any attempt to register must throw with reason "frozen"
		expect(() => {
			grantRegistry.register("authorization_code", {} as never);
		}).toThrow();

		// Verify it is the GrantRegistryError with reason="frozen"
		let thrown: unknown;
		try {
			grantRegistry.register("authorization_code", {} as never);
		} catch (err) {
			thrown = err;
		}
		expect(thrown).toBeDefined();
		const e = thrown as { reason?: string; name?: string };
		expect(e.name).toBe("GrantRegistryError");
		expect(e.reason).toBe("frozen");
	});
});

// ---------------------------------------------------------------------------
// 3. ExchangeTokenValidatorRegistry stub — freeze() invoked
// ---------------------------------------------------------------------------

describe("freezeWorld — 3. ExchangeTokenValidatorRegistry-like stub freeze() invoked", () => {
	it("stub registry with freeze() has freeze() called; post-freeze register throws", () => {
		// Use a stub that mimics ExchangeTokenValidatorRegistry behaviour
		// (same contract: register/replace/freeze, throws reason="frozen" post-freeze).
		const stubRegistry = makeStubNameKeyedCollector<unknown>({ withFreeze: true });

		const registries: Map<ContributionKind, unknown> = new Map([
			["tokenExchangeValidators", stubRegistry],
		]);

		const world = makeMinimalRegistryWorld(registries);
		freezeWorld(world);

		expect(stubRegistry.freezeCalled).toBe(true);
		expect(() => {
			stubRegistry.register("urn:token-type:access_token", {});
		}).toThrow(/frozen/);
	});
});

// ---------------------------------------------------------------------------
// 4. RouteCollector.freeze() invoked
// ---------------------------------------------------------------------------

describe("freezeWorld — 4. RouteCollector.freeze() invoked", () => {
	it("after freezeWorld, calling append on RouteCollector throws", () => {
		const routeCollector = makeStubRouteCollector();

		const registries: Map<ContributionKind, unknown> = new Map([["routes", routeCollector]]);

		const world = makeMinimalRegistryWorld(registries);
		freezeWorld(world);

		expect(routeCollector.freezeCalled).toBe(true);
		expect(() => {
			routeCollector.append({
				contribution: { mountPath: "/test", handler: {} as never },
				contributedBy: "TestModule",
				declarationIndex: 0,
			});
		}).toThrow(/frozen/);
	});
});

// ---------------------------------------------------------------------------
// 5. Optional freeze?() — called when defined, skipped when absent
// ---------------------------------------------------------------------------

describe("freezeWorld — 5. Optional freeze?() on ListCollector", () => {
	it("ListCollector without freeze: freezeWorld does not throw", () => {
		const listCollector = makeStubListCollectorNoFreeze<unknown>();

		const registries: Map<ContributionKind, unknown> = new Map([["auditHooks", listCollector]]);

		const world = makeMinimalRegistryWorld(registries);
		// Must NOT throw even though auditHooks collector has no freeze()
		expect(() => freezeWorld(world)).not.toThrow();
		expect(listCollector.freezeCalled).toBe(false);
	});

	it("ListCollector with freeze: freeze() is called", () => {
		const listCollectorWithFreeze = makeStubListCollectorNoFreeze<unknown>();
		let freezeCalled = false;
		(listCollectorWithFreeze as unknown as { freeze(): void }).freeze = () => {
			freezeCalled = true;
		};

		const registries: Map<ContributionKind, unknown> = new Map([
			["grantPolicyHooks", listCollectorWithFreeze],
		]);

		const world = makeMinimalRegistryWorld(registries);
		freezeWorld(world);

		expect(freezeCalled).toBe(true);
	});
});
