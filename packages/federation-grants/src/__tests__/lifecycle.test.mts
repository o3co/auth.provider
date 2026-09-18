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
 * Why the drain is a component and not a `lifecycleRegistrar` callback
 * (#593, D12).
 *
 * `AppHandle.dispose()` runs component cleanups first and registrar callbacks
 * afterwards, so a drain registered with the registrar would run *after* the
 * store's own cleanup — an adapter that closes its client there would pull the
 * connection out from under the rotated refresh token the drain is waiting to
 * see persisted. A component whose dependency edges point at the store, the
 * revocation boundary and the sink is ordered before all three, because
 * cleanups run in reverse of the order the components were built in.
 *
 * Those edges are `optional`, not `requires`: a deployment that installs the
 * package and leaves the feature off must still boot with no store at all. An
 * optional key still produces the ordering edge whenever a *module* fills it,
 * which is the case that has anything to close; a slot filled from
 * `bootstrapComponents` is the host's own value, and the boot planner neither
 * orders nor disposes of those.
 */

import type { BootstrapMap, FederationGrantStore } from "@o3co/auth-provider-core";
import {
	createApp,
	createMemoryFederationGrantStore,
	defineModule,
} from "@o3co/auth-provider-core";
import { makeValidCoreConfig } from "@o3co/auth-provider-core/testing";
import { describe, expect, it } from "vitest";
import { federationGrantBackgroundModule, federationGrantsModule } from "#/index.mjs";

const bootstrap = (): BootstrapMap =>
	({
		config: makeValidCoreConfig(),
		pathResolver: (s: string) => s,
	}) as unknown as BootstrapMap;

/**
 * A grant store contributed by a *module*, so that it is the boot planner's to
 * order and to close — which is the whole point being tested. Its cleanup
 * writes to `order`.
 */
const storeModuleWriting = (order: string[]) =>
	defineModule({
		name: "test-federation-grant-store",
		provides: {
			federationGrantStore: (): FederationGrantStore => createMemoryFederationGrantStore(),
		},
		lifecycle: {
			federationGrantStore: {
				cleanup: () => {
					order.push("store closed");
				},
			},
		},
	});

const tick = (): Promise<void> => new Promise((r) => setTimeout(r, 10));

describe("the background component's place in a shutdown", () => {
	it("gives each application its own registry", async () => {
		// A module-global set would be shared by two applications in one
		// process — which is what a test suite is, and what a host embedding
		// two providers is. Disposing one would drain the other's work.
		const first = await createApp({
			modules: [federationGrantBackgroundModule, federationGrantsModule],
			bootstrapComponents: bootstrap(),
		});
		const second = await createApp({
			modules: [federationGrantBackgroundModule, federationGrantsModule],
			bootstrapComponents: bootstrap(),
		});

		expect(first.components.federationGrantBackground).toBeDefined();
		expect(second.components.federationGrantBackground).toBeDefined();
		expect(first.components.federationGrantBackground).not.toBe(
			second.components.federationGrantBackground,
		);

		await first.dispose();
		expect(first.components.federationGrantBackground?.closing).toBe(true);
		expect(second.components.federationGrantBackground?.closing).toBe(false);
		await second.dispose();
	});

	it("waits for a late write before the store it was written through closes", async () => {
		const order: string[] = [];
		const handle = await createApp({
			modules: [storeModuleWriting(order), federationGrantBackgroundModule, federationGrantsModule],
			bootstrapComponents: bootstrap(),
		});

		const background = handle.components.federationGrantBackground;
		expect(background).toBeDefined();

		let persist!: () => void;
		const write = new Promise<void>((resolve) => {
			persist = () => resolve();
		});
		background?.register(
			write.then(() => {
				order.push("late write persisted");
			}),
		);

		const disposed = handle.dispose();
		await tick();
		// The store must still be open: this is the rotated refresh token that
		// the upstream has already accepted and this process has not yet
		// written down.
		expect(order).toEqual([]);

		persist();
		await disposed;
		expect(order).toEqual(["late write persisted", "store closed"]);
	});

	it("orders the drain against the store however the modules were listed", async () => {
		// The composition root's array order is not the initialisation order —
		// the planner sorts it. A drain that only happened to run first because
		// its module was written last would be a coincidence, not a contract.
		const order: string[] = [];
		const handle = await createApp({
			modules: [federationGrantsModule, federationGrantBackgroundModule, storeModuleWriting(order)],
			bootstrapComponents: bootstrap(),
		});

		let persist!: () => void;
		const write = new Promise<void>((resolve) => {
			persist = () => resolve();
		});
		handle.components.federationGrantBackground?.register(
			write.then(() => {
				order.push("late write persisted");
			}),
		);

		const disposed = handle.dispose();
		await tick();
		expect(order).toEqual([]);
		persist();
		await disposed;
		expect(order).toEqual(["late write persisted", "store closed"]);
	});

	it("is idempotent, and disposing twice does not wait again", async () => {
		const order: string[] = [];
		const handle = await createApp({
			modules: [storeModuleWriting(order), federationGrantBackgroundModule, federationGrantsModule],
			bootstrapComponents: bootstrap(),
		});

		await handle.dispose();
		await handle.dispose();
		expect(order).toEqual(["store closed"]);
	});

	it("refuses to admit new work once the drain has begun", async () => {
		const handle = await createApp({
			modules: [federationGrantBackgroundModule, federationGrantsModule],
			bootstrapComponents: bootstrap(),
		});
		const background = handle.components.federationGrantBackground;
		const release = background?.admit();
		expect(release).toBeTypeOf("function");
		// Released first, deliberately: an operation that is never released
		// holds the drain open for as long as the host's cleanup budget allows,
		// which is the documented limit of what a drain can promise — it cannot
		// turn a hung adapter read into a completed one.
		release?.();

		await handle.dispose();
		expect(background?.admit()).toBeUndefined();
	});

	it("refuses to boot the routes without the companion module", async () => {
		// `federationGrantsModules` is the documented installation form because
		// routes mounted without a registry would detach every refresh tail
		// with nothing to wait for it. Requiring the slot makes that a boot
		// refusal rather than a shutdown that silently loses writes.
		await expect(
			createApp({
				modules: [federationGrantsModule],
				bootstrapComponents: bootstrap(),
			}),
		).rejects.toThrow(/federationGrantBackground/);
	});
});
