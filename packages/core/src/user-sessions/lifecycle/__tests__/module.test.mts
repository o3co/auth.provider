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
 * `sessionLifecycleModule` at boot: the slot it fills, the notifier a
 * composition with relying parties must wire, and the sweep it starts only
 * when `core.sessionLifecycle.sweepIntervalSeconds` is written.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
	createApp,
	createInMemorySessionLifecycleStore,
	defaultRefreshTokenFamilyRevocationModule,
	defineModule,
	InMemoryClientRepository,
	memoryFederationTokenStoreModule,
	memoryRefreshTokenFamilyStoreModule,
	memorySessionStoresModule,
	readCoreSection,
	type SessionCloseNotifier,
	type SessionLifecycle,
	sessionLifecycleModule,
} from "#/index.mjs";
import { coreConfigForTests, makeValidCoreConfig } from "#/testing/index.mjs";

const SWEEP_KEY = "core.sessionLifecycle.sweepIntervalSeconds";

/** A module whose route makes boot materialise `sessionLifecycle`. */
const activator = defineModule({
	name: "lifecycle-activator",
	requires: ["sessionLifecycle"] as never,
	contributes: {
		routes: [
			{
				mountPath: "/__test_noop__",
				id: "test-noop",
				handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
			},
		],
	},
});

const MODULES = [
	memorySessionStoresModule,
	memoryRefreshTokenFamilyStoreModule,
	defaultRefreshTokenFamilyRevocationModule,
	memoryFederationTokenStoreModule,
	sessionLifecycleModule,
	activator,
];

const notifier: SessionCloseNotifier = { notify: async () => undefined };

/** Boots the modules over core's valid config, its `core` section laid over by `sweep`. */
const boot = (
	options: {
		readonly sweepIntervalSeconds?: unknown;
		readonly components?: Record<string, unknown>;
		readonly overrides?: Record<string, unknown>;
	} = {},
) => {
	const config = makeValidCoreConfig();
	const core = coreConfigForTests(
		options.sweepIntervalSeconds === undefined
			? {}
			: { sessionLifecycleSweepIntervalSeconds: options.sweepIntervalSeconds },
	).core;
	return createApp({
		modules: MODULES,
		bootstrapComponents: {
			config: { ...config, core },
			pathResolver: (p: string) => p,
			...options.components,
		},
		...(options.overrides === undefined ? {} : { overrideComponents: options.overrides }),
	} as never);
};

afterEach(() => {
	vi.useRealTimers();
});

describe("sessionLifecycleModule", () => {
	it("is named core-session-lifecycle", () => {
		expect(sessionLifecycleModule.name).toBe("core-session-lifecycle");
	});

	it("fills the sessionLifecycle slot over the stores", async () => {
		const handle = await boot();
		const lifecycle = (handle.components as Record<string, unknown>)
			.sessionLifecycle as SessionLifecycle;
		expect(await lifecycle.close("no-such-session", "expiry")).toEqual({
			outcome: "done",
			rps: [],
			federations: [],
		});
		expect(await lifecycle.liveness("no-such-session")).toEqual({ outcome: "not_live" });
		await handle.dispose();
	});

	it("refuses to boot with relying parties (a client repository) and no notifier", async () => {
		await expect(
			boot({ components: { clientRepository: new InMemoryClientRepository(new Map()) } }),
		).rejects.toThrow(/sessionCloseNotifier/);
	});

	it("boots with relying parties and a notifier", async () => {
		const handle = await boot({
			components: {
				clientRepository: new InMemoryClientRepository(new Map()),
				sessionCloseNotifier: notifier,
			},
		});
		await handle.dispose();
	});

	describe("the sweep", () => {
		/** A lifecycle store that counts its closing listings. */
		const countingStore = () => {
			const inner = createInMemorySessionLifecycleStore();
			let listings = 0;
			return {
				store: {
					...inner,
					listClosing: (limit: number, after?: string) => {
						listings += 1;
						return inner.listClosing(limit, after);
					},
				},
				listings: () => listings,
			};
		};

		it("resumes pending closes every sweepIntervalSeconds, and stops on dispose", async () => {
			vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
			const counting = countingStore();
			const handle = await boot({
				sweepIntervalSeconds: "30",
				overrides: { sessionLifecycleStore: counting.store },
			});
			expect(counting.listings()).toBe(0);
			await vi.advanceTimersByTimeAsync(30_000);
			expect(counting.listings()).toBe(1);
			await vi.advanceTimersByTimeAsync(30_000);
			expect(counting.listings()).toBe(2);
			await handle.dispose();
			await vi.advanceTimersByTimeAsync(90_000);
			expect(counting.listings()).toBe(2);
		});

		it("does not sweep unless the interval is written", async () => {
			vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
			const counting = countingStore();
			const handle = await boot({ overrides: { sessionLifecycleStore: counting.store } });
			await vi.advanceTimersByTimeAsync(24 * 60 * 60 * 1000);
			expect(counting.listings()).toBe(0);
			await handle.dispose();
		});

		it.each([0, -1, 1.5, "1e3", "", true, 2_147_484])(
			"refuses to boot with an interval of %j, naming the key",
			async (value) => {
				await expect(boot({ sweepIntervalSeconds: value })).rejects.toThrow(SWEEP_KEY);
			},
		);
	});
});

describe("core.sessionLifecycle", () => {
	it("is read as part of core's section", () => {
		expect(readCoreSection({ core: { sessionLifecycle: { sweepIntervalSeconds: 60 } } })).toEqual({
			sessionLifecycle: { sweepIntervalSeconds: 60 },
		});
	});

	it("refuses an unknown key, naming it", () => {
		expect(() => readCoreSection({ core: { sessionLifecycle: { sweepInterval: 60 } } })).toThrow(
			/core\.sessionLifecycle/,
		);
	});
});
