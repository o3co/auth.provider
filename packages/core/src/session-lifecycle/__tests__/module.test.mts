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
	type Module,
	memoryFederationTokenStoreModule,
	memoryRefreshTokenFamilyStoreModule,
	memorySessionStoresModule,
	readCoreSection,
	type SessionCloseNotice,
	type SessionCloseNotifier,
	type SessionLifecycle,
	sessionLifecycleModule,
} from "#/index.mjs";
import {
	coreConfigForTests,
	createTestOAuthTokenSettings,
	makeValidCoreConfig,
} from "#/testing/index.mjs";

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

/** A module that contributes `notifier` as its session-close notifier. */
const notifierModule = (
	name = "test-notifier",
	contributed: SessionCloseNotifier | null = notifier,
): Module =>
	defineModule({
		name,
		contributes: { sessionCloseNotifiers: { [name]: () => contributed as SessionCloseNotifier } },
	});

/** Boots the modules over core's valid config, its `core` section laid over by `sweep`. */
const boot = (
	options: {
		readonly sweepIntervalSeconds?: unknown;
		readonly components?: Record<string, unknown>;
		readonly overrides?: Record<string, unknown>;
		readonly activated?: boolean;
		readonly extra?: readonly Module[];
	} = {},
) => {
	const config = makeValidCoreConfig();
	const core = coreConfigForTests(
		options.sweepIntervalSeconds === undefined
			? {}
			: { sessionLifecycleSweepIntervalSeconds: options.sweepIntervalSeconds },
	).core;
	return createApp({
		modules: [
			...(options.activated === false ? MODULES.filter((m) => m !== activator) : MODULES),
			...(options.extra ?? []),
		],
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

	it("is built at boot with nothing requiring the slot", async () => {
		const handle = await boot({ activated: false });
		expect(
			typeof ((handle.components as Record<string, unknown>).sessionLifecycle as SessionLifecycle)
				.close,
		).toBe("function");
		await handle.dispose();
	});

	it("refuses relying parties without a notifier with nothing requiring the slot", async () => {
		await expect(
			boot({
				activated: false,
				components: { clientRepository: new InMemoryClientRepository(new Map()) },
			}),
		).rejects.toThrow(/sessionCloseNotifier/);
	});

	it("boots with relying parties and a contributed notifier", async () => {
		const handle = await boot({
			components: { clientRepository: new InMemoryClientRepository(new Map()) },
			extra: [notifierModule()],
		});
		await handle.dispose();
	});

	it("refuses with the provider's reason and text, at the end of the contributions", async () => {
		await expect(
			boot({ components: { clientRepository: new InMemoryClientRepository(new Map()) } }),
		).rejects.toMatchObject({
			reason: "provides-factory-failed",
			message: expect.stringContaining(
				"core-session-lifecycle: relying parties are served (the clientRepository slot is filled) " +
					"and no sessionCloseNotifier is wired, so a closed session's relying parties would never " +
					"be told. Install a module that contributes a sessionCloseNotifiers entry (oauthEndpointsModule does).",
			),
		});
	});

	it("refuses a second notifier at stage 1", async () => {
		await expect(
			boot({ extra: [notifierModule("notifier-a"), notifierModule("notifier-b")] }),
		).rejects.toMatchObject({
			reason: "duplicate-contribute",
			stage: "validateManifests",
			details: { kind: "sessionCloseNotifiers", modules: ["notifier-a", "notifier-b"] },
		});
	});

	it("refuses a notifier factory that answers no notifier", async () => {
		await expect(boot({ extra: [notifierModule("notifier-a", null)] })).rejects.toMatchObject({
			reason: "contribute-factory-failed",
		});
	});

	it("refuses a host collector for the notifiers", async () => {
		const config = makeValidCoreConfig();
		await expect(
			createApp({
				modules: MODULES,
				bootstrapComponents: { config, pathResolver: (p: string) => p },
				contributionKinds: { sessionCloseNotifiers: {} },
			} as never),
		).rejects.toMatchObject({
			reason: "contribution-kind-guarded",
			details: { kind: "sessionCloseNotifiers" },
		});
	});

	it("boots a notifier that reads a slot of a module requiring the lifecycle, with no cycle", async () => {
		const notices: SessionCloseNotice[] = [];
		// Stands in for the module that issues to relying parties: it provides
		// the token settings and requires the lifecycle.
		const issuing = defineModule({
			name: "issuing",
			requires: ["sessionLifecycle"] as never,
			provides: { oauthTokenSettings: () => createTestOAuthTokenSettings() },
		});
		const telling = defineModule({
			name: "telling",
			requires: ["oauthTokenSettings"] as never,
			contributes: {
				sessionCloseNotifiers: {
					telling: (deps: { readonly oauthTokenSettings: { readonly issuer: string } }) => ({
						notify: async (notice: SessionCloseNotice) => {
							expect(deps.oauthTokenSettings.issuer).toBeTypeOf("string");
							notices.push(notice);
						},
					}),
				},
			} as never,
		});
		const handle = await boot({
			components: { clientRepository: new InMemoryClientRepository(new Map()) },
			extra: [issuing, telling],
		});
		const components = handle.components as Record<string, unknown>;
		const lifecycle = components.sessionLifecycle as SessionLifecycle;
		const sessions = components.userSessionStore as {
			create(input: unknown): Promise<void>;
		};
		const expiresAt = new Date(Date.now() + 3_600_000);
		await sessions.create({
			sid: "sid-1",
			sub: "user-1",
			authTime: new Date(),
			expiresAt,
			claims: {},
			amr: ["pwd"],
			authentication: undefined,
		});
		const rp = {
			clientId: "rp-a",
			backchannelLogoutUri: undefined,
			backchannelLogoutSessionRequired: undefined,
			frontchannelLogoutUri: undefined,
			frontchannelLogoutSessionRequired: undefined,
			registeredAt: new Date(),
		};
		expect(await lifecycle.join("sid-1", { rp, familyId: "f1" })).toEqual({ outcome: "joined" });
		expect((await lifecycle.close("sid-1", "rp_logout")).outcome).toBe("done");
		expect(notices).toEqual([
			{ sid: "sid-1", sub: "user-1", clientId: "rp-a", cause: "rp_logout" },
		]);
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
				activated: false,
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
