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
 * The `sessionCloseNotifiers` contribution kind, booted through
 * `createApp`: at most one notifier, judged at stage 1; a container that is
 * no record and any override refused there; and the rule that a composition
 * serving relying parties contributes one, judged at the end of stage 4 only
 * where core's session lifecycle module built the slot.
 */

import { describe, expect, it } from "vitest";
import {
	createApp,
	defaultRefreshTokenFamilyRevocationModule,
	defineModule,
	InMemoryClientRepository,
	type Module,
	memoryFederationTokenStoreModule,
	memoryRefreshTokenFamilyStoreModule,
	memorySessionStoresModule,
	type SessionCloseNotifier,
	sessionLifecycleModule,
} from "#/index.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";

const LIFECYCLE = [
	memorySessionStoresModule,
	memoryRefreshTokenFamilyStoreModule,
	defaultRefreshTokenFamilyRevocationModule,
	memoryFederationTokenStoreModule,
	sessionLifecycleModule,
];

const notifier: SessionCloseNotifier = { notify: async () => undefined };

const boot = (modules: readonly Module[], components: Record<string, unknown> = {}) =>
	createApp({
		modules,
		bootstrapComponents: {
			config: makeValidCoreConfig(),
			pathResolver: (p: string) => p,
			...components,
		},
	} as never);

const contributing = (name: string): Module =>
	defineModule({ name, contributes: { sessionCloseNotifiers: { [name]: () => notifier } } });

describe("sessionCloseNotifiers", () => {
	it("refuses a second notifier at stage 1, whatever its name", async () => {
		await expect(boot([contributing("tell-a"), contributing("tell-b")])).rejects.toMatchObject({
			reason: "duplicate-contribute",
			stage: "validateManifests",
			details: {
				reason: "duplicate-contribute",
				kind: "sessionCloseNotifiers",
				identityKind: "name",
				modules: ["tell-a", "tell-b"],
			},
		});
	});

	it("refuses an override of the notifier at stage 1, as the kind guarded", async () => {
		const overriding = defineModule({
			name: "silencer",
			overrides: { sessionCloseNotifiers: { "tell-a": () => notifier } },
		});
		await expect(boot([contributing("tell-a"), overriding])).rejects.toMatchObject({
			reason: "contribution-kind-guarded",
			stage: "validateManifests",
			details: {
				reason: "contribution-kind-guarded",
				kind: "sessionCloseNotifiers",
				channel: "overrides",
				module: "silencer",
			},
		});
	});

	it("refuses a container that is no record at stage 1", async () => {
		const listed = defineModule({
			name: "listed",
			contributes: { sessionCloseNotifiers: [() => notifier] } as never,
		});
		await expect(boot([listed])).rejects.toMatchObject({
			reason: "contribution-malformed",
			stage: "validateManifests",
			details: { kind: "sessionCloseNotifiers", channel: "contributes" },
		});
	});

	it("leaves a sessionLifecycle the host filled to the host: no notifier rule applies", async () => {
		const handle = await createApp({
			modules: LIFECYCLE,
			bootstrapComponents: {
				config: makeValidCoreConfig(),
				pathResolver: (p: string) => p,
				clientRepository: new InMemoryClientRepository(new Map()),
			},
			overrideComponents: { sessionLifecycle: { close: async () => undefined } },
		} as never);
		await handle.dispose();
	});

	it("applies the rule where the lifecycle module built the slot", async () => {
		await expect(
			boot(LIFECYCLE, { clientRepository: new InMemoryClientRepository(new Map()) }),
		).rejects.toMatchObject({
			reason: "provides-factory-failed",
			stage: "applyContributions",
			details: { module: "core-session-lifecycle", componentKey: "sessionLifecycle" },
		});
	});
});
