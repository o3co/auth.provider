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
import { redisChallengeStoreBuilder } from "../src/challenges.mjs";
import type {
	ChallengeStoreClient,
	DeviceCodeStoreClient,
	ReplaySeenSetClient,
	SessionRPRegistryClient,
	SessionSidSortedSetClient,
	UserSessionStoreClient,
} from "../src/clients.mjs";
import { redisDeviceCodeStoreBuilder } from "../src/device-code-store.mjs";
import { redisReplaySeenSetBuilder } from "../src/replay-seen-set.mjs";
import { redisSessionFamilyIndexBuilder } from "../src/sessionFamilyIndex.mjs";
import { redisSessionFederationIndexBuilder } from "../src/sessionFederationIndex.mjs";
import { redisSessionRPRegistryBuilder } from "../src/sessionRPRegistry.mjs";
import { redisUserSessionStoreBuilder } from "../src/userSessionStore.mjs";

// TS-M2 (Wave 5g): boot-time guard tests for the builder-pattern entry
// points used by AdapterFactory wiring. The real factory invokes the
// builder with the merged config slice; if the slice is missing `client`,
// the prior behavior was to construct a store and crash on first Redis op
// with a cryptic `Cannot read properties of undefined`.

const noopChallengeClient: ChallengeStoreClient = {
	set: async () => "OK",
	pttl: async () => -2,
	del: async () => 0,
};

const noopReplayClient: ReplaySeenSetClient = {
	set: async () => "OK",
	exists: async () => 0,
};

describe("TS-M2: redisChallengeStoreBuilder — client guard", () => {
	it("throws when 'client' option is missing (config = {})", () => {
		expect(() =>
			redisChallengeStoreBuilder({} as never, { lifecycle: undefined } as never),
		).toThrow("redisChallengeStoreBuilder: 'client' option is required");
	});

	it("succeeds when 'client' is present", () => {
		const store = redisChallengeStoreBuilder(
			{ client: noopChallengeClient } as never,
			{ lifecycle: undefined } as never,
		);
		expect(store).toBeDefined();
		expect(store.kind).toBe("redis");
	});
});

describe("TS-M2: redisReplaySeenSetBuilder — client guard", () => {
	it("throws when 'client' option is missing (config = {})", () => {
		expect(() => redisReplaySeenSetBuilder({} as never, { lifecycle: undefined } as never)).toThrow(
			"redisReplaySeenSetBuilder: 'client' option is required",
		);
	});

	it("succeeds when 'client' is present", () => {
		const store = redisReplaySeenSetBuilder(
			{ client: noopReplayClient } as never,
			{ lifecycle: undefined } as never,
		);
		expect(store).toBeDefined();
		expect(store.kind).toBe("redis");
	});
});

// AS-9 (Wave 5h): Redis session sub-adapter builders. Same boot-time guard
// pattern as TS-M2 — fail at boot when `client` is missing rather than at
// first Redis op. The 4 builders complete the tripartite `create* + *Builder
// + *Module` pattern previously only covered by the bundled
// `redisSessionStoresModule`.

const noopSidSortedSetClient: SessionSidSortedSetClient = {
	unlink: async () => 0,
	multi: () => ({}) as never,
	pExpireAt: async () => 0,
	pExpireGT: async () => 0,
	zAdd: async () => 0,
	zRange: async () => [],
	zRem: async () => 0,
};

const noopRPRegistryClient: SessionRPRegistryClient = {
	unlink: async () => 0,
	hSet: async () => 0,
	hScanIterator: () => (async function* () {})(),
	multi: () => ({}) as never,
	pExpireAt: async () => 0,
	pExpireGT: async () => 0,
};

const noopUserSessionStoreClient: UserSessionStoreClient = {
	set: (async () => "OK") as UserSessionStoreClient["set"],
	get: async () => null,
	del: async () => 0,
};

describe("AS-9: redisSessionFamilyIndexBuilder — client guard", () => {
	it("throws when 'client' option is missing (config = {})", () => {
		expect(() =>
			redisSessionFamilyIndexBuilder({} as never, { lifecycle: undefined } as never),
		).toThrow("redisSessionFamilyIndexBuilder: 'client' option is required");
	});

	it("succeeds when 'client' is present", () => {
		const adapter = redisSessionFamilyIndexBuilder(
			{ client: noopSidSortedSetClient } as never,
			{ lifecycle: undefined } as never,
		);
		expect(adapter).toBeDefined();
		expect(adapter.kind).toBe("redis");
	});
});

describe("AS-9: redisSessionFederationIndexBuilder — client guard", () => {
	it("throws when 'client' option is missing (config = {})", () => {
		expect(() =>
			redisSessionFederationIndexBuilder({} as never, { lifecycle: undefined } as never),
		).toThrow("redisSessionFederationIndexBuilder: 'client' option is required");
	});

	it("succeeds when 'client' is present", () => {
		const adapter = redisSessionFederationIndexBuilder(
			{ client: noopSidSortedSetClient } as never,
			{ lifecycle: undefined } as never,
		);
		expect(adapter).toBeDefined();
		expect(adapter.kind).toBe("redis");
	});
});

describe("AS-9: redisSessionRPRegistryBuilder — client guard", () => {
	it("throws when 'client' option is missing (config = {})", () => {
		expect(() =>
			redisSessionRPRegistryBuilder({} as never, { lifecycle: undefined } as never),
		).toThrow("redisSessionRPRegistryBuilder: 'client' option is required");
	});

	it("succeeds when 'client' is present", () => {
		const adapter = redisSessionRPRegistryBuilder(
			{ client: noopRPRegistryClient } as never,
			{ lifecycle: undefined } as never,
		);
		expect(adapter).toBeDefined();
		expect(adapter.kind).toBe("redis");
	});
});

describe("AS-9: redisUserSessionStoreBuilder — client guard", () => {
	it("throws when 'client' option is missing (config = {})", () => {
		expect(() =>
			redisUserSessionStoreBuilder({} as never, { lifecycle: undefined } as never),
		).toThrow("redisUserSessionStoreBuilder: 'client' option is required");
	});

	it("succeeds when 'client' is present", () => {
		const adapter = redisUserSessionStoreBuilder(
			{ client: noopUserSessionStoreClient } as never,
			{ lifecycle: undefined } as never,
		);
		expect(adapter).toBeDefined();
		expect(adapter.kind).toBe("redis");
	});
});

// #433: the Redis DeviceCodeStore builder. Same boot-time guard as the
// builders above — a missing `client` is named at boot, not at the first
// device poll.

const noopDeviceCodeStoreClient: DeviceCodeStoreClient = {
	create: async () => true,
	findPending: async () => null,
	decide: async () => ({ kind: "not_found" }),
	poll: async () => ({ kind: "not_found" }),
	remove: async () => {},
};

describe("#433: redisDeviceCodeStoreBuilder — client guard", () => {
	it("throws when 'client' option is missing (config = {})", () => {
		expect(() =>
			redisDeviceCodeStoreBuilder({} as never, { lifecycle: undefined } as never),
		).toThrow("redisDeviceCodeStoreBuilder: 'client' option is required");
	});

	it("succeeds when 'client' is present", async () => {
		const store = await redisDeviceCodeStoreBuilder(
			{ client: noopDeviceCodeStoreClient } as never,
			{ lifecycle: undefined } as never,
		);
		expect(store).toBeDefined();
		expect(store.kind).toBe("redis");
	});
});
