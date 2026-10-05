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
import { redisChallengeStoreBuilder } from "#/challenges.mjs";
import type {
	ChallengeStoreClient,
	ConsentStoreClient,
	DeviceCodeStoreClient,
	PendingConsentStoreClient,
	ReplaySeenSetClient,
	SessionRPRegistryClient,
	SessionSidSortedSetClient,
	UserSessionStoreClient,
} from "#/clients.mjs";
import { redisConsentStoreBuilder, redisPendingConsentStoreBuilder } from "#/consent-store.mjs";
import { redisDeviceCodeStoreBuilder } from "#/device-code-store.mjs";
import { redisReplaySeenSetBuilder } from "#/replay-seen-set.mjs";
import { redisSessionFamilyIndexBuilder } from "#/sessionFamilyIndex.mjs";
import { redisSessionFederationIndexBuilder } from "#/sessionFederationIndex.mjs";
import { redisSessionRPRegistryBuilder } from "#/sessionRPRegistry.mjs";
import { redisUserSessionStoreBuilder } from "#/userSessionStore.mjs";

// Boot-time guards on the builders AdapterFactory wiring calls with the merged
// config slice: a slice without `client` is refused at build, by name, instead
// of building a store that fails on its first Redis call.

const noopChallengeClient: ChallengeStoreClient = {
	set: async () => "OK",
	pttl: async () => -2,
	del: async () => 0,
	get: async () => null,
};

const noopReplayClient: ReplaySeenSetClient = {
	set: async () => "OK",
	exists: async () => 0,
};

describe("redisChallengeStoreBuilder — client guard", () => {
	it("throws when 'client' option is missing (config = {})", () => {
		expect(() =>
			redisChallengeStoreBuilder({} as never, { lifecycle: undefined } as never),
		).toThrow("redisChallengeStoreBuilder: 'client' option is required");
	});

	it("succeeds when 'client' is present", () => {
		const store = redisChallengeStoreBuilder(
			{ client: noopChallengeClient } as never,
			{ lifecycle: undefined } as never,
		) as { kind: string };
		expect(store).toBeDefined();
		expect(store.kind).toBe("redis");
	});
});

describe("redisReplaySeenSetBuilder — client guard", () => {
	it("throws when 'client' option is missing (config = {})", () => {
		expect(() => redisReplaySeenSetBuilder({} as never, { lifecycle: undefined } as never)).toThrow(
			"redisReplaySeenSetBuilder: 'client' option is required",
		);
	});

	it("succeeds when 'client' is present", () => {
		const store = redisReplaySeenSetBuilder(
			{ client: noopReplayClient } as never,
			{ lifecycle: undefined } as never,
		) as { kind: string };
		expect(store).toBeDefined();
		expect(store.kind).toBe("redis");
	});
});

// The Redis session sub-adapter builders: the same boot-time guard.

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
	replaceIfUnchanged: async () => false,
};

describe("redisSessionFamilyIndexBuilder — client guard", () => {
	it("throws when 'client' option is missing (config = {})", () => {
		expect(() =>
			redisSessionFamilyIndexBuilder({} as never, { lifecycle: undefined } as never),
		).toThrow("redisSessionFamilyIndexBuilder: 'client' option is required");
	});

	it("succeeds when 'client' is present", () => {
		const adapter = redisSessionFamilyIndexBuilder(
			{ client: noopSidSortedSetClient } as never,
			{ lifecycle: undefined } as never,
		) as { kind: string };
		expect(adapter).toBeDefined();
		expect(adapter.kind).toBe("redis");
	});
});

describe("redisSessionFederationIndexBuilder — client guard", () => {
	it("throws when 'client' option is missing (config = {})", () => {
		expect(() =>
			redisSessionFederationIndexBuilder({} as never, { lifecycle: undefined } as never),
		).toThrow("redisSessionFederationIndexBuilder: 'client' option is required");
	});

	it("succeeds when 'client' is present", () => {
		const adapter = redisSessionFederationIndexBuilder(
			{ client: noopSidSortedSetClient } as never,
			{ lifecycle: undefined } as never,
		) as { kind: string };
		expect(adapter).toBeDefined();
		expect(adapter.kind).toBe("redis");
	});
});

describe("redisSessionRPRegistryBuilder — client guard", () => {
	it("throws when 'client' option is missing (config = {})", () => {
		expect(() =>
			redisSessionRPRegistryBuilder({} as never, { lifecycle: undefined } as never),
		).toThrow("redisSessionRPRegistryBuilder: 'client' option is required");
	});

	it("succeeds when 'client' is present", () => {
		const adapter = redisSessionRPRegistryBuilder(
			{ client: noopRPRegistryClient } as never,
			{ lifecycle: undefined } as never,
		) as { kind: string };
		expect(adapter).toBeDefined();
		expect(adapter.kind).toBe("redis");
	});
});

describe("redisUserSessionStoreBuilder — client guard", () => {
	it("throws when 'client' option is missing (config = {})", () => {
		expect(() =>
			redisUserSessionStoreBuilder({} as never, { lifecycle: undefined } as never),
		).toThrow("redisUserSessionStoreBuilder: 'client' option is required");
	});

	it("succeeds when 'client' is present", () => {
		const adapter = redisUserSessionStoreBuilder(
			{ client: noopUserSessionStoreClient } as never,
			{ lifecycle: undefined } as never,
		) as { kind: string };
		expect(adapter).toBeDefined();
		expect(adapter.kind).toBe("redis");
	});
});

// The Redis DeviceCodeStore builder: the same guard, so a missing `client` is
// named at boot, not at the first device poll.

const noopDeviceCodeStoreClient: DeviceCodeStoreClient = {
	create: async () => true,
	findPending: async () => null,
	decide: async () => ({ kind: "not_found" }),
	poll: async () => ({ kind: "not_found" }),
	remove: async () => {},
};

describe("redisDeviceCodeStoreBuilder — client guard", () => {
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

// The Redis consent store builders: the same guard, so a missing `client` is
// named at boot, not at the first `/authorize` for a client that is not
// first-party.

const noopConsentStoreClient: ConsentStoreClient = {
	find: async () => null,
	grant: async () => {},
	revoke: async () => false,
};

const noopPendingConsentStoreClient: PendingConsentStoreClient = {
	set: async () => {},
	get: async () => null,
	consume: async () => null,
	discard: async () => false,
};

describe("redisConsentStoreBuilder / redisPendingConsentStoreBuilder — client guard", () => {
	it("throws when 'client' option is missing (config = {})", () => {
		expect(() => redisConsentStoreBuilder({} as never, { lifecycle: undefined } as never)).toThrow(
			"redisConsentStoreBuilder: 'client' option is required",
		);
		expect(() =>
			redisPendingConsentStoreBuilder({} as never, { lifecycle: undefined } as never),
		).toThrow("redisPendingConsentStoreBuilder: 'client' option is required");
	});

	it("succeeds when 'client' is present", async () => {
		const consent = await redisConsentStoreBuilder(
			{ client: noopConsentStoreClient } as never,
			{ lifecycle: undefined } as never,
		);
		const pending = await redisPendingConsentStoreBuilder(
			{ client: noopPendingConsentStoreClient } as never,
			{ lifecycle: undefined } as never,
		);
		expect(consent.kind).toBe("redis");
		expect(pending.kind).toBe("redis");
	});
});
