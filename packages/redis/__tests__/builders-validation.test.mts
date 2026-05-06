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
import type { ChallengeStoreClient, ReplaySeenSetClient } from "../src/clients.mjs";
import { redisReplaySeenSetBuilder } from "../src/replay-seen-set.mjs";

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
