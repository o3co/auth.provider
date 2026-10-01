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

// What turns configuration into a Redis intent store (ADR
// 2026-09-17-federation-grants-offline-delegation, D16).

import { describe, expect, it } from "vitest";
import type { FederationGrantIntentStoreClient } from "#/clients.mjs";
import {
	redisFederationGrantIntentStoreModule,
	resolveRedisFederationGrantIntentStoreOptions,
} from "#/federation-grant-intent-store.mjs";

const client = {} as FederationGrantIntentStoreClient;

describe("the Redis federation grant intent store module", () => {
	it("needs the client, and says which slot it fills", () => {
		expect(redisFederationGrantIntentStoreModule.name).toBe("redis-federation-grant-intent-store");
		expect(redisFederationGrantIntentStoreModule.requires).toStrictEqual([
			"federationGrantIntentStoreClient",
		]);
		expect(Object.keys(redisFederationGrantIntentStoreModule.provides ?? {})).toStrictEqual([
			"federationGrantIntentStore",
		]);
	});

	it("reads its own section's key prefix, fg: when it is not set, and refuses a key it does not declare", () => {
		expect(
			resolveRedisFederationGrantIntentStoreOptions({ keyPrefix: "tenant-a:fg:" }),
		).toStrictEqual({ keyPrefix: "tenant-a:fg:" });
		expect(resolveRedisFederationGrantIntentStoreOptions(undefined)).toStrictEqual({
			keyPrefix: "fg:",
		});
		expect(() => resolveRedisFederationGrantIntentStoreOptions({ prefix: "x:" })).toThrow();
	});

	it("builds a redis store, and refuses a prefix that would break the shared slot", () => {
		const provide = redisFederationGrantIntentStoreModule.provides?.federationGrantIntentStore as (
			deps: unknown,
		) => { kind: string };
		expect(provide({ federationGrantIntentStoreClient: client, section: undefined }).kind).toBe(
			"redis",
		);
		expect(() =>
			provide({ federationGrantIntentStoreClient: client, section: { keyPrefix: "fg{x}:" } }),
		).toThrow(/brace/);
	});
});
