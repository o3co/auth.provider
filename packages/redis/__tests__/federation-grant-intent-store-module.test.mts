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

// What turns configuration into a Redis intent store (#593, D16, slice 6).

import { describe, expect, it } from "vitest";
import type { FederationGrantIntentStoreClient } from "../src/clients.mjs";
import {
	redisFederationGrantIntentStoreModule,
	resolveRedisFederationGrantIntentStoreOptions,
} from "../src/federation-grant-intent-store.mjs";

const client = {} as FederationGrantIntentStoreClient;

describe("the Redis federation grant intent store module (#593, slice 6)", () => {
	it("needs the client and the configuration, and says which slot it fills", () => {
		expect(redisFederationGrantIntentStoreModule.name).toBe("redis-federation-grant-intent-store");
		expect(redisFederationGrantIntentStoreModule.requires).toStrictEqual([
			"federationGrantIntentStoreClient",
			"config",
		]);
		expect(Object.keys(redisFederationGrantIntentStoreModule.provides ?? {})).toStrictEqual([
			"federationGrantIntentStore",
		]);
	});

	it("reads the grant store's key prefix, so the two namespaces move together", () => {
		// D16 puts both under one prefix; a deployment that changed it must not
		// find acquisition's records left in the old one.
		expect(
			resolveRedisFederationGrantIntentStoreOptions({
				redisFederationGrantStore: { keyPrefix: "tenant-a:fg:" },
			}),
		).toStrictEqual({ keyPrefix: "tenant-a:fg:" });
		expect(resolveRedisFederationGrantIntentStoreOptions({})).toStrictEqual({ keyPrefix: "fg:" });
	});

	it("builds a redis store, and refuses a prefix that would break the shared slot", () => {
		const provide = redisFederationGrantIntentStoreModule.provides?.federationGrantIntentStore as (
			deps: unknown,
		) => { kind: string };
		expect(provide({ federationGrantIntentStoreClient: client, config: {} }).kind).toBe("redis");
		expect(() =>
			provide({
				federationGrantIntentStoreClient: client,
				config: { redisFederationGrantStore: { keyPrefix: "fg{x}:" } },
			}),
		).toThrow(/brace/);
	});
});
