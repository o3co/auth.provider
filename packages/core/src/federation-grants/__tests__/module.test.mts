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
 * The bundled in-memory grant store's manifest. One setting, and the one where
 * a misreading is invisible from outside: "keep no tombstones" and "keep
 * thirty days of them" look identical until somebody asks why a revoked grant
 * cannot be looked up.
 */

import { describe, expect, it } from "vitest";
import { memoryFederationGrantStoreModule } from "#/federation-grants/module.mjs";

/** The module's own section, `core-federation-grant-store-memory`, parsed with its schema. */
const parse = (section: unknown) =>
	(
		memoryFederationGrantStoreModule.section?.schema as unknown as {
			parse(value: unknown): { tombstoneRetention?: number } | undefined;
		}
	).parse(section);

describe("memoryFederationGrantStoreModule", () => {
	it("declares itself unsafe to run on more than one replica, and says what forks", () => {
		expect(memoryFederationGrantStoreModule.replicaSafety?.unsafe).toBe(true);
		expect(memoryFederationGrantStoreModule.replicaSafety?.reason).toMatch(/fork per replica/);
	});

	it("reads the retention an operator wrote at its own section, in seconds", () => {
		expect(memoryFederationGrantStoreModule.section?.at).toBeUndefined();
		expect(memoryFederationGrantStoreModule.configSchema).toBeUndefined();
		expect(parse({ tombstoneRetention: 60 })?.tombstoneRetention).toBe(60);
		expect(parse({ tombstoneRetention: "60" })?.tombstoneRetention).toBe(60);
		// Zero is a deployment that wants no tombstones, and says so.
		expect(parse({ tombstoneRetention: 0 })?.tombstoneRetention).toBe(0);
	});

	it("refuses a retention that is not a duration rather than reading it as zero, and a key it does not declare", () => {
		for (const section of [
			...[null, true, [], "1e3", "thirty", -1, 1.5].map((tombstoneRetention) => ({
				tombstoneRetention,
			})),
			{ tombstone: 60 },
		]) {
			expect(() => parse(section), JSON.stringify(section)).toThrow();
		}
	});

	it("needs no configuration at all to be installed", () => {
		expect(() => parse(undefined)).not.toThrow();
		expect(memoryFederationGrantStoreModule.requires ?? []).toEqual([]);
	});

	it("builds a store, and one with the configured retention when there is one", () => {
		const provider = memoryFederationGrantStoreModule.provides?.federationGrantStore;
		expect(typeof provider).toBe("function");
		const store = (provider as (deps: unknown) => { kind: string })({
			section: { tombstoneRetention: 60 },
		});
		expect(store.kind).toBe("memory");
		const bare = (provider as (deps: unknown) => { kind: string })({ section: undefined });
		expect(bare.kind).toBe("memory");
	});
});
