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
import { replicaUnsafeReason } from "#/boot/replica-safety.mjs";
import { memoryFederationGrantStoreModule } from "#/federation-grants/module.mjs";

/** The module's own section, `core-federation-grant-store-memory`, parsed with its schema. */
const parse = (section: unknown): { tombstoneRetention?: number } | undefined => {
	const schema = memoryFederationGrantStoreModule.section?.schema;
	if (schema === undefined) throw new Error("the module declares no section");
	return schema.parse(section) as { tombstoneRetention?: number } | undefined;
};

describe("memoryFederationGrantStoreModule", () => {
	it("declares itself unsafe to run on more than one replica, and says what forks", () => {
		expect(memoryFederationGrantStoreModule.replicaSafety).toMatchObject({ unsafe: true });
		expect(replicaUnsafeReason(memoryFederationGrantStoreModule)).toMatch(/fork per replica/);
	});

	it("reads the retention an operator wrote at its own section, in seconds", () => {
		expect(memoryFederationGrantStoreModule.section).not.toHaveProperty("at");
		expect(memoryFederationGrantStoreModule).not.toHaveProperty("configSchema");
		expect(parse({ tombstoneRetention: 60 })?.tombstoneRetention).toBe(60);
		expect(parse({ tombstoneRetention: "60" })?.tombstoneRetention).toBe(60);
		// Zero is a deployment that wants no tombstones, and says so.
		expect(parse({ tombstoneRetention: 0 })?.tombstoneRetention).toBe(0);
	});

	it("refuses a retention that is not a duration, or past a year, rather than reading it as zero, and a key it does not declare", () => {
		for (const tombstoneRetention of [null, true, [], "", "1e3", "thirty", -1, 1.5, 31_536_001]) {
			expect(() => parse({ tombstoneRetention }), JSON.stringify(tombstoneRetention)).toThrow(
				"must be a whole number from 0 to 31536000, in decimal digits",
			);
		}
		expect(() => parse({ tombstone: 60 })).toThrow();
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
