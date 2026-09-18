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
 * The bundled in-memory grant store's manifest (#593, D16).
 *
 * One setting, and the one where a misreading is invisible from outside:
 * "keep no tombstones" and "keep thirty days of them" look identical until
 * somebody asks why a revoked grant cannot be looked up. Its schema used to be
 * a narrow restatement of core's section with `z.coerce.number()` in it, so
 * `tombstoneRetention: null` became `0` — Copilot's finding — and a deployment
 * that had written nothing of the sort had no tombstones at all.
 */

import { describe, expect, it } from "vitest";
import { memoryFederationGrantStoreModule } from "#/federation-grants/module.mjs";

const parse = (federationGrants: unknown) =>
	(
		memoryFederationGrantStoreModule.configSchema as unknown as {
			parse(value: unknown): { federationGrants?: { tombstoneRetention?: number } };
		}
	).parse({ federationGrants });

describe("memoryFederationGrantStoreModule", () => {
	it("declares itself unsafe to run on more than one replica, and says what forks", () => {
		expect(memoryFederationGrantStoreModule.replicaSafety?.unsafe).toBe(true);
		expect(memoryFederationGrantStoreModule.replicaSafety?.reason).toMatch(/fork per replica/);
	});

	it("reads the retention an operator wrote, in seconds", () => {
		expect(parse({ tombstoneRetention: 60 }).federationGrants?.tombstoneRetention).toBe(60);
		expect(parse({ tombstoneRetention: "60" }).federationGrants?.tombstoneRetention).toBe(60);
		// Zero is a deployment that wants no tombstones, and says so.
		expect(parse({ tombstoneRetention: 0 }).federationGrants?.tombstoneRetention).toBe(0);
	});

	it("refuses a retention that is not a duration rather than reading it as zero", () => {
		for (const tombstoneRetention of [null, true, [], "1e3", "thirty", -1, 1.5]) {
			expect(() => parse({ tombstoneRetention }), JSON.stringify(tombstoneRetention)).toThrow();
		}
	});

	it("needs no configuration at all to be installed", () => {
		expect(() => parse(undefined)).not.toThrow();
	});

	it("builds a store, and one with the configured retention when there is one", () => {
		const provider = memoryFederationGrantStoreModule.provides?.federationGrantStore;
		expect(typeof provider).toBe("function");
		const store = (provider as (deps: unknown) => { kind: string })({
			config: { federationGrants: { tombstoneRetention: 60 } },
		});
		expect(store.kind).toBe("memory");
		const bare = (provider as (deps: unknown) => { kind: string })({ config: {} });
		expect(bare.kind).toBe("memory");
	});
});
