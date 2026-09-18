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
import { createMemoryFederationGrantStore } from "#/federation-grants/memory.mjs";
import { requireFederationGrantSubjectRevocation } from "#/federation-grants/revocationWiring.mjs";
import type { FederationGrantStore } from "#/federation-grants/store.mjs";
import { createInMemorySubjectRevocation } from "#/user-sessions/memory/subjectRevocation.mjs";
import type { SubjectRevocation } from "#/user-sessions/types.mjs";

const durableStore = {
	...createMemoryFederationGrantStore(),
	kind: "redis",
} as FederationGrantStore;

/** The single-boundary surface #296 shipped, and nothing more. */
const olderAdapter = (): SubjectRevocation => ({
	kind: "redis",
	revokeBefore: async () => undefined,
	revokedBefore: async () => null,
});

describe("requireFederationGrantSubjectRevocation", () => {
	it("accepts an adapter that carries both boundaries", () => {
		const revocation = createInMemorySubjectRevocation();
		expect(
			requireFederationGrantSubjectRevocation({ module: "m", subjectRevocation: revocation }),
		).toBe(revocation);
	});

	it("refuses a deployment with no boundary at all", () => {
		expect(() =>
			requireFederationGrantSubjectRevocation({ module: "m", subjectRevocation: undefined }),
		).toThrow(/requires a subjectRevocation component/);
	});

	it("refuses an adapter that only carries the older single boundary", () => {
		// Absence declared through the policy is not an escape here: sessions
		// end when their cookie does, and a grant ends when nothing does.
		expect(() =>
			requireFederationGrantSubjectRevocation({ module: "m", subjectRevocation: olderAdapter() }),
		).toThrow(/grantsRevokedBefore/);
	});

	it("refuses grants that outlive the process beside a boundary that does not", () => {
		expect(() =>
			requireFederationGrantSubjectRevocation({
				module: "m",
				subjectRevocation: createInMemorySubjectRevocation(),
				federationGrantStore: durableStore,
			}),
		).toThrow(/outlive the process/);
	});

	it("accepts the bundled memory pair, which fails over together or not at all", () => {
		expect(() =>
			requireFederationGrantSubjectRevocation({
				module: "m",
				subjectRevocation: createInMemorySubjectRevocation(),
				federationGrantStore: createMemoryFederationGrantStore(),
			}),
		).not.toThrow();
	});

	it("does not judge a custom store it cannot ask about persistence", () => {
		// `kind` is all the port exposes. Anything that is not the bundled
		// memory store is treated as durable, which is the conservative
		// direction: it refuses a pairing that would lose the boundary rather
		// than admitting one it cannot prove.
		const custom = { ...createMemoryFederationGrantStore(), kind: "acme" } as FederationGrantStore;
		expect(() =>
			requireFederationGrantSubjectRevocation({
				module: "m",
				subjectRevocation: { ...createInMemorySubjectRevocation(), kind: "acme" },
				federationGrantStore: custom,
			}),
		).not.toThrow();
	});

	it("names the module that asked, so an operator knows where to look", () => {
		expect(() =>
			requireFederationGrantSubjectRevocation({
				module: "subjectRevocationServiceModule",
				subjectRevocation: undefined,
			}),
		).toThrow(/^subjectRevocationServiceModule: /);
	});
});
