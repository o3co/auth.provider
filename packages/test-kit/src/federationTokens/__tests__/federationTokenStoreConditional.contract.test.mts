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
 * `FederationTokenStore`'s binding run over core's in-process store, and the
 * proof that its own cases are not vacuous: core's store with one fault each,
 * refused by the case that names it. The generic cases' broken stores are the
 * generic suite's own tests'.
 */

import {
	createFederationTokenStoreFactory,
	type FederationTokenStore,
	type FederationTokens,
	type Logger,
	newStoreGeneration,
	registerBuiltinFederationTokenStores,
} from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import {
	type FederationTokenStoreConditionalHarness,
	federationTokenStoreConditionalContract,
} from "#/index.mjs";

const quiet: Logger = {
	trace() {},
	debug() {},
	info() {},
	warn() {},
	error() {},
	fatal() {},
	child: () => quiet,
};

/** Core's in-process store, through its public factory. */
async function createInMemoryFederationTokenStore(): Promise<FederationTokenStore> {
	const factory = createFederationTokenStoreFactory();
	registerBuiltinFederationTokenStores(factory, quiet);
	return factory.create({ type: "memory" });
}

describe("federationTokenStoreConditionalContract over core's in-process store", () => {
	for (const contractCase of federationTokenStoreConditionalContract({
		build: async () => ({ store: await createInMemoryFederationTokenStore() }),
	})) {
		it(contractCase.name, contractCase.run);
	}
});

/** The names of the cases that refuse the store `make` builds, one per case. */
async function refusedBy(make: () => Promise<FederationTokenStore>): Promise<string[]> {
	const refused: string[] = [];
	const build = async (): Promise<FederationTokenStoreConditionalHarness> => ({
		store: await make(),
	});
	for (const contractCase of federationTokenStoreConditionalContract({ build })) {
		try {
			await contractCase.run();
		} catch {
			refused.push(contractCase.name);
		}
	}
	return refused;
}

const CASE = {
	agree: "get and getVersioned answer the same record",
	fence:
		"a replace or a removal of one record leaves the session's other federations and other sessions' records at their generations",
	logout: "removeBySid ends every federation of the session and no other session's record",
	restore:
		"after removeBySid, a replace at a generation read before it answers missing and restores nothing",
	undated:
		"a record with no obtainedAt is read back with the key named, as undefined, through every read and write",
	wholeRecord: "a created record is read back whole, at a well-formed generation",
} as const;

/** Core's store, with every record it answers passed through `answer`. */
async function answering(
	answer: (tokens: FederationTokens) => FederationTokens,
): Promise<FederationTokenStore> {
	const store = await createInMemoryFederationTokenStore();
	return {
		...store,
		get: async (sid, name) => {
			const read = await store.get(sid, name);
			return read === null ? null : answer(read);
		},
		getVersioned: async (sid, name) => {
			const read = await store.getVersioned(sid, name);
			return read === null ? null : { value: answer(read.value), generation: read.generation };
		},
	};
}

describe("federationTokenStoreConditionalContract refuses a broken store", () => {
	it("passes core's store, with every case's name listed", async () => {
		expect(await refusedBy(createInMemoryFederationTokenStore)).toEqual([]);
		const names = federationTokenStoreConditionalContract({
			build: async () => ({ store: await createInMemoryFederationTokenStore() }),
		}).map((c) => c.name);
		expect(names).toEqual(expect.arrayContaining(Object.values(CASE)));
		expect(names).toContain("not run: the expiry case (supports.forceExpire not declared)");
		expect(names).toContain("not run: the outage case (supports.unreachable not declared)");
		expect(names.some((name) => name.startsWith("every unconditional write"))).toBe(true);
	});

	it("refuses every case of a store without the conditional members", async () => {
		const withoutMembers = async () => {
			const {
				getVersioned: _g,
				replaceIf: _r,
				removeIf: _d,
				...rest
			} = await createInMemoryFederationTokenStore();
			return rest as unknown as FederationTokenStore;
		};
		const cases = federationTokenStoreConditionalContract({
			build: async () => ({ store: await withoutMembers() }),
		}).filter((c) => !c.name.startsWith("not run:"));
		expect((await refusedBy(withoutMembers)).sort()).toEqual(cases.map((c) => c.name).sort());
	});

	it("refuses a get that answers another record than getVersioned", async () => {
		const refused = await refusedBy(async () => {
			const store = await createInMemoryFederationTokenStore();
			return {
				...store,
				get: async (sid, name) => {
					const read = await store.get(sid, name);
					return read === null ? null : { ...read, scope: "stale" };
				},
			};
		});
		expect(refused).toContain(CASE.agree);
	});

	it("refuses a replace that moves the generation of the session's other federations", async () => {
		const refused = await refusedBy(async () => {
			const store = await createInMemoryFederationTokenStore();
			return {
				...store,
				replaceIf: async (sid, name, expected, tokens) => {
					const answer = await store.replaceIf(sid, name, expected, tokens);
					if (answer.outcome === "updated") {
						const sibling = await store.getVersioned(sid, `${name}-other`);
						if (sibling !== null) await store.attach(sid, `${name}-other`, sibling.value);
					}
					return answer;
				},
			};
		});
		expect(refused).toContain(CASE.fence);
	});

	it("refuses a removeBySid that leaves a federation of the session, or removes another session's", async () => {
		const leaves = await refusedBy(async () => {
			const store = await createInMemoryFederationTokenStore();
			return {
				...store,
				removeBySid: async (sid) => store.delete(sid, "conditional"),
			};
		});
		expect(leaves).toContain(CASE.logout);
		const sids: string[] = [];
		const reaches = await refusedBy(async () => {
			const store = await createInMemoryFederationTokenStore();
			return {
				...store,
				attach: async (sid, name, tokens) => {
					sids.push(sid);
					await store.attach(sid, name, tokens);
				},
				removeBySid: async () => {
					for (const sid of sids) await store.removeBySid(sid);
				},
			};
		});
		expect(reaches).toContain(CASE.logout);
	});

	it("refuses a replace that restores a record a logout removed", async () => {
		const refused = await refusedBy(async () => {
			const store = await createInMemoryFederationTokenStore();
			return {
				...store,
				replaceIf: async (sid, name, expected, tokens) => {
					const answer = await store.replaceIf(sid, name, expected, tokens);
					if (answer.outcome !== "missing") return answer;
					await store.attach(sid, name, tokens);
					return { outcome: "updated", generation: newStoreGeneration() };
				},
			};
		});
		expect(refused).toContain(CASE.restore);
	});

	it("refuses a store that drops obtainedAt", async () => {
		const refused = await refusedBy(() =>
			answering(({ obtainedAt: _dropped, ...rest }) => rest as FederationTokens),
		);
		expect(refused).toContain(CASE.wholeRecord);
		expect(refused).toContain(CASE.undated);
	});

	it("refuses a store that leaves an unset obtainedAt out, or answers it as null", async () => {
		const leavesOut = await refusedBy(() =>
			answering((tokens) => {
				if (tokens.obtainedAt !== undefined) return tokens;
				const { obtainedAt: _unset, ...rest } = tokens;
				return rest as FederationTokens;
			}),
		);
		expect(leavesOut).toEqual([CASE.undated]);
		const answersNull = await refusedBy(() =>
			answering((tokens) =>
				tokens.obtainedAt === undefined
					? ({ ...tokens, obtainedAt: null } as unknown as FederationTokens)
					: tokens,
			),
		);
		expect(answersNull).toEqual([CASE.undated]);
	});
});
