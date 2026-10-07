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
 * `FederationTokenStore`'s binding of the record-scoped conditional-write
 * contract: one `(sid, federationName)` record and its store generation,
 * held to `conditionalRecordContract` through `getVersioned`, `replaceIf`
 * and `removeIf`, with `attach` as the create path and `attach`, `delete` and
 * `removeBySid` as the unconditional writes, the last two removals. The cases of the port's own add that a record's generation
 * fences that record alone: another federation of the session, and another
 * session's record of the federation, are left as they were.
 *
 * Each case builds its own harness and closes it. A case's key is the
 * record's sid, under one federation name, so a session's removal reaches
 * that case's record alone.
 */

import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import {
	type FederationTokenStore,
	type FederationTokens,
	readConditionalRemoveAnswer,
	readConditionalReplaceAnswer,
	readVersioned,
	type Versioned,
} from "@o3co/auth-provider-core";
import {
	type ConditionalRecordHarness,
	type ConditionalRecordTarget,
	conditionalRecordContract,
} from "../conditionalWrite/conditionalWrite.contract.mjs";
import type { ContractCase } from "../contractCase.mjs";

/** What one case runs over. */
export interface FederationTokenStoreConditionalHarness {
	readonly store: FederationTokenStore;
	/**
	 * The same backend through a second instance: another connection, pool or
	 * client. Absent: `store` again, with no cross-process proof.
	 */
	readonly second?: FederationTokenStore;
	/**
	 * Moves the backend's clock past the retention deadline the store set for
	 * the record of `(sid, federationName)`. It never judges what expires, and
	 * never deletes.
	 */
	readonly forceExpire?: (sid: string, federationName: string) => Promise<void>;
	/** A store over the same backend that cannot reach it. */
	readonly unreachable?: () => FederationTokenStore;
	readonly close?: () => Promise<void>;
}

export interface FederationTokenStoreConditionalContractInput {
	readonly build: () => Promise<FederationTokenStoreConditionalHarness>;
	/**
	 * The hooks every harness `build` answers, declared up front, so the case
	 * list is fixed when the suite is built. A declared hook that a harness
	 * lacks fails its case; an undeclared one runs no case, and one passing
	 * case names what was not run.
	 */
	readonly supports?: {
		readonly forceExpire?: boolean;
		readonly unreachable?: boolean;
	};
}

/** The federation name every case's record is kept under; the case's key is its sid. */
const NAME = "conditional";

/** Another federation name, for the records a case must leave alone. */
const OTHER_NAME = "conditional-other";

/** Two distinct records, every key named, built fresh on every call. */
const values = (): readonly [FederationTokens, FederationTokens] => [
	{
		accessToken: "at-one",
		refreshToken: "rt-one",
		idToken: "id-one",
		expiresAt: new Date("2026-10-02T01:00:00.000Z"),
		tokenType: "Bearer",
		scope: "openid email",
		grantedScope: "openid email profile",
		obtainedAt: new Date("2026-10-02T00:00:00.000Z"),
	},
	{
		accessToken: "at-two",
		refreshToken: undefined,
		idToken: undefined,
		expiresAt: null,
		tokenType: undefined,
		scope: undefined,
		grantedScope: undefined,
		obtainedAt: new Date("2026-10-02T00:30:00.000Z"),
	},
];

/** Mutates each `Date` of a record in place: the store must have kept its own copy. */
const mutate = (value: FederationTokens): void => {
	value.expiresAt?.setTime(0);
	value.obtainedAt?.setTime(0);
};

/** The port's record of `(key, NAME)` as the generic suite's target. */
const targetOf = (store: FederationTokenStore): ConditionalRecordTarget<FederationTokens> => ({
	put: (key, value) => store.attach(key, NAME, value),
	getVersioned: (key) => store.getVersioned(key, NAME),
	replaceIf: (key, expected, value) => store.replaceIf(key, NAME, expected, value),
	removeIf: (key, expected) => store.removeIf(key, NAME, expected),
	unconditional: {
		attach: (key, value) => store.attach(key, NAME, value),
		delete: (key) => store.delete(key, NAME),
		removeBySid: (key) => store.removeBySid(key),
	},
});

/** The unconditional writes that end the record. */
const REMOVALS = ["delete", "removeBySid"] as const;

/** A sid no other case uses, on a backend cases may share. */
const freshSid = (label: string): string => `ft-${label}-${randomUUID()}`;

/** The live record of `(sid, name)`, read through core's reader. */
async function live(
	store: FederationTokenStore,
	sid: string,
	name: string,
): Promise<Versioned<FederationTokens>> {
	const read = readVersioned(await store.getVersioned(sid, name));
	assert.notEqual(read, null, `${sid}/${name} is live`);
	return read as Versioned<FederationTokens>;
}

/** The cases of `FederationTokenStore`'s conditional writes over the harnesses `input` builds. */
export function federationTokenStoreConditionalContract(
	input: FederationTokenStoreConditionalContractInput,
): readonly ContractCase[] {
	const generic = conditionalRecordContract<FederationTokens>({
		build: async (): Promise<ConditionalRecordHarness<FederationTokens>> => {
			const harness = await input.build();
			const { second, forceExpire, unreachable, close } = harness;
			return {
				store: targetOf(harness.store),
				...(second === undefined ? {} : { second: targetOf(second) }),
				...(forceExpire === undefined ? {} : { forceExpire: (key) => forceExpire(key, NAME) }),
				...(unreachable === undefined ? {} : { unreachable: () => targetOf(unreachable()) }),
				...(close === undefined ? {} : { close }),
			};
		},
		values,
		mutate,
		removals: REMOVALS,
		supports: {
			unconditional: true,
			...(input.supports?.forceExpire === true ? { forceExpire: true } : {}),
			...(input.supports?.unreachable === true ? { unreachable: true } : {}),
		},
	});

	const test = (
		name: string,
		body: (harness: FederationTokenStoreConditionalHarness) => Promise<void>,
	): ContractCase => ({
		name,
		run: async () => {
			const harness = await input.build();
			try {
				await body(harness);
			} finally {
				await harness.close?.();
			}
		},
	});

	const own: ContractCase[] = [
		test("get and getVersioned answer the same record", async ({ store }) => {
			const sid = freshSid("agree");
			assert.equal(await store.get(sid, NAME), null);
			assert.equal(readVersioned(await store.getVersioned(sid, NAME)), null);
			await store.attach(sid, NAME, values()[0]);
			assert.deepStrictEqual(await store.get(sid, NAME), (await live(store, sid, NAME)).value);
		}),

		test("a replace or a removal of one record leaves the session's other federations and other sessions' records at their generations", async ({
			store,
		}) => {
			const sid = freshSid("fence");
			const otherSid = freshSid("fence-other");
			await store.attach(sid, NAME, values()[0]);
			await store.attach(sid, OTHER_NAME, values()[0]);
			await store.attach(otherSid, NAME, values()[0]);
			const sibling = await live(store, sid, OTHER_NAME);
			const elsewhere = await live(store, otherSid, NAME);
			const read = await live(store, sid, NAME);
			const replaced = readConditionalReplaceAnswer(
				await store.replaceIf(sid, NAME, read.generation, values()[1]),
			);
			assert.ok(replaced.outcome === "updated");
			assert.deepStrictEqual(await live(store, sid, OTHER_NAME), sibling);
			assert.deepStrictEqual(await live(store, otherSid, NAME), elsewhere);
			assert.equal(
				readConditionalRemoveAnswer(await store.removeIf(sid, NAME, replaced.generation)).outcome,
				"removed",
			);
			assert.deepStrictEqual(await live(store, sid, OTHER_NAME), sibling);
			assert.deepStrictEqual(await live(store, otherSid, NAME), elsewhere);
			// A generation fences its own record: another record's answers conflict there.
			assert.equal(
				readConditionalReplaceAnswer(
					await store.replaceIf(otherSid, NAME, sibling.generation, values()[1]),
				).outcome,
				"conflict",
			);
		}),

		test("a record with no obtainedAt is read back with the key named, as undefined, through every read and write", async ({
			store,
		}) => {
			const sid = freshSid("undated");
			const undated: FederationTokens = { ...values()[0], obtainedAt: undefined };
			const named = (read: FederationTokens | null | undefined, where: string): void => {
				assert.ok(
					read !== null && read !== undefined && Object.hasOwn(read, "obtainedAt"),
					`${where}: obtainedAt is named`,
				);
				assert.deepStrictEqual(read, undated, `${where}: obtainedAt is undefined, never null`);
			};
			await store.attach(sid, NAME, undated);
			named(await store.get(sid, NAME), "get after attach");
			const read = await live(store, sid, NAME);
			named(read.value, "getVersioned after attach");
			const dated = readConditionalReplaceAnswer(
				await store.replaceIf(sid, NAME, read.generation, values()[0]),
			);
			assert.ok(dated.outcome === "updated");
			const undatedAgain = readConditionalReplaceAnswer(
				await store.replaceIf(sid, NAME, dated.generation, undated),
			);
			assert.ok(undatedAgain.outcome === "updated");
			named(await store.get(sid, NAME), "get after replaceIf");
			named((await live(store, sid, NAME)).value, "getVersioned after replaceIf");
		}),

		test("removeBySid ends every federation of the session and no other session's record", async ({
			store,
		}) => {
			const sid = freshSid("logout");
			const otherSid = freshSid("logout-other");
			await store.attach(sid, NAME, values()[0]);
			await store.attach(sid, OTHER_NAME, values()[1]);
			await store.attach(otherSid, NAME, values()[0]);
			const elsewhere = await live(store, otherSid, NAME);
			await store.removeBySid(sid);
			assert.equal(readVersioned(await store.getVersioned(sid, NAME)), null);
			assert.equal(readVersioned(await store.getVersioned(sid, OTHER_NAME)), null);
			assert.deepStrictEqual(await live(store, otherSid, NAME), elsewhere);
		}),

		test("after removeBySid, a replace at a generation read before it answers missing and restores nothing", async ({
			store,
		}) => {
			const sid = freshSid("restore");
			await store.attach(sid, NAME, values()[0]);
			const read = await live(store, sid, NAME);
			await store.removeBySid(sid);
			assert.equal(
				readConditionalReplaceAnswer(await store.replaceIf(sid, NAME, read.generation, values()[1]))
					.outcome,
				"missing",
			);
			assert.equal(await store.get(sid, NAME), null);
			assert.equal(readVersioned(await store.getVersioned(sid, NAME)), null);
		}),
	];

	return [...generic, ...own];
}
