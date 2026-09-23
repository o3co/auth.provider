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

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { replicaUnsafeReason } from "#/boot/replica-safety.mjs";
import {
	createFederationGrantStoreFactory,
	registerBuiltinFederationGrantStores,
} from "#/federation-grants/factory.mjs";
import {
	createMemoryFederationGrantStore,
	DEFAULT_FEDERATION_GRANT_TOMBSTONE_RETENTION_MS,
	MEMORY_FEDERATION_GRANT_STORE_SWEEP_FLOOR,
	type MemoryFederationGrantStore,
} from "#/federation-grants/memory.mjs";
import { memoryFederationGrantStoreModule } from "#/federation-grants/module.mjs";
import type { Logger } from "#/logging/Logger.mjs";
import { runFederationGrantStoreContract } from "./store.contract.mjs";

runFederationGrantStoreContract<MemoryFederationGrantStore>("memory", {
	create: async () => createMemoryFederationGrantStore(),
	credentialResident: async (store, grantId) => store.holdsCredential(grantId),
});

const MIN = 60_000;
const DAY = 86_400_000;
const T0 = new Date("2026-09-18T00:00:00.000Z");
const at = (ms: number): Date => new Date(T0.getTime() + ms);
const SCOPES = ["openid", "offline_access"];

const lodge = (store: MemoryFederationGrantStore, id: string, now = T0) =>
	store.createPending({
		id,
		subject: "u-1",
		clientId: "agent",
		connection: "okta-calendar",
		intent: { handle: `h-${id}`, expiresAt: new Date(now.getTime() + 10 * MIN) },
		now,
	});

const activate = (store: MemoryFederationGrantStore, id: string) =>
	store.activate({
		grantId: id,
		intentHandle: `h-${id}`,
		authorization: {
			identityRevision: "identity-1",
			authorizationRevision: "authorization-1",
			upstream: { issuer: "https://dev-1.okta.test", subject: "00u-alice" },
			scopes: SCOPES,
			consent: { at: at(MIN), sid: "sid-1", scopes: SCOPES },
			authorizedAt: at(2 * MIN),
			expiresAt: at(30 * DAY),
			resource: undefined,
		},
		credentials: { refreshToken: "rt-1", accessToken: undefined },
		now: at(2 * MIN),
	});

describe("createMemoryFederationGrantStore (#593, D16)", () => {
	// The adapter's own clock is what it reclaims on. Only `Date` is faked: the
	// lock in the contract suite above waits on real timers.
	beforeEach(() => {
		vi.useFakeTimers({ toFake: ["Date"] });
		vi.setSystemTime(T0);
	});

	afterEach(() => {
		vi.useRealTimers();
	});

	it("retains a record for thirty days past its expiry by default", () => {
		expect(DEFAULT_FEDERATION_GRANT_TOMBSTONE_RETENTION_MS).toBe(30 * DAY);
	});

	it("reclaims on its own clock, and not on a caller's: a `now` that is ahead is told nothing, and takes nothing", async () => {
		const store = createMemoryFederationGrantStore({ tombstoneRetentionMs: DAY });
		await lodge(store, "g-lapses");
		await lodge(store, "g-expires");
		await activate(store, "g-expires");

		expect(await store.find("g-lapses", at(10 * MIN))).toBeNull();
		expect(await store.find("g-expires", at(31 * DAY))).toBeNull();
		expect(await store.listBySubject("u-1", at(31 * DAY))).toEqual([]);
		expect(store.size).toBe(2);
		expect(store.holdsCredential("g-expires")).toBe(true);
		expect(await store.find("g-lapses", at(MIN))).not.toBeNull();
	});

	it("reclaims what nothing can read any more, once its own clock says so", async () => {
		const store = createMemoryFederationGrantStore({ tombstoneRetentionMs: DAY });
		await lodge(store, "g-lapses");
		await lodge(store, "g-expires");
		await activate(store, "g-expires");
		await lodge(store, "g-revoked-pending");
		await store.revoke("g-revoked-pending", "client", at(MIN));
		expect(store.size).toBe(3);

		// The first intent lapsed: its pending grant is gone, and reclaimed.
		vi.setSystemTime(at(10 * MIN));
		expect(await store.find("g-lapses", at(10 * MIN))).toBeNull();
		expect(store.size).toBe(2);

		// Revoked while pending: retained from the revocation, since it has no expiry.
		vi.setSystemTime(at(MIN + DAY - 1));
		expect(await store.find("g-revoked-pending", at(MIN + DAY - 1))).not.toBeNull();
		vi.setSystemTime(at(MIN + DAY));
		expect(await store.find("g-revoked-pending", at(MIN + DAY))).toBeNull();
		expect(store.size).toBe(1);

		// Authorized: retained from the stored expiry.
		vi.setSystemTime(at(31 * DAY - 1));
		expect(await store.find("g-expires", at(31 * DAY - 1))).not.toBeNull();
		vi.setSystemTime(at(31 * DAY));
		expect(await store.find("g-expires", at(31 * DAY))).toBeNull();
		expect(store.size).toBe(0);
	});

	it("reclaims on a listing too", async () => {
		const store = createMemoryFederationGrantStore({ tombstoneRetentionMs: DAY });
		for (const id of ["g-1", "g-2", "g-3"]) await lodge(store, id);
		vi.setSystemTime(at(10 * MIN));
		expect(await store.listBySubject("u-1", at(10 * MIN))).toEqual([]);
		expect(store.size).toBe(0);
	});

	it("retains an authorized grant from its expiry, whenever it was revoked: a revocation moves no horizon", async () => {
		// What a store with key TTLs does without being asked: the horizon is set
		// when the expiry is, and a later transition leaves it alone.
		const store = createMemoryFederationGrantStore({ tombstoneRetentionMs: DAY });
		for (const id of ["g-early", "g-late"]) {
			await lodge(store, id);
			await activate(store, id);
		}
		await store.revoke("g-early", "subject", at(2 * DAY));
		await store.revoke("g-late", "subject", at(30 * DAY + DAY / 2));
		for (const id of ["g-early", "g-late"]) {
			expect(await store.find(id, at(31 * DAY - 1)), id).toMatchObject({ status: "revoked" });
			expect(await store.find(id, at(31 * DAY)), id).toBeNull();
		}
	});

	it("writes nothing to a record its caller could not read: a guarded write judges on `now` as a read does", async () => {
		const store = createMemoryFederationGrantStore({ tombstoneRetentionMs: 0 });
		await lodge(store, "g-1");
		await activate(store, "g-1");
		await store.nameIntent({
			grantId: "g-1",
			intent: { handle: "h-re", expiresAt: at(31 * DAY) },
			now: at(DAY),
		});

		const gone = at(30 * DAY);
		expect(await store.find("g-1", gone)).toBeNull();
		expect(
			await store.requireReauthorization({ grantId: "g-1", expectedVersion: 2, now: gone }),
		).toEqual({ ok: false });
		await store.touch("g-1", gone);
		expect(await store.retireIntent({ grantId: "g-1", now: gone })).toEqual({ ok: false });

		const still = await store.find("g-1", at(DAY));
		expect(still).toMatchObject({ status: "active", version: 2 });
		// Named, and never set (#626).
		expect(still).toHaveProperty("lastUsedAt", undefined);
		expect(await store.isCurrentIntent("g-1", "h-re", at(DAY))).toBe(true);
	});

	it("sweeps what has lapsed when it lodges a new grant, so abandoned connects do not pile up unread", async () => {
		// A connect the user never finishes leaves a pending record nobody reads
		// again, under an ID nobody lodges again. Reclaiming on touch alone would
		// keep every one of them; so would a listing nobody asks for.
		const store = createMemoryFederationGrantStore();
		for (let i = 0; i < MEMORY_FEDERATION_GRANT_STORE_SWEEP_FLOOR; i++) {
			await lodge(store, `g-abandoned-${i}`);
		}
		expect(store.size).toBe(MEMORY_FEDERATION_GRANT_STORE_SWEEP_FLOOR);

		vi.setSystemTime(at(11 * MIN));
		await lodge(store, "g-next", at(11 * MIN));
		expect(store.size).toBe(1);
	});

	it("takes nothing that is still live when it sweeps", async () => {
		const store = createMemoryFederationGrantStore();
		for (let i = 0; i < MEMORY_FEDERATION_GRANT_STORE_SWEEP_FLOOR + 10; i++) {
			await lodge(store, `g-live-${i}`);
		}
		expect(store.size).toBe(MEMORY_FEDERATION_GRANT_STORE_SWEEP_FLOOR + 10);
	});

	it("drops an expired credential whatever touches the record: a secret gets no retention", async () => {
		const store = createMemoryFederationGrantStore();
		for (const id of ["g-found", "g-listed"]) {
			await lodge(store, id);
			await activate(store, id);
		}

		// Neither of these opens a credential, and each leaves the record in place.
		vi.setSystemTime(at(30 * DAY));
		await store.find("g-found", at(30 * DAY));
		expect(store.holdsCredential("g-found")).toBe(false);
		expect(store.holdsCredential("g-listed")).toBe(true);
		await store.listBySubject("u-1", at(30 * DAY));
		expect(store.holdsCredential("g-listed")).toBe(false);
		expect(store.size).toBe(2);
	});

	it("drops expired credentials in the sweep too, for records nobody touches", async () => {
		const store = createMemoryFederationGrantStore();
		await lodge(store, "g-untouched");
		await activate(store, "g-untouched");

		vi.setSystemTime(at(30 * DAY));
		for (let i = 0; i < MEMORY_FEDERATION_GRANT_STORE_SWEEP_FLOOR; i++) {
			await lodge(store, `g-filler-${i}`, at(30 * DAY));
		}
		// The record is inside its retention; its secret is not.
		expect(store.holdsCredential("g-untouched")).toBe(false);
		expect(await store.find("g-untouched", at(30 * DAY))).not.toBeNull();
	});

	it("frees an ID once its record is reclaimed, and not before: a caller whose clock is ahead cannot take a resident record's ID", async () => {
		const store = createMemoryFederationGrantStore();
		await lodge(store, "g-1");
		expect((await lodge(store, "g-1", at(10 * MIN))).ok).toBe(false);
		expect((await store.find("g-1", at(MIN)))?.status).toBe("pending");

		vi.setSystemTime(at(10 * MIN));
		expect((await lodge(store, "g-1", at(10 * MIN))).ok).toBe(true);
	});

	it("refuses a retention that is not a non-negative finite number", () => {
		for (const bad of [-1, Number.NaN, Number.POSITIVE_INFINITY]) {
			expect(() => createMemoryFederationGrantStore({ tombstoneRetentionMs: bad })).toThrow(
				RangeError,
			);
		}
	});

	it("hands every failed write its own result: one caller's object is not another's", async () => {
		const store = createMemoryFederationGrantStore();
		const first = await store.revoke("g-unknown", "client", T0);
		(first as { ok: boolean }).ok = true;
		expect(await store.revoke("g-unknown", "client", T0)).toEqual({ ok: false });
		expect(await createMemoryFederationGrantStore().revoke("g-unknown", "client", T0)).toEqual({
			ok: false,
		});
	});
});

describe("the FederationGrantStore factory (#593)", () => {
	it("builds the memory adapter by name, and says what it is good for", async () => {
		const warn = vi.fn();
		const logger: Logger = {
			trace: vi.fn(),
			debug: vi.fn(),
			info: vi.fn(),
			warn,
			error: vi.fn(),
			fatal: vi.fn(),
			child: () => logger,
		};
		const factory = createFederationGrantStoreFactory();
		registerBuiltinFederationGrantStores(factory, logger);
		expect(warn).not.toHaveBeenCalled();

		expect((await factory.create({ type: "memory" })).kind).toBe("memory");
		expect(warn).toHaveBeenCalledTimes(1);
		expect(warn.mock.calls[0]?.[0]).toMatch(/dev\/test only/);
	});
});

describe("memoryFederationGrantStoreModule (#593)", () => {
	it("provides the slot and declares why it forks per replica", () => {
		expect(memoryFederationGrantStoreModule.name).toBe("core-federation-grant-store-memory");
		expect(Object.keys(memoryFederationGrantStoreModule.provides ?? {})).toEqual([
			"federationGrantStore",
		]);
		expect(replicaUnsafeReason(memoryFederationGrantStoreModule)).toMatch(/fork/);
	});
});
