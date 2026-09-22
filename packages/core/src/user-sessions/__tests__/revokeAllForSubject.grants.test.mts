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
 * `revokeAllForSubject` reaches the subject's federation grants (#593, D13).
 *
 * The free function **always revokes**: it has no way to keep anything, and
 * that is deliberate. Keeping is offered only by the subject revocation
 * service, where an operator's allowance can be read — a boolean handed to a
 * helper by the Store would be a convention among trusted callers rather than
 * a control.
 *
 * The grant store stays **optional**, and its omission is not a newly
 * unavailable capability. Every call written before #593 omits it, and marking
 * those incomplete would turn working deployments — ones with no grants at
 * all — into failures overnight. What omission means is "no explicit grant
 * pass was asked for", and the adapter-enforced boundary is the backstop for
 * exactly that case.
 */

import { describe, expect, it, vi } from "vitest";
import { harness, now } from "#/federation-grants/__tests__/retrieve.harness.mjs";
import { createInMemorySubjectRevocation } from "#/user-sessions/memory/subjectRevocation.mjs";
import { revokeAllForSubject } from "#/user-sessions/revokeAllForSubject.mjs";

const base = () => ({
	subject: "u-1",
	watermarkTtlMs: 600_000,
	cascadeSession: async () => ({ ok: true }),
	subjectSessionIndex: {
		listSids: async () => [] as readonly string[],
		addSid: async () => undefined,
		removeSid: async () => undefined,
	} as never,
	subjectRevocation: createInMemorySubjectRevocation(),
});

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

describe("revokeAllForSubject with a grant store", () => {
	it("ends every grant the subject has, pending ones included", async () => {
		const h = harness();
		await h.seed();
		await h.seed({ id: "g-2" });
		await h.store.createPending({
			id: "g-pending",
			subject: "u-1",
			clientId: "agent",
			connection: "okta-calendar",
			intent: { handle: "h", expiresAt: new Date(now().getTime() + 600_000) },
			now: now(),
		});

		const result = await revokeAllForSubject({
			...base(),
			federationGrantStore: h.store,
			now: () => now().getTime(),
		});

		expect(result.complete).toBe(true);
		expect([...result.grantsRevoked].sort()).toEqual(["g-1", "g-2", "g-pending"]);
		for (const id of ["g-1", "g-2", "g-pending"]) {
			expect((await h.store.inspect(id, now()))?.grant.status, id).toBe("revoked");
		}
	});

	it("stamps the boundary before it lists anything", async () => {
		// A grant consented during the pass is covered by the boundary even
		// though it was not in the list. Listing first would leave it outside
		// both mechanisms, which is the same argument the sessions pass makes.
		const h = harness();
		await h.seed();
		const order: string[] = [];
		const revocation = createInMemorySubjectRevocation();
		vi.spyOn(revocation, "revokeBefore").mockImplementation(async () => {
			order.push("stamp");
		});
		vi.spyOn(h.store, "listBySubject").mockImplementation(async () => {
			order.push("list");
			return [];
		});

		await revokeAllForSubject({
			...base(),
			subjectRevocation: revocation,
			federationGrantStore: h.store,
			now: () => now().getTime(),
		});

		expect(order).toEqual(["stamp", "list"]);
	});

	it("still runs the grant pass when the stamp failed", async () => {
		const h = harness();
		await h.seed();
		const revocation = createInMemorySubjectRevocation();
		vi.spyOn(revocation, "revokeBefore").mockRejectedValue(new Error("store is down"));

		const result = await revokeAllForSubject({
			...base(),
			subjectRevocation: revocation,
			federationGrantStore: h.store,
			now: () => now().getTime(),
		});

		expect(result.complete).toBe(false);
		expect(result.grantsRevoked).toEqual(["g-1"]);
	});

	it("reports a listing outage and does not call it an empty subject", async () => {
		const h = harness();
		await h.seed();
		vi.spyOn(h.store, "listBySubject").mockRejectedValue(new Error("store is down"));

		const result = await revokeAllForSubject({
			...base(),
			federationGrantStore: h.store,
			now: () => now().getTime(),
		});

		expect(result.complete).toBe(false);
		expect(result.failures).toContainEqual(
			expect.objectContaining({ capability: "federationGrantStore", operation: "listBySubject" }),
		);
	});

	it("carries on past a grant that would not write, and names it", async () => {
		const h = harness();
		await h.seed();
		await h.seed({ id: "g-2" });
		const real = h.store.revoke.bind(h.store);
		vi.spyOn(h.store, "revoke").mockImplementation(async (id, by, at) => {
			if (id === "g-1") throw new Error("store is down");
			return real(id, by, at);
		});

		const result = await revokeAllForSubject({
			...base(),
			federationGrantStore: h.store,
			now: () => now().getTime(),
		});

		expect(result.complete).toBe(false);
		expect(result.grantsRevoked).toEqual(["g-2"]);
		expect(result.grantsFailed).toEqual(["g-1"]);
		expect(result.failures).toContainEqual(
			expect.objectContaining({ operation: "revoke", grantId: "g-1" }),
		);
	});

	it("treats a write that changed nothing as done, not as a failure", async () => {
		// Somebody else revoked it first. The grant is ended either way.
		const h = harness();
		await h.seed();
		await h.store.revoke("g-1", "operator", now());

		const result = await revokeAllForSubject({
			...base(),
			federationGrantStore: h.store,
			now: () => now().getTime(),
		});

		expect(result.complete).toBe(true);
		expect(result.grantsFailed).toEqual([]);
		// Nor is it something this call ended. It reports what it changed.
		expect(result.grantsRevoked).toEqual([]);
	});

	it("leaves a call that passed no store complete, and says the pass was not run", async () => {
		// Every call written before #593 looks like this, and the boundary the
		// stamp just wrote is the backstop for it.
		const result = await revokeAllForSubject({ ...base(), now: () => now().getTime() });
		expect(result.complete).toBe(true);
		expect(result.unavailable).toEqual([]);
		expect(result.grantsRequested).toBe(false);
	});

	it("tells the audit sink about every grant it ended", async () => {
		const h = harness();
		await h.seed();
		await h.seed({ id: "g-2" });
		const events: { type: string; grantId: string; outcome: string; correlationId: string }[] = [];

		await revokeAllForSubject({
			...base(),
			federationGrantStore: h.store,
			federationGrantAudit: (event) => {
				events.push(event as (typeof events)[number]);
			},
			correlationId: "corr-1",
			now: () => now().getTime(),
		});

		expect(events.map((event) => event.grantId).sort()).toEqual(["g-1", "g-2"]);
		for (const event of events) {
			expect(event.type).toBe("federation.grant.revoked");
			expect(event.outcome).toBe("subject");
			expect(event.correlationId).toBe("corr-1");
		}
	});

	it("gives a pass one correlation ID of its own when the caller passes none: every event of the pass carries it, and the next pass another (#618)", async () => {
		const h = harness();
		await h.seed();
		await h.seed({ id: "g-2" });
		const events: { correlationId: string }[] = [];
		const pass = () =>
			revokeAllForSubject({
				...base(),
				federationGrantStore: h.store,
				federationGrantAudit: (event) => {
					events.push(event as (typeof events)[number]);
				},
				now: () => now().getTime(),
			});

		await pass();
		expect(events).toHaveLength(2);
		const first = new Set(events.map((event) => event.correlationId));
		expect(first.size).toBe(1);
		for (const id of first) expect(id).toMatch(UUID);

		await h.seed({ id: "g-3" });
		await pass();
		expect(events).toHaveLength(3);
		expect(events[2]?.correlationId).toMatch(UUID);
		expect(first.has(events[2]?.correlationId ?? "")).toBe(false);
	});

	it("samples the clock at each write rather than once for the batch", async () => {
		// Two grants revoked in one pass are two facts that happened at two
		// instants. A batch-wide timestamp would put a write before the moment
		// it ran, and the record is what an operator reconstructs an incident
		// from.
		const h = harness();
		await h.seed();
		await h.seed({ id: "g-2" });
		let clock = now().getTime();

		await revokeAllForSubject({
			...base(),
			federationGrantStore: h.store,
			now: () => {
				clock += 1_000;
				return clock;
			},
		});

		const first = (await h.store.inspect("g-1", now()))?.grant;
		const second = (await h.store.inspect("g-2", now()))?.grant;
		const instant = (grant: unknown) =>
			(grant as { revocation: { at: Date } }).revocation.at.getTime();
		expect(instant(first)).not.toBe(instant(second));
	});

	it("revokes on the subject's behalf, which is what the backstop would have said", async () => {
		const h = harness();
		await h.seed();
		await revokeAllForSubject({
			...base(),
			federationGrantStore: h.store,
			now: () => now().getTime(),
		});
		const grant = (await h.store.inspect("g-1", now()))?.grant;
		expect((grant as { revocation: { by: string } }).revocation.by).toBe("subject");
	});
});
