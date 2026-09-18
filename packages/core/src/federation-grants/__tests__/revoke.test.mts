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
 * The two calls a Store makes rather than two routes this server mounts
 * (#593, D13).
 *
 * `revokeFederationGrant` is how an operator's own console ends a grant, and
 * `listFederationGrantsForSubject` is what lets a Store offer a user a
 * "connected applications" page. Without the second, a user has no direct way
 * to withdraw one at all.
 *
 * They are library calls because this provider mounts no admin route and has
 * no operator identity model to authorize one with. Authenticating the person
 * and checking that the grant they picked is theirs belongs to the Store,
 * which has both.
 */

import { describe, expect, it, vi } from "vitest";
import type { FederationGrantAuditEvent } from "#/federation-grants/retrieve.mjs";
import {
	listFederationGrantsForSubject,
	revokeFederationGrant,
} from "#/federation-grants/revoke.mjs";
import { connection, harness, now, SCOPES, SECRET } from "./retrieve.harness.mjs";

const deps = (over: Record<string, unknown> = {}) => {
	const h = harness();
	const events: FederationGrantAuditEvent[] = [];
	return {
		h,
		events,
		deps: {
			store: h.store,
			now,
			audit: (event: FederationGrantAuditEvent) => {
				events.push(event);
			},
			...over,
		},
	};
};

describe("revokeFederationGrant", () => {
	it("ends the grant and answers with what it became", async () => {
		const { h, deps: d } = deps();
		await h.seed();
		const written = await revokeFederationGrant(d as never, "g-1", "operator");
		expect(written.ok).toBe(true);
		if (written.ok) expect(written.grant.status).toBe("revoked");
	});

	it("is idempotent, and says which call changed the record", async () => {
		// The answer is the same for both; only one of them did anything, and a
		// Store retrying must not read the second as a failure.
		const { h, deps: d } = deps();
		await h.seed();
		expect((await revokeFederationGrant(d as never, "g-1", "subject")).ok).toBe(true);
		expect((await revokeFederationGrant(d as never, "g-1", "subject")).ok).toBe(false);
	});

	it("answers rather than throwing for a grant that is not there", async () => {
		const { deps: d } = deps();
		expect((await revokeFederationGrant(d as never, "never-existed", "operator")).ok).toBe(false);
	});

	it("does not read the record first, so a damaged one can still be ended", async () => {
		// A record whose credential cannot be decoded is exactly the one an
		// operator needs to end, and the Redis store deliberately allows
		// revoking it. A read in front of this would refuse the cleanup.
		const { h, deps: d } = deps();
		await h.seed();
		const find = vi.spyOn(h.store, "find");
		const open = vi.spyOn(h.store, "open");
		const inspect = vi.spyOn(h.store, "inspect");
		await revokeFederationGrant(d as never, "g-1", "operator");
		expect(find).not.toHaveBeenCalled();
		expect(open).not.toHaveBeenCalled();
		expect(inspect).not.toHaveBeenCalled();
	});

	it("surfaces a storage outage rather than reporting a revocation that did not happen", async () => {
		const { h, deps: d } = deps();
		await h.seed();
		vi.spyOn(h.store, "revoke").mockRejectedValue(new Error("store is down"));
		await expect(revokeFederationGrant(d as never, "g-1", "operator")).rejects.toThrow();
	});

	it("audits the transition it made, and nothing when it made none", async () => {
		const { h, deps: d, events } = deps();
		await h.seed();
		await revokeFederationGrant(d as never, "g-1", "subject");
		await revokeFederationGrant(d as never, "g-1", "subject");
		const revoked = events.filter((e) => e.type === "federation.grant.revoked");
		expect(revoked).toHaveLength(1);
		expect(revoked[0]?.outcome).toBe("subject");
		// Built from the record it ended, not from what the caller claimed.
		expect(revoked[0]?.grantId).toBe("g-1");
		expect(revoked[0]?.subject).toBe("u-1");
		expect(JSON.stringify(events)).not.toContain(SECRET);
	});

	it("says what access it ended, not only which grant", async () => {
		// D18 carries the upstream account, the connection, the resource and
		// the scopes where they have been established — and the record the
		// write returned is the establishment. Without them an operator
		// reading a revocation has a grant id and has to go and look up what
		// was taken away, from a record that may now be a tombstone.
		const { h, deps: d, events } = deps();
		await h.seed();
		await revokeFederationGrant(d as never, "g-1", "operator");
		const revoked = events.find((e) => e.type === "federation.grant.revoked");
		expect(revoked).toMatchObject({
			connection: connection.name,
			upstream: { issuer: connection.upstreamIssuer, subject: "00u-alice" },
			scopes: [...SCOPES],
		});
	});

	it("reports no authorization for a grant that never had one", async () => {
		// A grant revoked while `pending` has no upstream account and no
		// scopes. The absence is the honest answer: nothing was authorized.
		const { h, deps: d, events } = deps();
		await h.store.createPending({
			id: "g-pending",
			subject: "u-1",
			clientId: "agent",
			connection: connection.name,
			intent: { handle: "h", expiresAt: new Date(now().getTime() + 600_000) },
			now: now(),
		});
		await revokeFederationGrant(d as never, "g-pending", "subject");
		const revoked = events.find((e) => e.type === "federation.grant.revoked");
		expect(revoked?.connection).toBe(connection.name);
		expect(revoked?.upstream).toBeUndefined();
		expect(revoked?.scopes).toBeUndefined();
	});

	it("hands the sink copies rather than the record's own fields", async () => {
		// A sink that holds its argument, and edits it, must not be editing
		// the record the store is still answering from.
		const { h, deps: d, events } = deps();
		await h.seed();
		await revokeFederationGrant(d as never, "g-1", "operator");
		const revoked = events.find((e) => e.type === "federation.grant.revoked");

		if (revoked === undefined) throw new Error("expected a revocation event");
		(revoked.scopes as string[]).push("injected.scope");
		(revoked.upstream as { subject: string }).subject = "somebody-else";

		const stored = await h.store.find("g-1", now());
		expect((stored as { scopes: readonly string[] }).scopes).toEqual([...SCOPES]);
		expect((stored as { upstream: { subject: string } }).upstream.subject).toBe("00u-alice");
	});

	it("does not let a failing sink undo a revocation that happened", async () => {
		const { h } = deps();
		await h.seed();
		const written = await revokeFederationGrant(
			{
				store: h.store,
				now,
				audit: () => {
					throw new Error("sink is down");
				},
			} as never,
			"g-1",
			"operator",
		);
		expect(written.ok).toBe(true);
	});
});

describe("listFederationGrantsForSubject", () => {
	it("lists what the subject has, pending and ended records included", async () => {
		// A connected-applications page that hid a pending authorization would
		// hide the one the user is in the middle of granting.
		const { h, deps: d } = deps();
		await h.seed();
		await h.seed({ id: "g-2" });
		await h.store.revoke("g-2", "subject", now());
		const listed = await listFederationGrantsForSubject(d as never, "u-1");
		expect(listed.map((g) => g.id).sort()).toEqual(["g-1", "g-2"]);
	});

	it("answers nothing for a subject with none", async () => {
		const { deps: d } = deps();
		expect(await listFederationGrantsForSubject(d as never, "nobody")).toEqual([]);
	});

	it("surfaces a storage outage rather than turning it into an empty page", async () => {
		// "You have no connected applications" is a sentence a user acts on.
		const { h, deps: d } = deps();
		vi.spyOn(h.store, "listBySubject").mockRejectedValue(new Error("store is down"));
		await expect(listFederationGrantsForSubject(d as never, "u-1")).rejects.toThrow();
	});
});
