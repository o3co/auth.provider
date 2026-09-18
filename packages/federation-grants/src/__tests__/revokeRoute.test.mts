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
 * `POST /oauth/federation-grants/:grantId/revoke` (#593, D9, D13).
 *
 * The route an owning client calls to end its own grant. What it asks is a
 * different question from `/token`, and almost everything `/token` consults is
 * deliberately not consulted here: ownership is the whole check, and every
 * other rule exists to decide whether a credential may be *disclosed*.
 *
 * The cases that matter are the ones where a grant is hard to use and must
 * still be easy to end — a connection removed from the configuration, a key
 * out of the ring, a grant that expired last week — plus the two that keep a
 * retrying client honest: 204 on the second call, and 404 for a grant that is
 * not both this client's and this subject's.
 */

import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import {
	basic,
	CLIENT_ID,
	clientWithoutAllowlist,
	connection,
	GRANT_ID,
	harness,
	SUBJECT,
} from "./harness.mjs";

const path = (id: string = GRANT_ID) => `/oauth/federation-grants/${id}/revoke`;

const ask = (h: ReturnType<typeof harness>, id = GRANT_ID, body: unknown = { sub: SUBJECT }) =>
	request(h.app)
		.post(path(id))
		.set("Authorization", basic())
		.send(body as object);

const statusOf = async (h: ReturnType<typeof harness>, id = GRANT_ID) =>
	(await h.store.find(id, h.world.now))?.status;

describe("the revoke route — ending a grant", () => {
	it("ends the grant and answers 204 with no body", async () => {
		const h = harness();
		await h.seed();

		const response = await ask(h);

		expect(response.status).toBe(204);
		expect(response.body).toEqual({});
		expect(response.text).toBe("");
		expect(await statusOf(h)).toBe("revoked");
	});

	it("records who ended it, which is not the same fact as a user withdrawing", async () => {
		const h = harness();
		await h.seed();
		await ask(h);
		const grant = await h.store.find(GRANT_ID, h.world.now);
		expect((grant as { revocation: { by: string } }).revocation.by).toBe("client");
	});

	it("answers 204 again on a second call", async () => {
		// The record is retained as a tombstone for the status route, so a
		// client retrying after a timeout must not be told its second attempt
		// failed at something that had already succeeded.
		const h = harness();
		await h.seed();

		expect((await ask(h)).status).toBe(204);
		const write = vi.spyOn(h.store, "revoke");
		expect((await ask(h)).status).toBe(204);
		// And writes nothing the second time. The record is a tombstone the
		// status route answers from; revoking it again is a write against a
		// record nothing can change.
		expect(write).not.toHaveBeenCalled();
	});

	it("ends a grant the subject was in the middle of giving", async () => {
		const h = harness();
		await h.store.createPending({
			id: "g-pending",
			subject: SUBJECT,
			clientId: CLIENT_ID,
			connection: connection.name,
			intent: { handle: "h", expiresAt: new Date(h.world.now.getTime() + 600_000) },
			now: h.world.now,
		});

		expect((await ask(h, "g-pending")).status).toBe(204);
		expect(await statusOf(h, "g-pending")).toBe("revoked");
	});

	it("ends a grant whose connection the operator has removed", async () => {
		// The configuration no longer describes what the grant is for, which
		// makes it unusable and is exactly why it should be endable.
		const h = harness();
		await h.seed();
		h.world.connections.delete(connection.name);

		expect((await ask(h)).status).toBe(204);
		expect(await statusOf(h)).toBe("revoked");
	});

	it("ends a grant whose credential will not open", async () => {
		const h = harness();
		await h.seed();
		h.world.credentials = "key_unavailable";
		const open = vi.spyOn(h.store, "open");
		const inspect = vi.spyOn(h.store, "inspect");

		expect((await ask(h)).status).toBe(204);
		// `find`, and neither of these: ownership lives on the record, and a
		// credential nobody can read is not a reason to keep a grant alive.
		expect(open).not.toHaveBeenCalled();
		expect(inspect).not.toHaveBeenCalled();
	});

	it("ends a grant that expired while it was still retained", async () => {
		const h = harness();
		await h.seed({ expiresAt: new Date(h.world.now.getTime() + 1000) });
		// Past its own expiry, and still retained: `find` answers for as long
		// as the tombstone lives, and this is the grant most worth ending.
		h.world.now = new Date(h.world.now.getTime() + 60_000);

		expect((await ask(h)).status).toBe(204);
		expect(await statusOf(h)).toBe("revoked");
	});

	it("does not consult the client's connection allowlist", async () => {
		// The allowlist decides what a client may obtain tokens for. A client
		// whose registration changed must still be able to clean up what it
		// created, or the grant outlives every way of ending it.
		const h = harness();
		await h.seed();
		h.world.client = clientWithoutAllowlist;

		expect((await ask(h)).status).toBe(204);
	});

	it("neither reads nor stamps the subject's boundary", async () => {
		// Ending one grant is a local fact about one record. Stamping the
		// boundary would end every grant the subject has, and their sessions
		// with them.
		const h = harness();
		await h.seed();
		h.world.boundary = new Error("the boundary must not be read");

		expect((await ask(h)).status).toBe(204);
	});

	it("never calls the upstream", async () => {
		// A withdrawal that waited on another service could not be completed
		// while that service was down.
		const h = harness();
		await h.seed();

		await ask(h);

		expect(h.refresh).not.toHaveBeenCalled();
	});
});

describe("the revoke route — what it refuses", () => {
	it("answers the same 404 for an unknown id, another client's grant and another subject's", async () => {
		const h = harness();
		await h.seed();
		await h.seed({ id: "g-theirs", clientId: "other-worker" });
		await h.seed({ id: "g-hers", subject: "another-subject" });

		const bodies: unknown[] = [];
		for (const id of ["g-nothing", "g-theirs", "g-hers"]) {
			const response = await ask(h, id);
			expect(response.status, id).toBe(404);
			bodies.push(response.body);
		}
		expect(bodies[0]).toEqual({ error: "grant_not_found" });
		expect(bodies[1]).toEqual(bodies[0]);
		expect(bodies[2]).toEqual(bodies[0]);
		// And none of them was ended: a 404 is not a withdrawal.
		expect(await statusOf(h, "g-theirs")).toBe("active");
		expect(await statusOf(h, "g-hers")).toBe("active");
	});

	it("requires the subject, and takes nothing else", async () => {
		const h = harness();
		await h.seed();

		const missing = await ask(h, GRANT_ID, {});
		expect(missing.status).toBe(400);
		expect(missing.body).toEqual({ error: "invalid_request", error_description: "sub_required" });

		for (const body of [
			{ sub: SUBJECT, scope: "openid" },
			{ sub: SUBJECT, min_ttl: 60 },
			{ sub: SUBJECT, connection: connection.name },
			{ sub: SUBJECT, resource: "https://graph.example" },
		]) {
			const response = await ask(h, GRANT_ID, body);
			expect(response.status, JSON.stringify(body)).toBe(400);
			// A withdrawal has no conditions. Accepting a field that reads like
			// one would suggest it was honoured.
			expect(response.body.error_description).toBe("unexpected_parameter");
		}
		expect(await statusOf(h)).toBe("active");
	});

	it("answers 503 storage when the record cannot be read", async () => {
		const h = harness();
		await h.seed();
		vi.spyOn(h.store, "find").mockRejectedValue(new Error("store is down"));

		const response = await ask(h);

		expect(response.status).toBe(503);
		expect(response.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "storage",
		});
	});

	it("answers 503 storage when the write throws, and does not claim success", async () => {
		const h = harness();
		await h.seed();
		vi.spyOn(h.store, "revoke").mockRejectedValue(new Error("store is down"));

		const response = await ask(h);

		expect(response.status).toBe(503);
		expect(await statusOf(h)).toBe("active");
	});

	it("answers 204 when the write changed nothing because somebody else got there first", async () => {
		const h = harness();
		await h.seed();
		vi.spyOn(h.store, "revoke").mockResolvedValue({ ok: false });

		expect((await ask(h)).status).toBe(204);
	});

	it("refuses an unauthenticated caller before it looks anything up", async () => {
		const h = harness();
		await h.seed();
		const find = vi.spyOn(h.store, "find");

		const response = await request(h.app).post(path()).send({ sub: SUBJECT });

		expect(response.status).toBe(401);
		expect(find).not.toHaveBeenCalled();
	});

	it("refuses a request admitted as the process is shutting down", async () => {
		const h = harness();
		await h.seed();
		const drained = h.background.drain();

		const response = await ask(h);

		expect(response.status).toBe(503);
		expect(response.body).toEqual({
			error: "service_unavailable",
			error_description: "shutting_down",
		});
		await drained;
	});
});

describe("the revoke route — the trail it leaves", () => {
	it("records the withdrawal once, built from the record it ended", async () => {
		const h = harness({ withSink: true });
		await h.seed();

		await ask(h);
		await h.background.drain();

		const revoked = h.events.filter((event) => event.type === "federation.grant.revoked");
		expect(revoked).toHaveLength(1);
		expect(revoked[0]).toMatchObject({
			subject: SUBJECT,
			clientId: CLIENT_ID,
			details: { grantId: GRANT_ID, outcome: "client", connection: connection.name },
		});
	});

	it("records nothing the second time, because nothing changed", async () => {
		const h = harness({ withSink: true });
		await h.seed();

		await ask(h);
		await ask(h);
		await h.background.drain();

		expect(h.events.filter((event) => event.type === "federation.grant.revoked")).toHaveLength(1);
	});

	it("counts a refused withdrawal as its own kind of event", async () => {
		// Not a `.token.denied`: a dashboard counting denied disclosures would
		// otherwise count refused withdrawals with them, and they mean
		// opposite things — one is a credential not handed out, the other a
		// credential still live that somebody tried to end.
		const h = harness({ withSink: true });
		await h.seed();

		await ask(h, "g-nothing");
		await h.background.drain();

		const denied = h.events.filter((event) => event.type === "federation.grant.revoke.denied");
		expect(denied).toHaveLength(1);
		expect(denied[0]).toMatchObject({
			clientId: CLIENT_ID,
			subject: SUBJECT,
			details: { grantId: "g-nothing", outcome: "grant_not_found" },
		});
		expect(h.events.filter((event) => event.type === "federation.grant.token.denied")).toEqual([]);
	});

	it("names no client for a refusal that never got one", async () => {
		const h = harness({ withSink: true });
		await h.seed();

		await request(h.app).post(path()).send({ sub: SUBJECT });
		await h.background.drain();

		const denied = h.events.filter((event) => event.type === "federation.grant.revoke.denied");
		expect(denied).toHaveLength(1);
		// Before authentication there is a Basic username and an assertion
		// `iss` on the request, and neither has been verified.
		expect(denied[0]).toMatchObject({ clientId: "" });
		expect(denied[0]?.details).toMatchObject({ outcome: "invalid_client" });
	});

	it("copies nothing off a record whose owner is somebody else", async () => {
		const h = harness({ withSink: true });
		await h.seed({ id: "g-theirs", subject: "another-subject" });

		await ask(h, "g-theirs");
		await h.background.drain();

		const denied = h.events.find((event) => event.type === "federation.grant.revoke.denied");
		// The subject on the event is the one the caller ASSERTED. Reporting
		// the record's would tell the caller whose grant they just guessed at.
		expect(denied).toMatchObject({ subject: SUBJECT });
	});
});
