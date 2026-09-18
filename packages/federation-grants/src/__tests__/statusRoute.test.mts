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
 * `POST /oauth/federation-grants/:grantId/status` (#593, D9).
 *
 * Status describes a grant's lifecycle; token answers an issuance request. The
 * two are different questions and the difference runs all the way through:
 *
 *  - **200 for every effective status**, expired and revoked included. A
 *    successful inspection of a grant that has ended is a successful
 *    inspection. Returning the token route's 410 here would make an operator's
 *    dashboard read "this call failed" for a grant that is simply over.
 *  - **`inspect` only.** Never `open`, never a refresh, never the refresh
 *    lock, never `touch`. Calling retrieval from status would rotate a
 *    credential at an upstream because somebody opened a dashboard — and
 *    `lastUsedAt` would say a grant was used when it was only looked at.
 *  - **It is not a health check for `/token`.** An `active` status does not
 *    promise a token: `inspect` reports whether the credential authenticates,
 *    not whether the upstream will issue something usable. The reverse holds
 *    too — a grant reported ineligible can still have a usable cached token.
 */

import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import {
	basic,
	CLIENT_ID,
	clientWithoutAllowlist,
	connection,
	DAY,
	GRANT_ID,
	harness,
	SCOPES,
	SECRET,
	SUBJECT,
} from "./harness.mjs";

const path = (id: string = GRANT_ID) => `/oauth/federation-grants/${id}/status`;

const ask = (h: ReturnType<typeof harness>, id = GRANT_ID, body: unknown = { sub: SUBJECT }) =>
	request(h.app)
		.post(path(id))
		.set("Authorization", basic())
		.send(body as object);

describe("the status route — what it reports", () => {
	it("describes an active grant without touching its credential", async () => {
		const h = harness();
		await h.seed();
		const open = vi.spyOn(h.store, "open");
		const touch = vi.spyOn(h.store, "touch");
		const lock = vi.spyOn(h.store, "acquireRefreshLock");

		const response = await ask(h);

		expect(response.status).toBe(200);
		expect(response.body).toMatchObject({
			grant_id: GRANT_ID,
			status: "active",
			sub: SUBJECT,
			client_id: CLIENT_ID,
			connection: connection.name,
			upstream: { issuer: connection.upstreamIssuer, subject: "upstream-subject" },
			scope: SCOPES.join(" "),
		});
		expect(open).not.toHaveBeenCalled();
		expect(touch).not.toHaveBeenCalled();
		expect(lock).not.toHaveBeenCalled();
		expect(h.refresh).not.toHaveBeenCalled();
	});

	it("dates everything as UTC to the millisecond", async () => {
		const h = harness();
		await h.seed();
		const response = await ask(h);
		for (const field of ["created_at", "authorized_at", "expires_at"]) {
			expect(response.body[field], field).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
		}
	});

	it("reports the authorization's scopes, not a cached token's", async () => {
		// They differ the moment an upstream answers a refresh with fewer
		// scopes than the grant carries, and what a status describes is what
		// the user consented the client to — not what one token happens to hold.
		const h = harness();
		await h.seed({
			credentials: {
				refreshToken: SECRET,
				accessToken: {
					value: "narrow",
					tokenType: "Bearer",
					obtainedAt: h.world.now,
					issuedLifetime: 3600,
					scopes: ["openid"],
				},
			},
		});
		const response = await ask(h);
		expect(response.body.scope).toBe(SCOPES.join(" "));
	});

	it("reports the expiry as it is computed now, not as it was stored", async () => {
		// D3: lowering `maxExpiresIn` moves the reported expiry earlier for
		// grants that already exist, possibly into the past. That is intended —
		// the stored `expiresAt` never changes, and raising the maximum brings
		// the reported expiry back, never beyond what the user consented to.
		const h = harness();
		await h.seed();
		const generous = await ask(h);

		h.world.maxExpiresInMs = 1 * DAY;
		const strict = await ask(h);

		expect(new Date(strict.body.expires_at).getTime()).toBeLessThan(
			new Date(generous.body.expires_at).getTime(),
		);
	});

	it("answers 200 for a grant the user revoked, and names who", async () => {
		const h = harness();
		await h.seed();
		await h.store.revoke(GRANT_ID, "subject", h.world.now);

		const response = await ask(h);

		expect(response.status).toBe(200);
		expect(response.body).toMatchObject({ status: "revoked", reason: "subject" });
	});

	it("answers 200 for a grant whose consented lifetime has ended", async () => {
		const h = harness();
		await h.seed({ expiresAt: new Date(h.world.now.getTime() + 1000) });
		h.world.now = new Date(h.world.now.getTime() + 2000);

		const response = await ask(h);

		expect(response.status).toBe(200);
		expect(response.body).toMatchObject({ status: "expired", reason: "consented_lifetime" });
	});

	it("leaves out what a record does not have rather than reporting it empty", async () => {
		// A pending grant has no upstream account, no scopes, no authorization
		// date and no expiry — it has not been consented to yet.
		const h = harness();
		await h.store.createPending({
			id: "pending-1",
			subject: SUBJECT,
			clientId: CLIENT_ID,
			connection: connection.name,
			intent: { handle: "h", expiresAt: new Date(h.world.now.getTime() + 600_000) },
			now: h.world.now,
		});

		const response = await ask(h, "pending-1");

		expect(response.status).toBe(200);
		expect(response.body.status).toBe("pending");
		expect(response.body).not.toHaveProperty("upstream");
		expect(response.body).not.toHaveProperty("scope");
		expect(response.body).not.toHaveProperty("authorized_at");
		expect(response.body).not.toHaveProperty("expires_at");
		expect(response.body).not.toHaveProperty("last_used_at");
		expect(response.body).not.toHaveProperty("reason");
	});

	it("tells nobody anything about consent sessions, intents, revisions or credentials", async () => {
		const h = harness();
		await h.seed();
		const response = await ask(h);
		const serialized = JSON.stringify(response.body);
		expect(serialized).not.toContain(SECRET);
		expect(serialized).not.toContain("sid-1");
		for (const leak of [
			"identityRevision",
			"authorizationRevision",
			"version",
			"intent",
			"refreshFailure",
		]) {
			expect(serialized, leak).not.toContain(leak);
		}
	});
});

describe("the status route — who may ask", () => {
	it("gives the same 404 for an unknown grant, another client's and another subject's", async () => {
		const h = harness();
		await h.seed();
		await h.seed({ id: "g-other-client", clientId: "someone-else" });
		await h.seed({ id: "g-other-subject", subject: "someone-else" });

		const bodies: string[] = [];
		for (const id of ["never-existed", "g-other-client", "g-other-subject"]) {
			const response = await ask(h, id);
			expect(response.status).toBe(404);
			bodies.push(JSON.stringify(response.body));
		}
		expect(new Set(bodies).size).toBe(1);
		expect(bodies[0]).toBe('{"error":"grant_not_found"}');
	});

	it("refuses a caller who has not authenticated", async () => {
		const h = harness();
		await h.seed();
		const response = await request(h.app).post(path()).send({ sub: SUBJECT });
		expect(response.status).toBe(401);
	});

	it("requires the connection allowlist for a grant that is still live", async () => {
		const h = harness();
		await h.seed();
		h.world.allowedConnections = [];

		const response = await ask(h);

		expect(response.status).toBe(403);
		expect(response.body).toEqual({
			error: "access_denied",
			error_description: "connection_not_permitted",
		});
	});

	it("still describes a grant that has ended, allowlist or not", async () => {
		// A client whose registration changed can still be told that the grant
		// it used to spend is over — which is the answer that lets it stop
		// retrying. Nothing about a terminal grant needs the connection.
		const h = harness();
		await h.seed();
		await h.store.revoke(GRANT_ID, "operator", h.world.now);
		h.world.allowedConnections = [];

		const response = await ask(h);

		expect(response.status).toBe(200);
		expect(response.body).toMatchObject({ status: "revoked", reason: "operator" });
	});

	it("still describes an expired grant, allowlist or not", async () => {
		// The revoked case returns from the record before the allowlist is
		// reached; an expiry is computed, and goes through the same code an
		// active grant does. Both have to answer.
		const h = harness();
		await h.seed({ expiresAt: new Date(h.world.now.getTime() + 1000) });
		h.world.now = new Date(h.world.now.getTime() + 2000);
		h.world.allowedConnections = [];

		const response = await ask(h);

		expect(response.status).toBe(200);
		expect(response.body).toMatchObject({ status: "expired" });
	});

	it("requires the allowlist for a pending grant, which is not a terminal state", async () => {
		// Found by review. The exemption is for grants that have ENDED — the
		// answer that lets a client stop asking. A pending one has not started,
		// and describing it to a client that may no longer use the connection
		// is the ordinary authorization question.
		const h = harness();
		await h.store.createPending({
			id: "pending-1",
			subject: SUBJECT,
			clientId: CLIENT_ID,
			connection: connection.name,
			intent: { handle: "h", expiresAt: new Date(h.world.now.getTime() + 600_000) },
			now: h.world.now,
		});
		h.world.allowedConnections = [];

		const response = await ask(h, "pending-1");

		expect(response.status).toBe(403);
		expect(response.body.error).toBe("access_denied");
	});

	it("tells a de-allowlisted client that the grant ended, and nothing more", async () => {
		// Found by review. Removing a client from the allowlist is an
		// operator's lever; one that changes the status code but hands back the
		// same upstream account, the consented scope set and the dates is half
		// a lever. What survives is what lets the client stop asking.
		const h = harness();
		await h.seed();
		await h.store.revoke(GRANT_ID, "operator", h.world.now);
		h.world.allowedConnections = [];

		const response = await ask(h);

		expect(response.status).toBe(200);
		expect(response.body).toMatchObject({ status: "revoked", reason: "operator" });
		for (const field of [
			"upstream",
			"scope",
			"resource",
			"authorized_at",
			"expires_at",
			"last_used_at",
		]) {
			expect(response.body, field).not.toHaveProperty(field);
		}
	});

	it("reads an allowlist that is not a list as allowing nothing", async () => {
		// `ClientRepository` is a port, and a deployment's own repository
		// validates nothing this package can see. Review found what a
		// comma-joined string does to `.includes`: `"calendar,mail"` would have
		// allowed `"cal"`.
		const h = harness();
		await h.seed();
		h.world.allowedConnections = "calendar,mail" as unknown as readonly string[];

		expect((await ask(h)).status).toBe(403);
	});

	it("reads an absent allowlist as allowing nothing", async () => {
		const h = harness();
		await h.seed();
		h.world.client = clientWithoutAllowlist;
		h.world.allowedConnections = undefined;

		expect((await ask(h)).status).toBe(403);
	});
});

describe("the status route — the body it accepts", () => {
	it("takes a subject and nothing else", async () => {
		const h = harness();
		await h.seed();
		expect((await ask(h, GRANT_ID, { sub: SUBJECT })).status).toBe(200);
	});

	it("refuses the assertions the token route takes, rather than ignoring them", async () => {
		// Silently ignoring `min_ttl` here would let a caller believe status
		// answered the question they asked. It answers a different one.
		const h = harness();
		await h.seed();
		for (const body of [
			{ sub: SUBJECT, min_ttl: 60 },
			{ sub: SUBJECT, scope: "openid" },
			{ sub: SUBJECT, connection: connection.name },
			{ sub: SUBJECT, resource: "https://graph.example" },
		]) {
			const response = await ask(h, GRANT_ID, body);
			expect(response.status, JSON.stringify(body)).toBe(400);
			expect(response.body.error).toBe("invalid_request");
			// One identifier for every parameter this route does not take,
			// including the token route's own: a caller that sent `min_ttl`
			// and one that sent `minttl` both asked for something that did not
			// happen, and the difference is not something to branch on.
			expect(response.body.error_description).toBe("unexpected_parameter");
		}
	});

	it("requires a subject", async () => {
		const h = harness();
		await h.seed();
		expect((await ask(h, GRANT_ID, {})).status).toBe(400);
	});
});

describe("the status route — the boundary and the backstop", () => {
	it("answers 503 storage when the boundary cannot be read for a live grant", async () => {
		const h = harness();
		await h.seed();
		h.world.boundary = new Error("boundary is down");

		const response = await ask(h);

		expect(response.status).toBe(503);
		expect(response.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "storage",
		});
	});

	it("still answers from the record for a stored revocation, boundary or no boundary", async () => {
		// A revocation that is already written down needs nothing compared. A
		// 503 here would hide the one answer the caller most needs.
		const h = harness();
		await h.seed();
		await h.store.revoke(GRANT_ID, "subject", h.world.now);
		h.world.boundary = new Error("boundary is down");

		const response = await ask(h);

		expect(response.status).toBe(200);
		expect(response.body).toMatchObject({ status: "revoked", reason: "subject" });
	});

	it("answers from the record for a revoked grant whose client lost the connection", async () => {
		// Both exemptions at once, which is the case the early branch exists
		// for: no boundary to compare with, and no allowlist to check against.
		// A client that can no longer use the connection still gets the one
		// answer that lets it stop asking.
		const h = harness();
		await h.seed();
		await h.store.revoke(GRANT_ID, "subject", h.world.now);
		h.world.boundary = new Error("boundary is down");
		h.world.allowedConnections = [];

		const response = await ask(h);

		expect(response.status).toBe(200);
		expect(response.body).toMatchObject({ status: "revoked", reason: "subject" });
	});

	it("writes the backstop down when it finds one, and says so once", async () => {
		// The grant is covered by a subject-wide revocation that never reached
		// the record. Reporting it is not enough: the next reader would compute
		// it again, and a boundary that is later lost would resurrect the grant.
		const h = harness();
		await h.seed();
		h.world.boundary = new Date(h.world.now.getTime() + 1000);

		const response = await ask(h);

		expect(response.status).toBe(200);
		expect(response.body).toMatchObject({ status: "revoked", reason: "backstop" });
		const stored = await h.store.inspect(GRANT_ID, h.world.now);
		expect(stored?.grant.status).toBe("revoked");
		const revoked = h.events.filter((e) => e.type === "federation.grant.revoked");
		expect(revoked).toHaveLength(1);
		expect(revoked[0]?.details).toMatchObject({
			outcome: "backstop",
			operation: "status",
			// What access ended, and not only which grant (D18).
			connection: connection.name,
			upstream: { issuer: connection.upstreamIssuer, subject: "upstream-subject" },
			scopes: [...SCOPES],
		});
	});

	it("describes the record it ended, not the one it read a moment earlier", async () => {
		// Found by review. The backstop inspects, decides, and then writes —
		// and a reauthorization landing between those two replaces the
		// authorization. An event built from the earlier read would name the
		// scopes that were NOT the ones taken away.
		const h = harness();
		await h.seed();
		h.world.boundary = new Date(h.world.now.getTime() + 1000);
		const real = h.store.revoke.bind(h.store);
		vi.spyOn(h.store, "revoke").mockImplementation(async (id, by, at) => {
			const written = await real(id, by, at);
			if (!written.ok) return written;
			return {
				ok: true,
				grant: {
					...written.grant,
					scopes: ["openid", "calendar.write"],
					upstream: { issuer: connection.upstreamIssuer, subject: "reauthorized-subject" },
				},
			} as typeof written;
		});

		expect((await ask(h)).status).toBe(200);

		const revoked = h.events.find((e) => e.type === "federation.grant.revoked");
		expect(revoked?.details).toMatchObject({
			upstream: { subject: "reauthorized-subject" },
			scopes: ["openid", "calendar.write"],
		});
	});

	it("writes the backstop down as a backstop, not as somebody's decision", async () => {
		// `backstop` and `operator` are different facts about why a grant ended,
		// and the runbook tells an operator different things about each. The
		// response reason is computed; the stored one is what survives.
		const h = harness();
		await h.seed();
		h.world.boundary = new Date(h.world.now.getTime() + 1000);

		await ask(h);

		const stored = await h.store.inspect(GRANT_ID, h.world.now);
		if (stored === null) throw new Error("the grant is gone");
		expect(stored.grant.status).toBe("revoked");
		expect((stored.grant as { revocation: { by: string } }).revocation.by).toBe("backstop");
	});

	it("does not claim a revocation another reader wrote", async () => {
		// Two dashboards open on the same grant is the ordinary case. The
		// answer is the same for both; the event belongs to whichever call
		// actually changed the record.
		const h = harness();
		await h.seed();
		h.world.boundary = new Date(h.world.now.getTime() + 1000);
		vi.spyOn(h.store, "revoke").mockResolvedValue({ ok: false });

		const response = await ask(h);

		expect(response.status).toBe(200);
		expect(response.body).toMatchObject({ status: "revoked", reason: "backstop" });
		expect(h.events.filter((e) => e.type === "federation.grant.revoked")).toHaveLength(0);
	});

	it("answers 503 storage when the record itself cannot be read", async () => {
		// Found by review. A Redis outage on `/token` is 503
		// `temporarily_unavailable/storage`; the same outage here fell into the
		// handler's catch and answered 500 `server_error`, which tells a caller
		// this provider has a bug rather than that it should come back.
		const h = harness();
		await h.seed();
		vi.spyOn(h.store, "inspect").mockRejectedValue(new Error("store is down"));

		const response = await ask(h);

		expect(response.status).toBe(503);
		expect(response.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "storage",
		});
	});

	it("answers 503 when the backstop cannot be written down", async () => {
		const h = harness();
		await h.seed();
		h.world.boundary = new Date(h.world.now.getTime() + 1000);
		vi.spyOn(h.store, "revoke").mockRejectedValue(new Error("store is down"));

		const response = await ask(h);

		expect(response.status).toBe(503);
		expect(response.body.error_description).toBe("storage");
	});
});

describe("the status route — a key that is not in the ring", () => {
	it("answers 503 rather than sending the user to consent again", async () => {
		// A missing key is an outage an operator fixes by restoring it. Saying
		// `reauthorization_required` would send every user of that connection
		// through a consent page to solve a problem none of them has.
		const h = harness();
		await h.seed();
		h.world.credentials = "key_unavailable";

		const response = await ask(h);

		expect(response.status).toBe(503);
		expect(response.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "key_unavailable",
		});
	});

	it("does not let the outage mask a stored revocation", async () => {
		const h = harness();
		await h.seed();
		await h.store.revoke(GRANT_ID, "subject", h.world.now);
		h.world.credentials = "key_unavailable";

		const response = await ask(h);

		expect(response.status).toBe(200);
		expect(response.body).toMatchObject({ status: "revoked" });
	});

	it("does not let the outage mask an expiry, which needs no credential either", async () => {
		// This one reaches the check — a stored revocation returns before it —
		// so it is where "only where the answer would have been
		// `credential_unreadable`" is actually decided. A 503 here would tell
		// an operator to restore a key for a grant that is simply over.
		const h = harness();
		await h.seed({ expiresAt: new Date(h.world.now.getTime() + 1000) });
		h.world.now = new Date(h.world.now.getTime() + 2000);
		h.world.credentials = "key_unavailable";

		const response = await ask(h);

		expect(response.status).toBe(200);
		expect(response.body).toMatchObject({ status: "expired" });
	});
});

describe("the status route — configuration", () => {
	it("reports a connection an operator removed, and does not call it changed", async () => {
		// Putting the entry back restores the grant, so this is a configuration
		// remedy — not `connection_identity_changed`, which no reauthorization
		// can mend.
		const h = harness();
		await h.seed();
		h.world.connections.delete(connection.name);

		const response = await ask(h);

		expect(response.status).toBe(200);
		expect(response.body.status).toBe("connection_not_configured");
	});
});
