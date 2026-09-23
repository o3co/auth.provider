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
 * `POST /oauth/federation-grants` and `POST /oauth/federation-grants/:grantId/reauthorize`
 * (#593, D6, slice 6) — a confidential client lodging an intent.
 *
 * Run against the real lodging function and the real in-memory stores: what is
 * tested is that the route adds transport, authentication, serialization and
 * audit to what core decides, and decides nothing core has not.
 */

import request from "supertest";
import { describe, expect, it } from "vitest";
import {
	basic,
	CLIENT_ID,
	connection,
	DAY,
	GRANT_ID,
	harness,
	REDIRECT_URI,
	SCOPES,
	SECRET,
	SUBJECT,
} from "./harness.mjs";

type H = ReturnType<typeof harness>;

const lodge = (h: H, body: Record<string, unknown> = {}) =>
	request(h.app)
		.post("/oauth/federation-grants")
		.set("Authorization", basic())
		.send({
			connection: connection.name,
			sub: SUBJECT,
			redirect_uri: REDIRECT_URI,
			state: "client-state-1",
			...body,
		});

const renew = (h: H, body: Record<string, unknown> = {}, id = GRANT_ID) =>
	request(h.app)
		.post(`/oauth/federation-grants/${id}/reauthorize`)
		.set("Authorization", basic())
		.send({ sub: SUBJECT, redirect_uri: REDIRECT_URI, state: "client-state-2", ...body });

const handleOf = (connectUri: string): string =>
	new URL(connectUri).searchParams.get("request") ?? "";

describe("POST /oauth/federation-grants — lodging a first-time intent", () => {
	it("answers 201 with the pending grant, where to send the browser, and the durations that applied", async () => {
		const h = harness();
		const response = await lodge(h);
		expect(response.status).toBe(201);
		const body = response.body as Record<string, unknown>;
		expect(body.status).toBe("pending");
		expect(typeof body.grant_id).toBe("string");
		const connectUri = new URL(body.connect_uri as string);
		// On the issuer — never on a Host header a caller could choose.
		expect(connectUri.origin).toBe("https://auth.test");
		expect(connectUri.pathname).toBe("/session/federation-grants/connect");
		expect(body.connect_expires_in).toBe(600);
		expect(body.expires_in).toBe((30 * DAY) / 1000);

		const intent = await h.intents.getIntent(handleOf(body.connect_uri as string), h.world.now);
		expect(intent).toMatchObject({
			kind: "initial",
			grantId: body.grant_id,
			clientId: CLIENT_ID,
			subject: SUBJECT,
			connection: connection.name,
			redirectUri: REDIRECT_URI,
			clientState: "client-state-1",
			scopes: [...SCOPES],
		});
		expect((await h.store.find(body.grant_id as string, h.world.now))?.status).toBe("pending");
		expect(response.headers["cache-control"]).toContain("no-store");
	});

	it("clamps a lifetime above the maximum and says what applied", async () => {
		const h = harness();
		const response = await lodge(h, { expires_in: 365 * 86_400 });
		expect(response.status).toBe(201);
		expect(response.body.expires_in).toBe(30 * 86_400);
		const shorter = await lodge(h, { expires_in: "86400" });
		expect(shorter.body.expires_in).toBe(86_400);
	});

	it("audits the request with what was asked for, and never the handle", async () => {
		const h = harness();
		const response = await lodge(h, { scope: "openid offline_access" });
		await h.background.drain();
		const event = h.events.find((e) => e.type === "federation.grant.requested");
		expect(event).toMatchObject({
			type: "federation.grant.requested",
			clientId: CLIENT_ID,
			subject: SUBJECT,
			details: {
				grantId: response.body.grant_id,
				connection: connection.name,
				scopes: ["openid", "offline_access"],
				outcome: "initial",
			},
		});
		const handle = handleOf(response.body.connect_uri);
		expect(JSON.stringify(h.events)).not.toContain(handle);
		expect(JSON.stringify(h.logs)).not.toContain(handle);
	});

	it.each([
		[{ sub: undefined }, "sub_required"],
		[{ connection: undefined }, "connection_required"],
		[{ redirect_uri: undefined }, "redirect_uri_required"],
		[{ state: undefined }, "state_required"],
		[{ state: "" }, "state_required"],
		[{ scope: "" }, "invalid_scope"],
		[{ expires_in: "1.5" }, "invalid_expires_in"],
		[{ expires_in: "1e3" }, "invalid_expires_in"],
		[{ expires_in: 0 }, "invalid_expires_in"],
		[{ expires_in: true }, "invalid_expires_in"],
		[{ upstream_sub: "" }, "invalid_upstream_sub"],
		[{ resource: "https://api.example" }, "unexpected_parameter"],
		[{ expires_at: "2027-01-01" }, "unexpected_parameter"],
	])("refuses a body that cannot be lodged: %j → %s", async (over, description) => {
		const h = harness();
		const response = await lodge(h, over);
		expect(response.status).toBe(400);
		expect(response.body).toEqual({ error: "invalid_request", error_description: description });
		expect(h.intents.size).toBe(0);
	});

	it("refuses a parameter sent twice, rather than choosing one", async () => {
		const h = harness();
		const response = await request(h.app)
			.post("/oauth/federation-grants")
			.set("Authorization", basic())
			.type("form")
			.send(
				`connection=${connection.name}&sub=${SUBJECT}&sub=someone-else&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&state=s`,
			);
		expect(response.status).toBe(400);
		expect(response.body).toEqual({ error: "invalid_request", error_description: "duplicate_sub" });
	});

	it("maps what core refused to D6's exits", async () => {
		const h = harness();
		h.world.allowedConnections = [];
		expect((await lodge(h)).body).toEqual({
			error: "access_denied",
			error_description: "connection_not_permitted",
		});

		h.world.allowedConnections = [connection.name];
		h.world.connections.delete(connection.name);
		const gone = await lodge(h);
		expect(gone.status).toBe(503);
		expect(gone.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "connection_not_configured",
		});
		h.world.connections.set(connection.name, connection);

		const unregistered = await lodge(h, { redirect_uri: "https://evil.test/" });
		expect(unregistered.status).toBe(400);
		expect(unregistered.body).toEqual({
			error: "invalid_request",
			error_description: "redirect_uri_not_registered",
		});

		const widened = await lodge(h, { scope: "openid offline_access admin" });
		expect(widened.status).toBe(400);
		expect(widened.body).toEqual({ error: "invalid_scope", error_description: "scope_exceeded" });

		const noOpenid = await lodge(h, { scope: "offline_access" });
		expect(noOpenid.body).toEqual({ error: "invalid_scope", error_description: "openid_required" });
	});

	it("answers a full bound as the client's own throttle, and lodges nothing", async () => {
		const h = harness();
		for (let i = 0; i < 16; i += 1) expect((await lodge(h)).status).toBe(201);
		const refused = await lodge(h);
		expect(refused.status).toBe(429);
		expect(refused.body).toEqual({ error: "rate_limited", error_description: "intent_limit" });
	});

	it("audits a refusal it made itself, with the fixed outcome and the asserted subject", async () => {
		const h = harness();
		await lodge(h, { redirect_uri: "https://evil.test/" });
		await h.background.drain();
		expect(h.events.find((e) => e.type === "federation.grant.request.denied")).toMatchObject({
			clientId: CLIENT_ID,
			subject: SUBJECT,
			details: { outcome: "invalid_request/redirect_uri_not_registered" },
		});
	});

	it("audits a refusal the middleware made before the handler ran, naming no client", async () => {
		const h = harness();
		const response = await request(h.app)
			.post("/oauth/federation-grants")
			.set("Authorization", basic(CLIENT_ID, "wrong"))
			.send({ connection: connection.name, sub: SUBJECT, redirect_uri: REDIRECT_URI, state: "s" });
		expect(response.status).toBe(401);
		await h.background.drain();
		const event = h.events.find((e) => e.type === "federation.grant.request.denied");
		expect(event).toMatchObject({ clientId: "", details: { outcome: "invalid_client" } });
	});
});

describe("POST /oauth/federation-grants/:grantId/reauthorize — renewing a grant", () => {
	it("names a new intent on the grant and answers the grant's own status, which a renewal does not change", async () => {
		const h = harness();
		await h.seed();
		const response = await renew(h);
		expect(response.status).toBe(201);
		expect(response.body).toMatchObject({
			grant_id: GRANT_ID,
			status: "active",
			connect_expires_in: 600,
		});
		const handle = handleOf(response.body.connect_uri);
		expect(await h.store.isCurrentIntent(GRANT_ID, handle, h.world.now)).toBe(true);
		expect((await h.intents.getIntent(handle, h.world.now))?.kind).toBe("reauthorization");
		// The credential is untouched: nothing a client can see changed.
		expect((await h.store.find(GRANT_ID, h.world.now))?.status).toBe("active");
	});

	it("admits a grant starved of scope and answers 201 with the ineligibility it does not change (#616)", async () => {
		const h = harness();
		await h.seed();
		const grant = await h.store.find(GRANT_ID, h.world.now);
		const marked = await h.store.replaceCredentials({
			grantId: GRANT_ID,
			expectedVersion: grant?.version ?? -1,
			credentials: { refreshToken: SECRET, accessToken: undefined },
			ineligible: {
				reason: "scope_exceeded",
				at: h.world.now,
				judgedAgainst: connection.maxAccessTokenLifetime,
			},
			now: h.world.now,
		});
		expect(marked.ok).toBe(true);
		const response = await renew(h);
		expect(response.status).toBe(201);
		expect(response.body).toMatchObject({
			grant_id: GRANT_ID,
			status: "upstream_token_ineligible",
		});
		expect((await h.store.find(GRANT_ID, h.world.now))?.ineligible).toMatchObject({
			reason: "scope_exceeded",
		});
	});

	it("refuses every other ineligibility as it did: 502, by its reason, and no intent (#616)", async () => {
		const h = harness();
		await h.seed();
		h.world.connections.set(connection.name, { ...connection, maxAccessTokenLifetime: 0 });
		const response = await renew(h);
		expect(response.status).toBe(502);
		expect(response.body).toEqual({
			error: "upstream_token_ineligible",
			error_description: "lifetime_over_maximum",
		});
	});

	it("answers one way for an unknown grant, another client's and another subject's", async () => {
		const h = harness();
		await h.seed({ clientId: "someone-else" });
		for (const [body, id] of [
			[{}, "no-such-grant"],
			[{}, GRANT_ID],
		] as const) {
			const response = await renew(h, body, id);
			expect(response.status).toBe(404);
			expect(response.body).toEqual({ error: "grant_not_found" });
		}
		// The subject is judged on the client's OWN grant. Run against the
		// fixture above, this case would pass with the subject comparison
		// deleted — the client mismatch answers first.
		const own = harness();
		await own.seed();
		const response = await renew(own, { sub: "another-subject" }, GRANT_ID);
		expect(response.status).toBe(404);
		expect(response.body).toEqual({ error: "grant_not_found" });
	});

	it("revokes, and audits, a grant the subject-wide boundary covers — before it looks at anything else", async () => {
		const h = harness();
		await h.seed();
		h.world.boundary = new Date(h.world.now.getTime() + 1);
		const response = await renew(h, { redirect_uri: "https://evil.test/" });
		expect(response.status).toBe(410);
		expect(response.body).toEqual({ error: "grant_revoked", error_description: "backstop" });
		expect((await h.store.find(GRANT_ID, h.world.now))?.status).toBe("revoked");
		await h.background.drain();
		expect(h.events.filter((e) => e.type === "federation.grant.revoked")).toHaveLength(1);
		expect(h.events.find((e) => e.type === "federation.grant.revoked")?.details).toMatchObject({
			outcome: "backstop",
		});
	});

	it("answers a boundary it cannot read as an outage", async () => {
		const h = harness();
		await h.seed();
		h.world.boundary = new Error("down");
		const response = await renew(h);
		expect(response.status).toBe(503);
		expect(response.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "storage",
		});
	});

	it("refuses a connection it asserts that is not the grant's", async () => {
		const h = harness();
		await h.seed();
		const response = await renew(h, { connection: "another-connection" });
		expect(response.status).toBe(400);
		expect(response.body).toEqual({
			error: "invalid_request",
			error_description: "connection_mismatch",
		});
	});

	it("refuses what a renewal cannot mend with D11's status for it", async () => {
		const h = harness();
		await h.seed();
		// The operator lowered the maximum below the grant's age.
		h.world.maxExpiresInMs = 1;
		h.world.now = new Date(h.world.now.getTime() + 60_000);
		const expired = await renew(h);
		expect(expired.status).toBe(410);
		expect(expired.body).toEqual({ error: "grant_expired", error_description: "operator_maximum" });
		h.world.maxExpiresInMs = 30 * DAY;

		h.world.credentials = "key_unavailable";
		h.world.connections.set(connection.name, { ...connection });
		// A credential that will not open because its key is out of the ring.
		const keyless = await renew(h);
		expect(keyless.status).toBe(503);
		expect(keyless.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "key_unavailable",
		});
	});

	it("never puts a secret on the wire or in the trail", async () => {
		const h = harness();
		await h.seed();
		const response = await renew(h);
		await h.background.drain();
		expect(JSON.stringify(response.body)).not.toContain(SECRET);
		expect(JSON.stringify(h.events)).not.toContain(SECRET);
		expect(JSON.stringify(h.logs)).not.toContain(SECRET);
	});
});

describe("what the coverage report on #610 showed no test reached", () => {
	it("refuses to lodge once the drain has begun, and writes nothing", async () => {
		const h = harness();
		const draining = h.background.drain();
		for (const response of [await lodge(h), await renew(h)]) {
			expect(response.status).toBe(503);
			expect(response.body).toEqual({
				error: "service_unavailable",
				error_description: "shutting_down",
			});
		}
		expect(h.intents.size).toBe(0);
		expect(h.store.size).toBe(0);
		await draining;
	});

	it("answers a failure nothing expected with a fixed 500, and logs nothing it carried", async () => {
		const h = harness();
		// A configuration that cannot be read, with a secret in the message.
		h.world.connections.get = () => {
			throw new Error(`redis://user:${SECRET}@config refused the connection`);
		};
		const response = await lodge(h);
		expect(response.status).toBe(500);
		expect(response.body).toEqual({ error: "server_error", error_description: "unexpected_error" });
		expect(h.logs.length).toBeGreaterThan(0);
		expect(JSON.stringify(h.logs)).not.toContain(SECRET);
	});

	it("changes no answer, and no write, when the audit sink drops everything", async () => {
		const h = harness({
			sink: {
				kind: "down",
				record: async () => {
					throw new Error("the audit sink is down");
				},
			},
		});
		// Requested, refused, and a backstop revocation a renewal wrote.
		expect((await lodge(h)).status).toBe(201);
		expect((await lodge(h, { redirect_uri: "https://evil.test/" })).status).toBe(400);
		await h.seed();
		h.world.boundary = new Date(h.world.now.getTime() + 1);
		expect((await renew(h)).status).toBe(410);
		expect((await h.store.find(GRANT_ID, h.world.now))?.status).toBe("revoked");
		await h.background.drain();
	});
});
