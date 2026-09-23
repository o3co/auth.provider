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
 * `POST /oauth/federation-grants/:grantId/token` (#593, D9–D12).
 *
 * The route is a shell: transport, authentication, serialization, correlation
 * and audit, around one call to `retrieveFederationGrantToken`. So what these
 * tests are for is the shell — and, in particular, for the mistake this design
 * expects, which is an "obvious" authorization check placed in FRONT of core.
 * Core has settled precedence: a revoked grant answers 410 whether or not the
 * client may use its connection, and a cached token is served even when the
 * grant carries an ineligibility marker. A check here changes both, and every
 * one of those changes looks like a tightening.
 */

import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import {
	basic,
	brokenLimiter,
	CLIENT_ID,
	clientWithoutAllowlist,
	GRANT_ID,
	HOUR,
	harness,
	refusingLimiter,
	SCOPES,
	SECRET,
	SUBJECT,
} from "./harness.mjs";

const path = (id: string = GRANT_ID) => `/oauth/federation-grants/${id}/token`;

describe("the token route — a disclosed token", () => {
	it("answers a cached token as an OAuth token response", async () => {
		const h = harness();
		await h.seed();

		const response = await request(h.app)
			.post(path())
			.set("Authorization", basic())
			.send({ sub: SUBJECT });

		expect(response.status).toBe(200);
		expect(response.body).toEqual({
			access_token: "upstream-access-token",
			token_type: "Bearer",
			expires_in: 3600,
			scope: SCOPES.join(" "),
		});
		// No upstream round trip: the stored token has an hour left on it.
		expect(h.refresh).not.toHaveBeenCalled();
	});

	it("never discloses the refresh token, in the body or in an audit event", async () => {
		const h = harness();
		await h.seed();

		const response = await request(h.app)
			.post(path())
			.set("Authorization", basic())
			.send({ sub: SUBJECT });

		expect(JSON.stringify(response.body)).not.toContain(SECRET);
		expect(JSON.stringify(h.events)).not.toContain(SECRET);
		expect(JSON.stringify(h.logs)).not.toContain(SECRET);
	});

	it("takes a form body as readily as a JSON one", async () => {
		const h = harness();
		await h.seed();

		const response = await request(h.app)
			.post(path())
			.set("Authorization", basic())
			.type("form")
			.send({ sub: SUBJECT, connection: "calendar" });

		expect(response.status).toBe(200);
	});

	it("serves a token that cannot meet min_ttl rather than turning it into an error", async () => {
		// `min_ttl` asks for a refresh; it does not make a short token a
		// failure. Here the refresh cannot better it, and what core decides is
		// to serve what the grant has — a route that turned the unmet
		// assertion into a 400 would withhold a working token.
		const h = harness();
		await h.seed({
			credentials: {
				refreshToken: SECRET,
				accessToken: {
					value: "upstream-access-token",
					tokenType: "Bearer",
					// Obtained 60 seconds ago of a 100-second lifetime: past half
					// spent, which is the bound core puts on how often a client
					// can make it ask the upstream (D5) — before that, `min_ttl`
					// buys a rotation per request and nothing else.
					obtainedAt: new Date(h.world.now.getTime() - 60_000),
					issuedLifetime: 100,
					scopes: [...SCOPES],
				},
			},
		});
		h.refresh.mockRejectedValue(new Error("upstream is down"));

		const response = await request(h.app)
			.post(path())
			.set("Authorization", basic())
			.send({ sub: SUBJECT, min_ttl: 600 });

		expect(response.status).toBe(200);
		expect(response.body.expires_in).toBe(40);
		expect(h.refresh).toHaveBeenCalledTimes(1);
	});

	it("lets core judge a min_ttl the connection cannot honour, and does not judge it first", async () => {
		// The ceiling is the connection's `maxAccessTokenLifetime`, which the
		// route cannot see without resolving the grant — so asking for more
		// than it permits is core's `invalid_request/min_ttl_out_of_range`,
		// arriving with the same precedence as every other denial.
		const h = harness();
		await h.seed();

		const response = await request(h.app)
			.post(path())
			.set("Authorization", basic())
			.send({ sub: SUBJECT, min_ttl: 7200 });

		expect(response.status).toBe(400);
		expect(response.body).toEqual({
			error: "invalid_request",
			error_description: "min_ttl_out_of_range",
		});
	});

	it("writes one success event carrying the correlation the caller chose", async () => {
		const h = harness();
		await h.seed();

		await request(h.app)
			.post(path())
			.set("Authorization", basic())
			.set("x-request-id", "job-42")
			.send({ sub: SUBJECT });

		const success = h.events.filter((e) => e.type === "federation.grant.token.success");
		expect(success).toHaveLength(1);
		expect(success[0]).toMatchObject({
			clientId: CLIENT_ID,
			subject: SUBJECT,
			details: { correlationId: "job-42", grantId: GRANT_ID, operation: "token" },
		});
	});
});

describe("the token route — who may ask", () => {
	it("refuses an unauthenticated caller before it looks at the grant", async () => {
		const h = harness();
		await h.seed();
		const response = await request(h.app).post(path()).send({ sub: SUBJECT });
		expect(response.status).toBe(401);
		expect(response.body.error).toBe("invalid_client");
		// Nothing about the grant was decided, so nothing about it is audited.
		expect(
			h.events.some((e) => e.details?.grantId === GRANT_ID && e.type.endsWith("success")),
		).toBe(false);
	});

	it("refuses the wrong secret with the middleware's own envelope", async () => {
		const h = harness();
		await h.seed();
		const response = await request(h.app)
			.post(path())
			.set("Authorization", basic(CLIENT_ID, "wrong"))
			.send({ sub: SUBJECT });
		expect(response.status).toBe(401);
		expect(response.headers["www-authenticate"]).toMatch(/^Basic realm=/);
	});

	it("does not offer a Bearer challenge for a domain failure", async () => {
		// `WWW-Authenticate` belongs to client authentication. A grant that has
		// ended is not an authentication problem, and a client that retried
		// with a token would be answering the wrong question.
		const h = harness();
		const response = await request(h.app)
			.post(path("absent"))
			.set("Authorization", basic())
			.send({ sub: SUBJECT });
		expect(response.status).toBe(404);
		expect(response.headers["www-authenticate"]).toBeUndefined();
	});

	it("gives the same body for an unknown grant, another client's and another subject's", async () => {
		const h = harness();
		await h.seed();
		await h.seed({ id: "g-other-client", clientId: "someone-else" });
		await h.seed({ id: "g-other-subject", subject: "someone-else" });

		const bodies: string[] = [];
		for (const id of ["never-existed", "g-other-client", "g-other-subject"]) {
			const response = await request(h.app)
				.post(path(id))
				.set("Authorization", basic())
				.send({ sub: SUBJECT });
			expect(response.status).toBe(404);
			bodies.push(JSON.stringify(response.body));
		}
		expect(new Set(bodies).size).toBe(1);
		expect(bodies[0]).toBe('{"error":"grant_not_found"}');
	});

	it("refuses a connection the client is not allowed, and says so as 403", async () => {
		const h = harness();
		await h.seed();
		h.world.allowedConnections = [];

		const response = await request(h.app)
			.post(path())
			.set("Authorization", basic())
			.send({ sub: SUBJECT });

		expect(response.status).toBe(403);
		expect(response.body).toEqual({
			error: "access_denied",
			error_description: "connection_not_permitted",
		});
	});

	it("treats a client registered before the feature existed as allowed nothing", async () => {
		// Absence is not "unrestricted". A record with no
		// `allowedFederationGrantConnections` is every client a deployment had
		// before offline delegation, and reading it as a wildcard would opt all
		// of them into spending grants the day the feature is switched on.
		const h = harness();
		await h.seed();
		h.world.client = clientWithoutAllowlist;
		h.world.allowedConnections = undefined;

		const response = await request(h.app)
			.post(path())
			.set("Authorization", basic())
			.send({ sub: SUBJECT });

		expect(response.status).toBe(403);
		expect(response.body.error).toBe("access_denied");
	});

	it("reads an allowlist that is not a list as allowing nothing", async () => {
		const h = harness();
		await h.seed();
		h.world.allowedConnections = "calendar,mail" as unknown as readonly string[];

		const response = await request(h.app)
			.post(path())
			.set("Authorization", basic())
			.send({ sub: SUBJECT });

		expect(response.status).toBe(403);
	});

	it("refuses a public client, whose only credential is not a secret", async () => {
		const h = harness();
		await h.seed();
		h.world.client = {
			...clientWithoutAllowlist,
			tokenEndpointAuthMethod: "none",
		} as typeof clientWithoutAllowlist;

		const response = await request(h.app).post(path()).send({ sub: SUBJECT, client_id: CLIENT_ID });

		expect(response.status).toBeGreaterThanOrEqual(400);
		expect(response.body.error).toBe("invalid_client");
	});

	it("throttles before it authenticates, so guessing costs nothing to refuse", async () => {
		// The path carries an opaque grant id and the same 404 answers an
		// unknown one, another client's and another subject's — which is a
		// defence only while the number of guesses is bounded. Bounding it
		// after client authentication would put a repository lookup in front of
		// every guess.
		const h = harness({ rateLimiter: refusingLimiter });
		const response = await request(h.app).post(path()).send({ sub: SUBJECT });

		expect(response.status).toBe(429);
		expect(response.body).toEqual({ error: "rate_limited", error_description: "provider" });
	});

	it("keeps core's precedence: a revoked grant is 410 even for a client with no allowlist", async () => {
		// The mistake this design expects. An allowlist check in front of core
		// turns this into 403 — which tells a caller that the grant exists and
		// would work if their registration changed, when in fact the user
		// revoked it.
		const h = harness();
		await h.seed();
		await h.store.revoke(GRANT_ID, "subject", h.world.now);
		h.world.allowedConnections = [];

		const response = await request(h.app)
			.post(path())
			.set("Authorization", basic())
			.send({ sub: SUBJECT });

		expect(response.status).toBe(410);
		expect(response.body).toEqual({ error: "grant_revoked", error_description: "subject" });
	});
});

describe("the token route — what it refuses before core", () => {
	it("refuses a body it cannot read as 400 invalid_request", async () => {
		const h = harness();
		await h.seed();
		const response = await request(h.app)
			.post(path())
			.set("Authorization", basic())
			.send({ subject: SUBJECT });
		expect(response.status).toBe(400);
		expect(response.body.error).toBe("invalid_request");
	});

	it("refuses a body that is not the JSON it says it is, without quoting it back", async () => {
		// `body-parser` puts the offending input into its message. Echoing that
		// as `error_description` hands a caller their own bytes back through a
		// field this package promises is a stable identifier.
		const h = harness();
		const response = await request(h.app)
			.post(path())
			.set("Authorization", basic())
			.set("Content-Type", "application/json")
			.send('{"sub": "u", SENTINEL-not-json}');

		expect(response.status).toBe(400);
		expect(response.body).toEqual({
			error: "invalid_request",
			error_description: "malformed_body",
		});
	});

	it("refuses an unsupported content type as 415", async () => {
		const h = harness();
		const response = await request(h.app)
			.post(path())
			.set("Authorization", basic())
			.set("Content-Type", "application/xml")
			.send("<sub>u</sub>");
		expect(response.status).toBe(415);
		expect(response.body.error).toBe("invalid_request");
	});

	it("refuses a body over the limit as 413", async () => {
		const h = harness();
		const response = await request(h.app)
			.post(path())
			.set("Authorization", basic())
			.send({ sub: SUBJECT, connection: "x".repeat(20_000) });
		expect(response.status).toBe(413);
		expect(response.body.error).toBe("invalid_request");
	});

	it("audits a denial that never reached core, without naming a caller it has not authenticated", async () => {
		const h = harness();
		const response = await request(h.app)
			.post(path())
			.set("Authorization", basic())
			.send({ sub: "" });
		expect(response.status).toBe(400);
		const denied = h.events.filter((e) => e.type === "federation.grant.token.denied");
		expect(denied).toHaveLength(1);
		expect(denied[0]?.details?.outcome).toBe("invalid_request");
	});

	it("answers 503 shutting_down once the drain has begun, and starts nothing", async () => {
		const h = harness();
		await h.seed();
		await h.background.drain();

		const response = await request(h.app)
			.post(path())
			.set("Authorization", basic())
			.send({ sub: SUBJECT });

		expect(response.status).toBe(503);
		expect(response.body).toEqual({
			error: "service_unavailable",
			error_description: "shutting_down",
		});
		expect(h.refresh).not.toHaveBeenCalled();
	});
});

describe("the token route — denials decided before the handler", () => {
	it("audits an authentication failure, without naming the client it refused", async () => {
		// Found by review: these exits terminate inside middleware, so the
		// handler — which was the only thing emitting a denial — never ran, and
		// every refused credential and every throttled attempt was outside the
		// audit trail.
		const h = harness();
		await h.seed();

		const response = await request(h.app)
			.post(path())
			.set("Authorization", basic(CLIENT_ID, "wrong"))
			.send({ sub: SUBJECT });

		expect(response.status).toBe(401);
		const denied = h.events.filter((e) => e.type === "federation.grant.token.denied");
		expect(denied).toHaveLength(1);
		expect(denied[0]?.details).toMatchObject({ outcome: "invalid_client", grantId: GRANT_ID });
		expect(denied[0]?.clientId).toBe("");
	});

	it("audits a throttled attempt", async () => {
		const h = harness({ rateLimiter: refusingLimiter });
		const response = await request(h.app).post(path()).send({ sub: SUBJECT });

		expect(response.status).toBe(429);
		const denied = h.events.filter((e) => e.type === "federation.grant.token.denied");
		expect(denied).toHaveLength(1);
		expect(denied[0]?.details?.outcome).toBe("rate_limited/provider");
	});

	it("audits a body the parsers refused", async () => {
		const h = harness();
		const response = await request(h.app)
			.post(path())
			.set("Authorization", basic())
			.set("Content-Type", "application/xml")
			.send("<sub/>");

		expect(response.status).toBe(415);
		const denied = h.events.filter((e) => e.type === "federation.grant.token.denied");
		expect(denied).toHaveLength(1);
		expect(denied[0]?.details?.outcome).toBe("invalid_request");
	});

	it("audits a limiter outage as one, and keeps its message out of the trail", async () => {
		// Found by review. `checkWithFailMode` turns the limiter's exception
		// into its MESSAGE and puts that string into both the log line and the
		// `rate_limit.unavailable` event — and a string was passing this
		// package's sanitizer, which trusted scalars.
		const h = harness({ rateLimiter: brokenLimiter });
		const response = await request(h.app).post(path()).send({ sub: SUBJECT });

		expect(response.status).toBe(503);
		expect(JSON.stringify(h.events)).not.toContain(SECRET);
		expect(JSON.stringify(h.logs)).not.toContain(SECRET);
		const denied = h.events.filter((e) => e.type === "federation.grant.token.denied");
		expect(denied[0]?.details?.outcome).toBe("service_unavailable/rate_limiter");
	});

	it("writes exactly one denial for an exit the handler did reach", async () => {
		// The handler emits its own; the exit hook must not double it.
		const h = harness();
		const response = await request(h.app)
			.post(path())
			.set("Authorization", basic())
			.send({ sub: "" });

		expect(response.status).toBe(400);
		expect(h.events.filter((e) => e.type === "federation.grant.token.denied")).toHaveLength(1);
	});

	it("writes no denial for an answer that succeeded", async () => {
		const h = harness();
		await h.seed();
		await request(h.app).post(path()).set("Authorization", basic()).send({ sub: SUBJECT });
		expect(h.events.filter((e) => e.type === "federation.grant.token.denied")).toHaveLength(0);
	});

	it("writes no denial for the status route, which audits no denials at all", async () => {
		const h = harness({ rateLimiter: refusingLimiter });
		await request(h.app).post(`/oauth/federation-grants/${GRANT_ID}/status`).send({ sub: SUBJECT });
		expect(h.events.filter((e) => e.type === "federation.grant.token.denied")).toHaveLength(0);
	});
});

describe("the token route — how a failure is carried", () => {
	it("answers 503 storage when the revocation boundary cannot be read", async () => {
		// Failing closed: without the boundary there is no way to know the
		// subject's grants were not revoked, and D13 says an unknown answer is
		// not "no revocation recorded".
		const h = harness();
		await h.seed();
		h.world.boundary = new Error("boundary is down");

		const response = await request(h.app)
			.post(path())
			.set("Authorization", basic())
			.send({ sub: SUBJECT });

		expect(response.status).toBe(503);
		expect(response.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "storage",
		});
	});

	it("answers a grant whose refresh was refused for the user's absence with 410 by that name, no Retry-After, and never its cached token (#616)", async () => {
		const h = harness();
		await h.seed();
		const grant = await h.store.find(GRANT_ID, h.world.now);
		const noted = await h.store.noteRefreshFailure({
			grantId: GRANT_ID,
			expectedVersion: grant?.version ?? -1,
			failure: { at: h.world.now, kind: "rejected", upstreamCode: "consent_required" },
			rowMs: 300_000,
			now: h.world.now,
		});
		expect(noted.ok).toBe(true);

		const response = await request(h.app)
			.post(path())
			.set("Authorization", basic())
			.send({ sub: SUBJECT });

		expect(response.status).toBe(410);
		expect(response.body).toEqual({
			error: "reauthorization_required",
			error_description: "upstream_consent_required",
		});
		expect(response.headers["retry-after"]).toBeUndefined();
		expect(h.refresh).not.toHaveBeenCalled();
	});

	it("carries Retry-After from a denial that is not a throttle", async () => {
		const h = harness();
		await h.seed({
			credentials: { refreshToken: SECRET, accessToken: undefined },
		});
		// An upstream that answers with a token nobody may use: the marker
		// carries the interval before it is worth asking again.
		h.refresh.mockResolvedValue({
			accessToken: "fresh",
			expiresIn: 86_400,
			expiresAt: new Date(h.world.now.getTime() + 86_400_000),
			tokenType: "Bearer",
		});

		const response = await request(h.app)
			.post(path())
			.set("Authorization", basic())
			.send({ sub: SUBJECT });

		expect(response.status).toBe(502);
		expect(response.body.error).toBe("upstream_token_ineligible");
		expect(response.headers["retry-after"]).toBe("300");
	});

	it("never echoes what an upstream said back to the caller", async () => {
		const h = harness();
		await h.seed({ credentials: { refreshToken: SECRET, accessToken: undefined } });
		h.refresh.mockRejectedValue(new Error(`upstream said: ${SECRET}`));

		const response = await request(h.app)
			.post(path())
			.set("Authorization", basic())
			.send({ sub: SUBJECT });

		expect(JSON.stringify(response.body)).not.toContain(SECRET);
		expect(JSON.stringify(h.events)).not.toContain(SECRET);
		expect(JSON.stringify(h.logs)).not.toContain(SECRET);
	});

	it("answers 500 server_error, and audits one, when core does not conclude", async () => {
		const h = harness();
		await h.seed();
		vi.spyOn(h.store, "open").mockImplementation(() => {
			throw new Error(`store exploded ${SECRET}`);
		});

		const response = await request(h.app)
			.post(path())
			.set("Authorization", basic())
			.send({ sub: SUBJECT });

		expect([500, 503]).toContain(response.status);
		expect(JSON.stringify(response.body)).not.toContain(SECRET);
	});
});

describe("the token route — correlation", () => {
	it("echoes the caller's request id on every exit, live or refused", async () => {
		const h = harness();
		await h.seed();
		for (const [body, expected] of [
			[{ sub: SUBJECT }, 200],
			[{ sub: "" }, 400],
		] as const) {
			const response = await request(h.app)
				.post(path())
				.set("Authorization", basic())
				.set("x-request-id", "job-42")
				.send(body);
			expect(response.status).toBe(expected);
			expect(response.headers["x-request-id"]).toBe("job-42");
		}
	});

	it("correlates an event written after the answer with the request that started it", async () => {
		const h = harness();
		await h.seed({ credentials: { refreshToken: SECRET, accessToken: undefined } });
		h.refresh.mockResolvedValue({
			accessToken: "fresh",
			refreshToken: `${SECRET}-2`,
			expiresIn: 3600,
			expiresAt: new Date(h.world.now.getTime() + HOUR),
			tokenType: "Bearer",
		});

		await request(h.app)
			.post(path())
			.set("Authorization", basic())
			.set("x-request-id", "job-42")
			.send({ sub: SUBJECT });

		// The refresh's tail runs after the response; the drain is what a test
		// has to wait on, exactly as a shutdown does.
		await h.background.drain();
		expect(h.events.length).toBeGreaterThan(1);
		for (const event of h.events) {
			expect(event.details?.correlationId).toBe("job-42");
		}
	});
});
