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
 * What the client-authenticated routes log when something they depend on
 * cannot answer — through the real router, the real retrieval and lodging,
 * and the real in-memory stores, with a logger that records every line.
 *
 * - An outage answered `503` is ONE line, at error, object-first, naming what
 *   failed (`store`, `step`, or the `reason` core answered) with the error's
 *   projection (`err`) — never a warn, and never a second line for it.
 * - A failure that changed no answer is one structured warn.
 * - Contention — another replica holds the refresh, or won the write — is a
 *   warn: it answers 503, and nothing is down.
 * - Client authentication and the throttle log through core, with the
 *   deployment's own logger: the projection, not a redaction of it.
 */

import type { Request } from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { unexpectedErrors } from "#/routes.mjs";
import {
	basic,
	CLIENT_ID,
	connection,
	GRANT_ID,
	harness,
	REDIRECT_URI,
	SUBJECT,
} from "./harness.mjs";
import { createLogSpy, payloadOf, written } from "./logSpy.mjs";

type H = ReturnType<typeof harness>;

const REQUEST_ID = "job-1";

const call = (h: H, operation: "token" | "status" | "revoke", id = GRANT_ID) =>
	request(h.app)
		.post(`/oauth/federation-grants/${id}/${operation}`)
		.set("Authorization", basic())
		.set("x-request-id", REQUEST_ID)
		.send({ sub: SUBJECT });

const lodge = (h: H, body: Record<string, unknown> = {}) =>
	request(h.app)
		.post("/oauth/federation-grants")
		.set("Authorization", basic())
		.set("x-request-id", REQUEST_ID)
		.send({
			connection: connection.name,
			sub: SUBJECT,
			redirect_uri: REDIRECT_URI,
			state: "client-state-1",
			...body,
		});

const renew = (h: H) =>
	request(h.app)
		.post(`/oauth/federation-grants/${GRANT_ID}/reauthorize`)
		.set("Authorization", basic())
		.set("x-request-id", REQUEST_ID)
		.send({ sub: SUBJECT, redirect_uri: REDIRECT_URI, state: "client-state-2" });

/** Every line once the work an answer handed over has finished. */
const settled = async (h: H) => {
	await h.background.drain();
	return h.lines;
};

/** A grant whose access token has run out: a token request refreshes it. */
const seedExpired = (h: H) =>
	h.seed({ credentials: { refreshToken: "rt", accessToken: undefined } });

describe("the token route", () => {
	it("logs a grant store that cannot be read as one error line, with what failed and its projection", async () => {
		const h = harness();
		await h.seed();
		vi.spyOn(h.store, "open").mockRejectedValue(new Error("grant store down"));
		const response = await call(h, "token");
		expect(response.status).toBe(503);
		expect(response.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "storage",
		});
		expect(written(await settled(h))).toEqual(["error federation_grant_token_unavailable"]);
		expect(payloadOf(h.lines, "federation_grant_token_unavailable")).toEqual({
			grantId: GRANT_ID,
			correlationId: REQUEST_ID,
			reason: "storage",
			store: "federation_grant",
			step: "open",
			err: expect.objectContaining({ name: "Error", detail: "grant store down" }),
		});
	});

	it("names the revocation boundary when that is what could not be read", async () => {
		const h = harness();
		await h.seed();
		h.world.boundary = new Error("boundary down");
		expect((await call(h, "token")).status).toBe(503);
		expect(written(await settled(h))).toEqual(["error federation_grant_token_unavailable"]);
		expect(payloadOf(h.lines, "federation_grant_token_unavailable")).toMatchObject({
			reason: "storage",
			store: "revocation_boundary",
			step: "boundary",
			err: { name: "Error", detail: "boundary down" },
		});
	});

	it("logs a key missing from the ring at error, with nothing thrown to project", async () => {
		const h = harness();
		await h.seed();
		const opened = await h.store.open(GRANT_ID, h.world.now);
		vi.spyOn(h.store, "open").mockResolvedValue({
			grant: opened?.grant as never,
			credentials: { state: "key_unavailable" },
		});
		const response = await call(h, "token");
		expect(response.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "key_unavailable",
		});
		expect(written(await settled(h))).toEqual(["error federation_grant_token_unavailable"]);
		const payload = payloadOf(h.lines, "federation_grant_token_unavailable");
		expect(payload).toEqual({
			grantId: GRANT_ID,
			correlationId: REQUEST_ID,
			reason: "key_unavailable",
		});
	});

	it("logs an upstream that could not be reached as the outage, with the error's projection and cause", async () => {
		const h = harness();
		await seedExpired(h);
		h.refresh.mockRejectedValue(
			Object.assign(new TypeError("fetch failed"), {
				cause: Object.assign(new Error("connect ECONNREFUSED"), { code: "ECONNREFUSED" }),
			}),
		);
		const response = await call(h, "token");
		expect(response.status).toBe(503);
		expect(response.body.error_description).toBe("upstream");
		expect(written(await settled(h))).toEqual(["error federation_grant_token_unavailable"]);
		expect(payloadOf(h.lines, "federation_grant_token_unavailable")).toMatchObject({
			reason: "upstream",
			step: "upstream",
			err: { name: "TypeError", cause: { name: "Error", code: "ECONNREFUSED" } },
		});
	});

	it("logs an upstream's refusal as one warn: it answered, and nothing is down", async () => {
		const h = harness();
		await seedExpired(h);
		h.refresh.mockRejectedValue(
			Object.assign(new Error("refused"), { error: "invalid_client", status: 401 }),
		);
		const response = await call(h, "token");
		expect(response.status).toBe(502);
		expect(written(await settled(h))).toEqual(["warn federation_grant_token_step_failed"]);
		expect(payloadOf(h.lines, "federation_grant_token_step_failed")).toMatchObject({
			grantId: GRANT_ID,
			correlationId: REQUEST_ID,
			step: "upstream",
			err: { name: "Error", error: "invalid_client", status: 401 },
		});
	});

	it("logs a refresh another replica holds as contention, at warn", async () => {
		const h = harness();
		await seedExpired(h);
		vi.spyOn(h.store, "acquireRefreshLock").mockResolvedValue({
			acquired: false,
			reason: "timeout",
		});
		const response = await call(h, "token");
		expect(response.status).toBe(503);
		expect(response.body.error_description).toBe("lock_timeout");
		expect(written(await settled(h))).toEqual(["warn federation_grant_token_contended"]);
		expect(payloadOf(h.lines, "federation_grant_token_contended")).toEqual({
			grantId: GRANT_ID,
			correlationId: REQUEST_ID,
			reason: "lock_timeout",
		});
	});

	it("logs a failure the answer did not need as one warn", async () => {
		// Revoked: answered from the record, whatever the boundary says.
		const h = harness();
		await h.seed();
		await h.store.revoke(GRANT_ID, "client", h.world.now);
		h.world.boundary = new Error("boundary down");
		expect((await call(h, "token")).status).toBe(410);
		expect(written(await settled(h))).toEqual(["warn federation_grant_token_step_failed"]);
		expect(payloadOf(h.lines, "federation_grant_token_step_failed")).toMatchObject({
			step: "boundary",
			store: "revocation_boundary",
			err: { name: "Error", detail: "boundary down" },
		});
	});

	it("logs work that failed after the answer as one warn", async () => {
		const h = harness();
		await h.seed();
		vi.spyOn(h.store, "touch").mockRejectedValue(new Error("touch down"));
		expect((await call(h, "token")).status).toBe(200);
		expect(written(await settled(h))).toEqual(["warn federation_grant_token_step_failed"]);
		expect(payloadOf(h.lines, "federation_grant_token_step_failed")).toMatchObject({
			step: "touch",
			err: { name: "Error", detail: "touch down" },
		});
	});

	it("logs what core could not conclude as an unexpected error, at error", async () => {
		const h = harness();
		await h.seed();
		h.world.connections.get = () => {
			throw new Error("configuration unreadable");
		};
		expect((await call(h, "token")).status).toBe(500);
		expect(written(await settled(h))).toEqual(["error federation_grants_unexpected_error"]);
		expect(payloadOf(h.lines, "federation_grants_unexpected_error")).toMatchObject({
			site: "token",
			grantId: GRANT_ID,
			correlationId: REQUEST_ID,
			err: { name: "Error", detail: "configuration unreadable" },
		});
	});
});

describe("the status route", () => {
	it("logs a grant store that cannot be read as one error line", async () => {
		const h = harness();
		await h.seed();
		vi.spyOn(h.store, "inspect").mockRejectedValue(new Error("grant store down"));
		expect((await call(h, "status")).status).toBe(503);
		expect(written(await settled(h))).toEqual(["error federation_grant_status_unavailable"]);
		expect(payloadOf(h.lines, "federation_grant_status_unavailable")).toEqual({
			grantId: GRANT_ID,
			correlationId: REQUEST_ID,
			reason: "storage",
			store: "federation_grant",
			step: "inspect",
			err: expect.objectContaining({ name: "Error", detail: "grant store down" }),
		});
	});

	it("logs a boundary the answer needed as the outage, once", async () => {
		const h = harness();
		await h.seed();
		h.world.boundary = new Error("boundary down");
		expect((await call(h, "status")).status).toBe(503);
		expect(written(await settled(h))).toEqual(["error federation_grant_status_unavailable"]);
		expect(payloadOf(h.lines, "federation_grant_status_unavailable")).toMatchObject({
			reason: "storage",
			store: "revocation_boundary",
			step: "read",
			err: { name: "Error", detail: "boundary down" },
		});
	});

	it("logs a boundary the answer did not need as one warn", async () => {
		const h = harness();
		await h.seed();
		await h.store.revoke(GRANT_ID, "client", h.world.now);
		h.world.boundary = new Error("boundary down");
		expect((await call(h, "status")).status).toBe(200);
		expect(written(await settled(h))).toEqual(["warn federation_grant_status_step_failed"]);
		expect(payloadOf(h.lines, "federation_grant_status_step_failed")).toMatchObject({
			store: "revocation_boundary",
			step: "read",
			err: { name: "Error", detail: "boundary down" },
		});
	});

	it("logs a key missing from the ring, which it used to answer in silence", async () => {
		const h = harness();
		await h.seed();
		h.world.credentials = "key_unavailable";
		const response = await call(h, "status");
		expect(response.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "key_unavailable",
		});
		expect(written(await settled(h))).toEqual(["error federation_grant_status_unavailable"]);
		expect(payloadOf(h.lines, "federation_grant_status_unavailable")).toEqual({
			grantId: GRANT_ID,
			correlationId: REQUEST_ID,
			reason: "key_unavailable",
		});
	});

	it("logs a backstop it could not write down", async () => {
		const h = harness();
		await h.seed();
		h.world.boundary = new Date(h.world.now.getTime() + 1);
		h.world.now = new Date(h.world.now.getTime() + 10 * 60_000);
		vi.spyOn(h.store, "revoke").mockRejectedValue(new Error("write refused"));
		expect((await call(h, "status")).status).toBe(503);
		expect(written(await settled(h))).toEqual(["error federation_grant_status_unavailable"]);
		expect(payloadOf(h.lines, "federation_grant_status_unavailable")).toMatchObject({
			store: "federation_grant",
			step: "revoke",
			err: { name: "Error", detail: "write refused" },
		});
	});
});

describe("the revoke route", () => {
	it("logs the read and the write that could not be made, each as one error line", async () => {
		for (const [method, step] of [
			["find", "find"],
			["revoke", "revoke"],
		] as const) {
			const h = harness();
			await h.seed();
			vi.spyOn(h.store, method).mockRejectedValue(new Error(`${method} down`));
			expect((await call(h, "revoke")).status).toBe(503);
			expect(written(await settled(h))).toEqual(["error federation_grant_revoke_unavailable"]);
			expect(payloadOf(h.lines, "federation_grant_revoke_unavailable")).toEqual({
				grantId: GRANT_ID,
				correlationId: REQUEST_ID,
				reason: "storage",
				store: "federation_grant",
				step,
				err: expect.objectContaining({ name: "Error", detail: `${method} down` }),
			});
		}
	});
});

describe("the lodging routes", () => {
	it("logs the store that could not admit the intent, with the error core now carries", async () => {
		const h = harness();
		vi.spyOn(h.intents, "putIntent").mockRejectedValue(new Error("intent store down"));
		expect((await lodge(h)).status).toBe(503);
		expect(written(await settled(h))).toEqual(["error federation_grant_lodge_unavailable"]);
		expect(payloadOf(h.lines, "federation_grant_lodge_unavailable")).toEqual({
			operation: "create",
			correlationId: REQUEST_ID,
			reason: "storage",
			store: "federation_grant_intent",
			step: "put_intent",
			err: expect.objectContaining({ name: "Error", detail: "intent store down" }),
		});
	});

	it("logs the outage at error and an intent it could not close after it as one warn", async () => {
		const h = harness();
		vi.spyOn(h.store, "createPending").mockRejectedValue(new Error("grant store down"));
		vi.spyOn(h.intents, "finishIntent").mockRejectedValue(new Error("close failed"));
		expect((await lodge(h)).status).toBe(503);
		expect(written(await settled(h))).toEqual([
			"error federation_grant_lodge_unavailable",
			"warn federation_grant_lodge_step_failed",
		]);
		expect(payloadOf(h.lines, "federation_grant_lodge_unavailable")).toMatchObject({
			store: "federation_grant",
			step: "create_pending",
			err: { name: "Error", detail: "grant store down" },
		});
		expect(payloadOf(h.lines, "federation_grant_lodge_step_failed")).toMatchObject({
			operation: "create",
			store: "federation_grant_intent",
			step: "finish_intent",
			err: { name: "Error", detail: "close failed" },
		});
	});

	it("logs a connection that is permitted but not configured: a 503 the deployment must fix", async () => {
		const h = harness();
		h.world.allowedConnections = [connection.name, "retired"];
		const response = await lodge(h, { connection: "retired" });
		expect(response.status).toBe(503);
		expect(written(await settled(h))).toEqual(["error federation_grant_lodge_unavailable"]);
		expect(payloadOf(h.lines, "federation_grant_lodge_unavailable")).toEqual({
			operation: "create",
			correlationId: REQUEST_ID,
			reason: "connection_not_configured",
			connection: "retired",
		});
	});

	it("logs an intent it could not close after a lost renewal as one warn, whatever the answer", async () => {
		// The pointer write lost to a revocation, and the intent it named could
		// not be closed: the answer is the grant's (410 grant_revoked), and the
		// intent — which can activate nothing, and lapses with the flow budget —
		// is one warn, where it used to be nothing.
		const h = harness();
		await h.seed();
		const revoke = h.store.revoke.bind(h.store);
		vi.spyOn(h.store, "nameIntent").mockImplementation(async () => {
			await revoke(GRANT_ID, "subject", h.world.now);
			throw new Error("connection reset");
		});
		vi.spyOn(h.intents, "finishIntent").mockRejectedValue(new Error("close failed"));
		const response = await renew(h);
		expect(response.status).toBe(410);
		expect(response.body).toEqual({ error: "grant_revoked", error_description: "subject" });
		expect(written(await settled(h))).toEqual(["warn federation_grant_lodge_step_failed"]);
		expect(payloadOf(h.lines, "federation_grant_lodge_step_failed")).toEqual({
			operation: "reauthorize",
			grantId: GRANT_ID,
			correlationId: REQUEST_ID,
			store: "federation_grant_intent",
			step: "finish_intent",
			err: expect.objectContaining({ name: "Error", detail: "close failed" }),
		});
	});

	it("logs a renewal's key missing from the ring", async () => {
		const h = harness();
		await h.seed();
		h.world.credentials = "key_unavailable";
		expect((await renew(h)).status).toBe(503);
		expect(written(await settled(h))).toEqual(["error federation_grant_lodge_unavailable"]);
		expect(payloadOf(h.lines, "federation_grant_lodge_unavailable")).toEqual({
			operation: "reauthorize",
			grantId: GRANT_ID,
			correlationId: REQUEST_ID,
			reason: "key_unavailable",
		});
	});
});

describe("what the router mounts in front of the handlers", () => {
	it("logs a client repository that cannot answer through core's one line, unredacted", async () => {
		const h = harness();
		h.world.clientRepositoryDown = new Error("client registry down");
		const response = await call(h, "token");
		expect(response.status).toBe(503);
		expect(written(await settled(h))).toEqual(["error client_repository_unavailable"]);
		expect(payloadOf(h.lines, "client_repository_unavailable")).toEqual({
			site: "federation_grants",
			step: "find",
			clientId: CLIENT_ID,
			err: expect.objectContaining({ name: "Error", detail: "client registry down" }),
		});
	});

	it("hands the throttle the deployment's own logger and audit sink", async () => {
		const h = harness({
			rateLimiter: {
				kind: "down",
				check: async () => {
					throw new Error("limiter down");
				},
			},
		});
		expect((await call(h, "token")).status).toBe(503);
		expect(written(await settled(h))).toEqual(["error rate_limiter_failed_closed"]);
		expect(payloadOf(h.lines, "rate_limiter_failed_closed")).toMatchObject({
			tag: "federation_grants",
			error: "limiter down",
		});
		expect(h.events.find((event) => event.type === "rate_limit.unavailable")?.details).toEqual({
			tag: "federation_grants",
			cause: { name: "Error" },
		});
	});

	it("logs what escaped every handler with the error's projection", () => {
		const { logger, lines } = createLogSpy();
		const headers: Record<string, string> = { "x-request-id": REQUEST_ID };
		const res = {
			headersSent: false,
			status: () => res,
			json: () => res,
			getHeader: (name: string) => headers[name],
		};
		unexpectedErrors(logger)(
			Object.assign(new Error("store 403"), { expose: true, status: 403 }),
			{} as Request,
			res as never,
			() => undefined,
		);
		expect(written(lines)).toEqual(["error federation_grants_unexpected_error"]);
		expect(payloadOf(lines, "federation_grants_unexpected_error")).toEqual({
			correlationId: REQUEST_ID,
			err: expect.objectContaining({ name: "Error", detail: "store 403", status: 403 }),
		});
	});
});
