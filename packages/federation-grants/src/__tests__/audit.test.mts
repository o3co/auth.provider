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
 * Core's audit events carried to the deployment's sink (#593, D18).
 *
 * Two properties this file exists for, both of which are easy to lose:
 *
 *  1. **The sink's promise is returned**, not detached. `emitAuditEvent`
 *     swallows it (`sink.record(event).catch(…)`), which means core cannot
 *     bound its wait and a shutdown cannot drain it — the audit of a refresh
 *     that happened after the response is exactly the event that is lost when
 *     the process exits.
 *  2. **Core's omissions are preserved.** For an unknown grant, or one that
 *     was never authorized, core deliberately supplies no connection, no
 *     upstream and no scopes. Filling them in would take a second read — and
 *     for the unknown-grant case, would answer the question the identical 404
 *     exists to refuse.
 */

import type { AuditEvent, AuditSink, FederationGrantAuditEvent } from "@o3co/auth-provider-core";
import { describe, expect, it, vi } from "vitest";
import { createFederationGrantAuditBridge, routeDeniedEvent } from "#/audit.mjs";

const AT = new Date("2026-09-18T10:00:00.000Z");

/** The one event the sink was told about, or a failure that says it was not. */
const only = (record: { mock: { calls: unknown[][] } }): AuditEvent => {
	const call = record.mock.calls[0];
	if (call === undefined) throw new Error("the sink was never called");
	return call[0] as AuditEvent;
};

const sinkSpy = () => {
	const record = vi.fn(async () => undefined);
	return { sink: { kind: "test", record } as AuditSink, record };
};

const context = {
	ip: "203.0.113.7",
	userAgent: "worker/1.0",
	operation: "token" as const,
	now: () => AT,
};

const FULL: FederationGrantAuditEvent = {
	type: "federation.grant.token.success",
	correlationId: "req-1",
	grantId: "g1",
	clientId: "worker",
	subject: "local-subject",
	upstream: { issuer: "https://issuer.example", subject: "upstream-subject" },
	connection: "graph",
	resource: "https://graph.example",
	scopes: ["openid", "Files.Read"],
	outcome: "success",
};

describe("createFederationGrantAuditBridge", () => {
	it("carries every field core supplied into the sink's event", () => {
		const { sink, record } = sinkSpy();
		void createFederationGrantAuditBridge({ sink, ...context })(FULL);

		expect(record).toHaveBeenCalledTimes(1);
		expect(only(record)).toEqual({
			timestamp: AT,
			type: "federation.grant.token.success",
			subject: "local-subject",
			clientId: "worker",
			ip: "203.0.113.7",
			userAgent: "worker/1.0",
			details: {
				correlationId: "req-1",
				grantId: "g1",
				connection: "graph",
				upstream: { issuer: "https://issuer.example", subject: "upstream-subject" },
				resource: "https://graph.example",
				scopes: ["openid", "Files.Read"],
				outcome: "success",
				operation: "token",
			},
		});
	});

	it("carries the upstream identity as issuer and subject only, whatever else the event's object holds (#611)", () => {
		// Verified claims travel beside the subject into check 5 and nowhere
		// else. The bridge is its own boundary: it does not trust every caller
		// to have projected them away.
		const { sink, record } = sinkSpy();
		void createFederationGrantAuditBridge({ sink, ...context })({
			...FULL,
			upstream: {
				...FULL.upstream,
				claims: { oid: "sentinel-oid" },
			} as unknown as FederationGrantAuditEvent["upstream"],
		});
		expect((only(record).details as { upstream: unknown }).upstream).toStrictEqual({
			issuer: "https://issuer.example",
			subject: "upstream-subject",
		});
	});

	it("returns the sink's promise so core can bound it and a shutdown can drain it", async () => {
		let settle!: () => void;
		const pending = new Promise<void>((resolve) => {
			settle = resolve;
		});
		const sink = { kind: "test", record: () => pending } as unknown as AuditSink;

		const returned = createFederationGrantAuditBridge({ sink, ...context })(FULL);
		let done = false;
		void Promise.resolve(returned).then(() => {
			done = true;
		});
		await new Promise((r) => setTimeout(r, 0));
		expect(done).toBe(false);
		settle();
		await returned;
		expect(done).toBe(true);
	});

	it("keeps core's omissions rather than filling them in", () => {
		// An unknown grant has no connection, no upstream and no scopes — and
		// looking them up would answer the very question the identical 404
		// refuses to answer.
		const { sink, record } = sinkSpy();
		void createFederationGrantAuditBridge({ sink, ...context })({
			type: "federation.grant.token.denied",
			correlationId: "req-2",
			grantId: "unknown",
			clientId: "worker",
			subject: "local-subject",
			outcome: "grant_not_found",
		});
		const details = only(record).details as Record<string, unknown>;
		expect(details).not.toHaveProperty("connection");
		expect(details).not.toHaveProperty("upstream");
		expect(details).not.toHaveProperty("scopes");
		expect(details).not.toHaveProperty("resource");
	});

	it("copies the upstream and the scopes rather than holding core's own objects", () => {
		const { sink, record } = sinkSpy();
		const event = {
			...FULL,
			scopes: ["openid"],
			upstream: { ...FULL.upstream },
		} as FederationGrantAuditEvent;
		void createFederationGrantAuditBridge({ sink, ...context })(event);
		const details = only(record).details as Record<string, unknown>;
		expect(details.scopes).not.toBe(event.scopes);
		expect(details.upstream).not.toBe(event.upstream);
		expect(details.scopes).toEqual(["openid"]);
	});

	it("does nothing, and rejects nothing, when the deployment wired no sink", async () => {
		await expect(createFederationGrantAuditBridge({ ...context })(FULL)).resolves.toBeUndefined();
	});

	it("lets a failing sink be seen, because core reports what it cannot deliver", async () => {
		// Found by review. Swallowing this made the bridge resolve, so core's
		// own `audit()` helper never reached its reporting branch and an
		// operator learned nothing about a sink that was dropping everything.
		// Core already keeps an audit failure away from the HTTP answer — it
		// settles this promise and bounds it — so there is nothing for the
		// bridge to protect by hiding it.
		const rejecting = {
			kind: "test",
			record: async () => {
				throw new Error("sink is down");
			},
		} as unknown as AuditSink;
		await expect(
			createFederationGrantAuditBridge({ sink: rejecting, ...context })(FULL),
		).rejects.toThrow("sink is down");

		const throwing = {
			kind: "test",
			record: () => {
				throw new Error("sink threw");
			},
		} as unknown as AuditSink;
		await expect(
			createFederationGrantAuditBridge({ sink: throwing, ...context })(FULL),
		).rejects.toThrow("sink threw");
	});

	it("says which route the event came from, because status writes events too", () => {
		const { sink, record } = sinkSpy();
		void createFederationGrantAuditBridge({ sink, ...context, operation: "status" })({
			...FULL,
			type: "federation.grant.revoked",
			outcome: "backstop",
		});
		expect(only(record).details?.operation).toBe("status");
	});
});

describe("routeDeniedEvent", () => {
	it("is the same envelope for a denial that never reached core", () => {
		const event = routeDeniedEvent({
			correlationId: "req-3",
			grantId: "g1",
			outcome: "invalid_request",
		});
		expect(event).toMatchObject({
			type: "federation.grant.token.denied",
			correlationId: "req-3",
			grantId: "g1",
			outcome: "invalid_request",
		});
	});

	it("omits the caller and the owner rather than guessing at them", () => {
		// Before client authentication there is a Basic username and an
		// assertion `iss`, and neither has been verified. Promoting one into
		// `clientId` would put an unauthenticated caller's claim into the field
		// an operator reads as "this client did it".
		const event = routeDeniedEvent({
			correlationId: "req-3",
			grantId: "g1",
			outcome: "invalid_client",
		});
		expect(event.clientId).toBe("");
		expect(event.subject).toBe("");
	});

	it("carries the caller and owner once they have been established", () => {
		const event = routeDeniedEvent({
			correlationId: "req-4",
			grantId: "g1",
			outcome: "rate_limited/provider",
			clientId: "worker",
			subject: "local-subject",
		});
		expect(event).toMatchObject({ clientId: "worker", subject: "local-subject" });
	});
});
