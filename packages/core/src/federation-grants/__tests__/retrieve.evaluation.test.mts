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
import { retrieveFederationGrantToken } from "#/federation-grants/retrieve.mjs";
import {
	at,
	CONSENTED,
	connection,
	DAY,
	type Harness,
	harness,
	MIN,
	now,
	refreshed,
	request,
	SCOPES,
	SECRET,
	setNow,
	T0,
} from "./retrieve.harness.mjs";

describe("retrieveFederationGrantToken — what is evaluated before any token (#593, D10, D11)", () => {
	let h: Harness;

	beforeEach(() => {
		vi.useFakeTimers();
		setNow(T0);
		h = harness();
	});

	afterEach(() => {
		vi.useRealTimers();
	});

	const retrieve = (over: Partial<typeof request> = {}) =>
		retrieveFederationGrantToken(h.deps, { ...request, ...over });

	describe("a grant that is not the caller's", () => {
		it("answers the same for an unknown ID, another client's grant and another subject's: a known ID tells a stranger nothing", async () => {
			await h.seed();
			const unknown = await retrieve({ grantId: "g-unknown" });
			const otherClient = await retrieve({ clientId: "someone-else" });
			const otherSubject = await retrieve({ subject: "u-2" });

			expect(unknown).toStrictEqual({ ok: false, code: "grant_not_found" });
			expect(otherClient).toStrictEqual(unknown);
			expect(otherSubject).toStrictEqual(unknown);
			expect(h.refresh).not.toHaveBeenCalled();
		});

		it("answers not-found even while the subject's boundary cannot be read: an outage must not tell a stranger that the grant exists", async () => {
			await h.seed();
			h.world.boundary = new Error("redis down");
			expect(await retrieve({ clientId: "someone-else" })).toStrictEqual({
				ok: false,
				code: "grant_not_found",
			});
		});
	});

	describe("the stored token", () => {
		it("is disclosed while it has more life left than the refresh buffer, with what it carries", async () => {
			await h.seed();
			setNow(at(10 * MIN));
			expect(await retrieve()).toStrictEqual({
				ok: true,
				accessToken: "at-0",
				tokenType: "Bearer",
				expiresIn: 3000,
				scopes: [...SCOPES],
				refreshed: false,
			});
			expect(h.refresh).not.toHaveBeenCalled();
		});

		it("records the use, and does not fail the call when that cannot be recorded", async () => {
			await h.seed();
			setNow(at(10 * MIN));
			await retrieve();
			expect(await h.store.find("g-1", at(10 * MIN))).toHaveProperty("lastUsedAt", at(10 * MIN));

			vi.spyOn(h.store, "touch").mockRejectedValue(new Error("redis down"));
			expect((await retrieve()).ok).toBe(true);
		});

		it("clamps expires_in to what is left of the grant: a cache hint for a cooperating worker (D15)", async () => {
			await h.seed({ expiresAt: at(20 * MIN) });
			setNow(at(10 * MIN));
			expect(await retrieve()).toMatchObject({ ok: true, expiresIn: 600 });
		});

		it("clamps expires_in to the operator's maximum too, when that is what ends the grant first", async () => {
			await h.seed();
			h.deps.limits = { ...h.deps.limits, maxExpiresInMs: 15 * MIN };
			setNow(at(10 * MIN));
			expect(await retrieve()).toMatchObject({ ok: true, expiresIn: 300 });
		});

		it("is not disclosed when it is not a bearer token, however it got stored", async () => {
			await h.seed({
				credentials: {
					refreshToken: SECRET,
					accessToken: {
						value: "at-dpop",
						tokenType: "DPoP",
						obtainedAt: T0,
						issuedLifetime: 3600,
						scopes: [...SCOPES],
					},
				},
			});
			h.refresh.mockResolvedValue(refreshed("1", now()));
			setNow(at(MIN));
			expect(await retrieve()).toMatchObject({ ok: true, accessToken: "at-1", refreshed: true });
		});

		it("is judged against the CURRENT maximum: a cached token does not become disclosable by ageing", async () => {
			await h.seed();
			h.world.connections.set(connection.name, { ...connection, maxAccessTokenLifetime: 1800 });
			setNow(at(45 * MIN));
			h.refresh.mockRejectedValue(Object.assign(new Error("down"), { status: 503 }));
			// 15 minutes are left of a token issued for 60: under the lowered
			// maximum it is not disclosed, and a refresh is attempted instead.
			expect(await retrieve()).toMatchObject({ ok: false, code: "temporarily_unavailable" });
			expect(h.refresh).toHaveBeenCalledTimes(1);
		});
	});

	describe("the order of reporting — from what cannot be undone to what can", () => {
		it("reports a stored revocation, whatever else is wrong", async () => {
			await h.seed();
			await h.store.revoke("g-1", "subject", at(MIN));
			h.world.connections.clear();
			h.world.boundary = new Error("redis down");
			setNow(at(40 * DAY));
			// Not 403 for the connection, not 503 for the boundary, not expired.
			expect(await retrieve({ allowedConnections: [] })).toStrictEqual({
				ok: false,
				code: "grant_revoked",
				reason: "subject",
			});
		});

		it("reports a grant the user has not finished connecting", async () => {
			await h.store.createPending({
				id: "g-1",
				subject: "u-1",
				clientId: "agent",
				connection: connection.name,
				intent: { handle: "h-1", expiresAt: at(10 * MIN) },
				now: T0,
			});
			expect(await retrieve()).toStrictEqual({ ok: false, code: "authorization_pending" });
		});

		it("answers 503 when the subject's boundary cannot be read: the backstop fails closed", async () => {
			await h.seed();
			h.world.boundary = new Error("redis down");
			expect(await retrieve()).toStrictEqual({
				ok: false,
				code: "temporarily_unavailable",
				reason: "storage",
			});
		});

		it("answers 503 when the store cannot be read", async () => {
			await h.seed();
			vi.spyOn(h.store, "open").mockRejectedValue(new Error("redis down"));
			expect(await retrieve()).toStrictEqual({
				ok: false,
				code: "temporarily_unavailable",
				reason: "storage",
			});
		});

		it("makes the backstop durable on the first touch, and reports it before a mere expiry", async () => {
			await h.seed();
			h.world.boundary = at(MIN);
			setNow(at(40 * DAY));
			expect(await retrieve()).toStrictEqual({
				ok: false,
				code: "grant_revoked",
				reason: "backstop",
			});
			expect(await h.store.find("g-1", at(40 * DAY))).toMatchObject({
				status: "revoked",
				revocation: { by: "backstop" },
			});
			expect(h.store.holdsCredential("g-1")).toBe(false);
		});

		it("surfaces a backstop revocation that could not be written: a revocation outage is not answered as a revocation (D13)", async () => {
			await h.seed();
			h.world.boundary = at(MIN);
			vi.spyOn(h.store, "revoke").mockRejectedValue(new Error("redis down"));
			expect(await retrieve()).toStrictEqual({
				ok: false,
				code: "temporarily_unavailable",
				reason: "storage",
			});
		});

		it("still reports the backstop when someone else has revoked the grant meanwhile", async () => {
			await h.seed();
			h.world.boundary = at(MIN);
			vi.spyOn(h.store, "revoke").mockResolvedValue({ ok: false });
			expect(await retrieve()).toMatchObject({ code: "grant_revoked", reason: "backstop" });
		});

		it("reports an expiry, and which bound it was", async () => {
			await h.seed();
			setNow(at(30 * DAY));
			expect(await retrieve()).toStrictEqual({
				ok: false,
				code: "grant_expired",
				reason: "consented_lifetime",
			});

			h.deps.limits = { ...h.deps.limits, maxExpiresInMs: 10 * DAY };
			setNow(at(20 * DAY));
			expect(await retrieve()).toStrictEqual({
				ok: false,
				code: "grant_expired",
				reason: "operator_maximum",
			});
		});

		it("refuses a connection the client may not use, and one the operator removed, only after what is terminal", async () => {
			await h.seed();
			const denied = { ok: false, code: "access_denied", reason: "connection_not_permitted" };
			expect(await retrieve({ allowedConnections: ["another"] })).toStrictEqual(denied);

			h.world.connections.clear();
			expect(await retrieve()).toStrictEqual(denied);

			setNow(at(30 * DAY));
			expect(await retrieve({ allowedConnections: ["another"] })).toMatchObject({
				code: "grant_expired",
			});
		});

		it("reports a changed upstream identity as terminal, and any other connection change as a reauthorization", async () => {
			await h.seed();
			h.world.connections.set(connection.name, { ...connection, upstreamClientId: "0oa-rotated" });
			expect(await retrieve()).toStrictEqual({ ok: false, code: "connection_identity_changed" });

			h.world.connections.set(connection.name, { ...connection, boundary: "staging" });
			expect(await retrieve()).toStrictEqual({
				ok: false,
				code: "reauthorization_required",
				reason: "connection_changed",
			});
		});

		it("reports a grant whose credentials are gone or do not open as needing the user", async () => {
			const grant = await h.seed();
			await h.store.requireReauthorization({
				grantId: "g-1",
				expectedVersion: grant.version,
				now: T0,
			});
			expect(await retrieve()).toStrictEqual({
				ok: false,
				code: "reauthorization_required",
				reason: "upstream_invalid_grant",
			});
		});

		it("answers 503 for a key that is not in the ring, and keeps the record: an outage is not a status (D16)", async () => {
			const grant = await h.seed();
			vi.spyOn(h.store, "open").mockResolvedValue({
				grant,
				credentials: { state: "key_unavailable" },
			});
			expect(await retrieve()).toStrictEqual({
				ok: false,
				code: "temporarily_unavailable",
				reason: "key_unavailable",
			});

			vi.spyOn(h.store, "open").mockResolvedValue({ grant, credentials: { state: "unreadable" } });
			expect(await retrieve()).toStrictEqual({
				ok: false,
				code: "reauthorization_required",
				reason: "credential_unreadable",
			});
		});
	});

	describe("what the request asserts", () => {
		it("refuses an asserted connection, resource or scope the grant does not have, without an upstream call", async () => {
			await h.seed();
			// Half spent: a request the stored token cannot serve goes on to a
			// refresh from here, and one that can never succeed must not.
			setNow(at(30 * MIN));
			expect(await retrieve({ connection: "another" })).toStrictEqual({
				ok: false,
				code: "invalid_request",
				reason: "connection_mismatch",
			});
			expect(await retrieve({ resource: "https://files.example/" })).toStrictEqual({
				ok: false,
				code: "invalid_target",
			});
			expect(await retrieve({ scope: ["calendar.read", "files.readwrite"] })).toStrictEqual({
				ok: false,
				code: "invalid_scope",
			});
			const outOfRange = { ok: false, code: "invalid_request", reason: "min_ttl_out_of_range" };
			expect(await retrieve({ minTtlSeconds: 3601 })).toStrictEqual(outOfRange);
			for (const bad of [Number.NaN, -1, Number.POSITIVE_INFINITY, "60" as unknown as number]) {
				expect(await retrieve({ minTtlSeconds: bad })).toStrictEqual(outOfRange);
			}
			expect(h.refresh).not.toHaveBeenCalled();
		});

		it("accepts assertions the grant satisfies", async () => {
			await h.seed();
			expect(
				await retrieve({
					connection: connection.name,
					scope: ["calendar.read"],
					minTtlSeconds: 60,
				}),
			).toMatchObject({ ok: true, accessToken: "at-0" });
		});

		it("checks an asserted scope against what the TOKEN carries, not against what the grant once got", async () => {
			await h.seed({
				credentials: {
					refreshToken: SECRET,
					accessToken: {
						value: "at-narrow",
						tokenType: "Bearer",
						obtainedAt: T0,
						issuedLifetime: 3600,
						scopes: ["openid"],
					},
				},
			});
			h.refresh.mockRejectedValue(Object.assign(new Error("down"), { status: 503 }));
			// Half spent: before that it is answered `invalid_scope` without asking
			// the upstream, which has only just left the scope out.
			setNow(at(30 * MIN));
			// The stored token lacks the scope: it is not disclosed for this
			// request, and a refresh is what may bring one that has it.
			expect(await retrieve({ scope: ["calendar.read"] })).toMatchObject({
				ok: false,
				code: "temporarily_unavailable",
			});
			expect(h.refresh).toHaveBeenCalledTimes(1);
		});
	});

	describe("an upstream that stopped issuing eligible tokens", () => {
		const starve = async () => {
			const grant = await h.seed();
			await h.store.replaceCredentials({
				grantId: "g-1",
				expectedVersion: grant.version,
				credentials: { refreshToken: SECRET, accessToken: undefined },
				ineligible: { reason: "scope_exceeded", at: at(MIN), judgedAgainst: 3600 },
				now: at(MIN),
			});
		};

		it("is answered from the marker until the retry interval has passed, without an upstream call", async () => {
			await starve();
			setNow(at(2 * MIN));
			expect(await retrieve()).toStrictEqual({
				ok: false,
				code: "upstream_token_ineligible",
				reason: "scope_exceeded",
				retryAfterSeconds: 240,
			});
			expect(h.refresh).not.toHaveBeenCalled();
		});

		it("is tried again once the interval has passed: the marker must not make recovery unreachable", async () => {
			await starve();
			setNow(at(6 * MIN));
			h.refresh.mockRejectedValue(Object.assign(new Error("down"), { status: 503 }));
			await retrieve();
			expect(h.refresh).toHaveBeenCalledTimes(1);
		});

		it("is never asked at all under a maximum no token can satisfy", async () => {
			await h.seed();
			h.world.connections.set(connection.name, {
				...connection,
				maxAccessTokenLifetime: Number.NaN,
			});
			expect(await retrieve()).toStrictEqual({
				ok: false,
				code: "upstream_token_ineligible",
				reason: "lifetime_over_maximum",
			});
			expect(h.refresh).not.toHaveBeenCalled();
		});
	});

	describe("an outage masks nothing that is decided without what failed", () => {
		it("reports a pending grant while the boundary cannot be read", async () => {
			await h.store.createPending({
				id: "g-1",
				subject: "u-1",
				clientId: "agent",
				connection: connection.name,
				intent: { handle: "h-1", expiresAt: at(10 * MIN) },
				now: T0,
			});
			h.world.boundary = new Error("redis down");
			expect(await retrieve()).toStrictEqual({ ok: false, code: "authorization_pending" });
		});

		it("answers 503 for a boundary that is not a date, and tells the composer's logger why", async () => {
			await h.seed();
			const reported: unknown[] = [];
			h.deps.report = (failure) => reported.push(failure);
			h.world.boundary = new Date(Number.NaN);
			expect(await retrieve()).toStrictEqual({
				ok: false,
				code: "temporarily_unavailable",
				reason: "storage",
			});
			expect(reported).toMatchObject([
				{ during: "status", grantId: "g-1", correlationId: "req-1" },
			]);

			h.world.boundary = new Error("redis down");
			await retrieve();
			expect(reported[1]).toMatchObject({ during: "boundary", error: h.world.boundary });
		});

		it("reports the backstop, and an expiry, under a key that is missing from the ring: neither needs the credential", async () => {
			await h.seed();
			const real = h.store.open.bind(h.store);
			vi.spyOn(h.store, "open").mockImplementation(async (id, at) => {
				const opened = await real(id, at);
				return opened === null
					? null
					: { grant: opened.grant, credentials: { state: "key_unavailable" } };
			});

			expect(await retrieve()).toMatchObject({
				code: "temporarily_unavailable",
				reason: "key_unavailable",
			});

			h.world.connections.clear();
			expect(await retrieve()).toMatchObject({
				code: "access_denied",
				reason: "connection_not_permitted",
			});
			// A changed connection needs no credential either: the missing key is
			// answered only where the credential is what the answer turns on.
			h.world.connections.set(connection.name, { ...connection, boundary: "staging" });
			expect(await retrieve()).toMatchObject({
				code: "reauthorization_required",
				reason: "connection_changed",
			});
			h.world.connections.set(connection.name, connection);

			setNow(at(30 * DAY));
			expect(await retrieve()).toMatchObject({ code: "grant_expired" });

			setNow(at(DAY));
			h.world.boundary = at(MIN);
			expect(await retrieve()).toMatchObject({ code: "grant_revoked", reason: "backstop" });
			expect((await real("g-1", at(DAY)))?.grant.status).toBe("revoked");
		});
	});

	describe("the order of the two reads, and of the clock", () => {
		it("reads the record LAST: a revocation that lands while the boundary is being read is seen", async () => {
			await h.seed();
			h.deps.grantsBoundary = async () => {
				await h.store.revoke("g-1", "client", now());
				return null;
			};
			expect(await retrieve()).toStrictEqual({
				ok: false,
				code: "grant_revoked",
				reason: "client",
			});
		});

		it("samples the time AFTER the reads: a grant that expires while they are made has expired", async () => {
			await h.seed({ expiresAt: at(10 * MIN) });
			setNow(at(10 * MIN - 2_000));
			h.deps.grantsBoundary = async () => {
				await new Promise((resolve) => setTimeout(resolve, 5_000));
				return null;
			};
			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(5_000);
			expect(await answer).toStrictEqual({
				ok: false,
				code: "grant_expired",
				reason: "consented_lifetime",
			});
		});

		it("rounds expires_in down: a worker told a second too many caches a dead token", async () => {
			await h.seed();
			setNow(at(10 * MIN + 500));
			expect(await retrieve()).toMatchObject({ ok: true, expiresIn: 2999 });
		});

		it("refreshes a token whose remaining life only EQUALS the buffer: it has to exceed it", async () => {
			await h.seed();
			h.refresh.mockRejectedValue(Object.assign(new Error("down"), { status: 503 }));
			setNow(at(60 * MIN - 30_001));
			expect((await retrieve()).ok).toBe(true);
			expect(h.refresh).not.toHaveBeenCalled();
			setNow(at(60 * MIN - 30_000));
			// The refresh fails, and the token that ran down is answered as it is.
			expect((await retrieve()).ok).toBe(true);
			expect(h.refresh).toHaveBeenCalledTimes(1);
		});
	});

	describe("the backstop, where the connection is not the client's to use", () => {
		it("still answers 410, and is still made durable: a configuration remedy is not offered for a grant that is over", async () => {
			await h.seed();
			h.world.boundary = at(MIN);
			h.world.connections.clear();
			expect(await retrieve({ allowedConnections: [] })).toStrictEqual({
				ok: false,
				code: "grant_revoked",
				reason: "backstop",
			});
			expect((await h.store.find("g-1", now()))?.status).toBe("revoked");
			await Promise.all(h.background);
			expect(h.events.map((event) => `${event.type} ${event.outcome}`)).toEqual([
				"federation.grant.revoked backstop",
				"federation.grant.token.denied grant_revoked/backstop",
			]);
		});
	});

	describe("what is judged against the consent, and what against the grant", () => {
		it("discloses a stored token that carries a consented scope the upstream had not granted at first", async () => {
			// An IdP that accumulates consent adds it later. It is within what the
			// user agreed to, so it is eligible — the grant's own scopes are not the
			// measure of that.
			await h.seed({
				credentials: {
					refreshToken: SECRET,
					accessToken: {
						value: "at-wide",
						tokenType: "Bearer",
						obtainedAt: T0,
						issuedLifetime: 3600,
						scopes: [...CONSENTED],
					},
				},
			});
			setNow(at(10 * MIN));
			expect(await retrieve({ scope: ["calendar.write"] })).toMatchObject({
				ok: true,
				accessToken: "at-wide",
				scopes: [...CONSENTED],
			});
		});
	});

	describe("what the audit sink is told", () => {
		it("the grant's details for its owner, and nothing of them for a stranger's probe", async () => {
			await h.seed();
			await retrieve({ scope: ["files.readwrite"] });
			await retrieve({ clientId: "someone-else" });
			await Promise.all(h.background);
			expect(h.events).toStrictEqual([
				{
					type: "federation.grant.token.denied",
					correlationId: "req-1",
					grantId: "g-1",
					clientId: "agent",
					subject: "u-1",
					connection: "okta-calendar",
					upstream: { issuer: "https://dev-1.okta.test", subject: "00u-alice" },
					scopes: [...SCOPES],
					outcome: "invalid_scope",
				},
				{
					type: "federation.grant.token.denied",
					correlationId: "req-1",
					grantId: "g-1",
					clientId: "someone-else",
					subject: "u-1",
					outcome: "grant_not_found",
				},
			]);
		});
	});

	it("never puts a long-lived secret in a denial or an audit event (D18)", async () => {
		await h.seed();
		const results = [
			await retrieve({ grantId: "g-unknown" }),
			await retrieve({ scope: ["files.readwrite"] }),
			await retrieve(),
		];
		expect(results[2]).toMatchObject({ ok: true });
		expect(JSON.stringify(results.filter((result) => !result.ok))).not.toContain(SECRET);
		expect(h.events.length).toBeGreaterThan(0);
		expect(JSON.stringify(h.events)).not.toContain(SECRET);
		expect(JSON.stringify(h.events)).not.toContain("at-0");
	});
});
