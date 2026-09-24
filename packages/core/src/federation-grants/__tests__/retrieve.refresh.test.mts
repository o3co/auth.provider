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
import {
	assertFederationGrantRetrievalLimits,
	FEDERATION_GRANT_REFRESH_LOCK_MARGIN_MS,
	retrieveFederationGrantToken,
} from "#/federation-grants/retrieve.mjs";
import {
	federationGrantAuthorizationRevision,
	federationGrantIdentityRevision,
} from "#/federation-grants/revision.mjs";
import type { DelegatedTokens } from "#/federations/types.mjs";
import {
	at,
	CONSENTED,
	connection,
	DAY,
	type Harness,
	HOUR,
	harness,
	limits,
	MIN,
	now,
	refreshed,
	request,
	SCOPES,
	SECRET,
	setNow,
	T0,
} from "./retrieve.harness.mjs";

/** Fifteen seconds before the seeded token runs out: inside the refresh buffer. */
const DUE = at(HOUR - 15_000);
/** The seeded token has just run out: nothing that is stored serves a request any more. */
const GONE = at(HOUR);

interface Deferred<T> {
	readonly promise: Promise<T>;
	resolve(value: T): void;
	reject(error: unknown): void;
}

function deferred<T>(): Deferred<T> {
	let resolve!: (value: T) => void;
	let reject!: (error: unknown) => void;
	const promise = new Promise<T>((res, rej) => {
		resolve = res;
		reject = rej;
	});
	return { promise, resolve, reject };
}

describe("retrieveFederationGrantToken — the refresh (#593, D5, D10, D12)", () => {
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

	const stored = async () => {
		const opened = await h.store.open("g-1", now());
		return opened?.credentials.state === "ok" ? opened.credentials.value : undefined;
	};

	/**
	 * What the audit sink was told, once everything handed to `background` is
	 * done: a refresh tells the sink after it has let go of the lock, which may
	 * be after the call was answered.
	 */
	const types = async () => {
		await Promise.all(h.background);
		return h.events.map((event) => `${event.type} ${event.outcome}`).sort();
	};

	/** A refresh whose upstream call is held open until the test settles it. */
	const stamp = async () => (await h.store.find("g-1", now()))?.refreshFailure;

	const pendingUpstream = () => {
		const call = deferred<DelegatedTokens>();
		h.refresh.mockReturnValueOnce(call.promise);
		return call;
	};

	describe("a token that has run down", () => {
		it("is refreshed with the grant's scopes and resource, persisted, and disclosed as what is now stored", async () => {
			await h.seed();
			setNow(DUE);
			h.refresh.mockResolvedValue(refreshed("1", DUE));

			expect(await retrieve()).toStrictEqual({
				ok: true,
				accessToken: "at-1",
				tokenType: "Bearer",
				expiresIn: 3600,
				scopes: [...SCOPES],
				refreshed: true,
			});
			expect(h.refresh).toHaveBeenCalledTimes(1);
			expect(h.refresh.mock.calls[0]?.[0]).toMatchObject({
				refreshToken: SECRET,
				scopes: [...SCOPES],
			});
			expect(h.refresh.mock.calls[0]?.[0]).not.toHaveProperty("resource");
			expect(h.refresh.mock.calls[0]?.[0].signal).toBeInstanceOf(AbortSignal);
			expect(await stored()).toStrictEqual({
				refreshToken: `${SECRET}-1`,
				accessToken: {
					value: "at-1",
					tokenType: "Bearer",
					obtainedAt: DUE,
					issuedLifetime: 3600,
					scopes: [...SCOPES],
				},
			});
			expect(await types()).toEqual([
				"federation.grant.refreshed success",
				"federation.grant.token.success success",
			]);
			// The lock is released: a second refresh would get it at once.
			const lock = await h.store.acquireRefreshLock("g-1", { ttlMs: 1_000, waitForMs: 0 });
			expect(lock.acquired).toBe(true);
		});

		it("sends the grant's resource: an upstream that needed it at authorization needs it at refresh too (D17)", async () => {
			h.world.connections.set(connection.name, {
				...connection,
				resource: "https://calendar.example/",
			});
			await h.seed();
			setNow(DUE);
			h.refresh.mockResolvedValue(refreshed("1", DUE));

			expect(await retrieve({ resource: "https://calendar.example/" })).toMatchObject({ ok: true });
			expect(h.refresh.mock.calls[0]?.[0]).toMatchObject({ resource: "https://calendar.example/" });
			await Promise.all(h.background);
			expect(h.events.find((event) => event.type === "federation.grant.refreshed")).toMatchObject({
				resource: "https://calendar.example/",
			});
		});

		it("dates the token on the ADAPTER's clock, not on when its answer got here: a later reading would lengthen its life", async () => {
			await h.seed();
			setNow(DUE);
			const call = pendingUpstream();
			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(1_000);
			const obtained = now();
			await vi.advanceTimersByTimeAsync(2_000);
			// The adapter read the clock a second into the call; the answer arrives
			// three seconds in.
			call.resolve(refreshed("1", obtained));

			expect(await answer).toMatchObject({ ok: true, expiresIn: 3598 });
			expect((await stored())?.accessToken?.obtainedAt).toEqual(obtained);
		});

		it("keeps the stored refresh token when the upstream did not rotate it (RFC 6749 §6)", async () => {
			await h.seed();
			setNow(DUE);
			h.refresh.mockResolvedValue(refreshed("1", DUE, { refreshToken: undefined }));
			expect((await retrieve()).ok).toBe(true);
			expect((await stored())?.refreshToken).toBe(SECRET);
		});

		it("records the scopes and the token type the response names, and the grant's scopes and Bearer when it names none", async () => {
			await h.seed();
			setNow(DUE);
			// As the upstream spelled it: a bearer token in any case is one (D5).
			h.refresh.mockResolvedValue(
				refreshed("1", DUE, { scope: "openid  calendar.read", tokenType: "BEARER" }),
			);
			expect(await retrieve()).toMatchObject({
				ok: true,
				scopes: ["openid", "calendar.read"],
				tokenType: "BEARER",
			});

			setNow(new Date(DUE.getTime() + HOUR));
			h.refresh.mockResolvedValue(refreshed("2", now(), { tokenType: undefined }));
			expect(await retrieve()).toMatchObject({
				ok: true,
				scopes: [...SCOPES],
				tokenType: "Bearer",
			});
		});

		it("reads the scope the upstream answered by RFC 6749 §3.3's grammar: whitespace separates, blank means the grant's", async () => {
			// An upstream's answer is read tolerantly (parseScopeTokens, as the
			// session-bound refresh route reads one): a tab is not part of a
			// scope's name, so it cannot make a consented scope look foreign.
			await h.seed();
			setNow(DUE);
			h.refresh.mockResolvedValue(refreshed("1", DUE, { scope: "openid\tcalendar.read\n" }));
			expect(await retrieve()).toMatchObject({ ok: true, scopes: ["openid", "calendar.read"] });

			setNow(new Date(DUE.getTime() + HOUR));
			h.refresh.mockResolvedValue(refreshed("2", now(), { scope: " \t " }));
			expect(await retrieve()).toMatchObject({ ok: true, scopes: [...SCOPES] });
		});

		it("judges the lifetime the upstream ISSUED, which a skewed expiry cannot change", async () => {
			// 3600 s issued, and an adapter whose clock stepped forward by a second
			// and a half while it computed the expiry. Recovered from `expiresAt`
			// that reads as 3602 s, and every grant on a connection whose maximum
			// is 3600 would starve.
			await h.seed();
			setNow(DUE);
			h.refresh.mockResolvedValue(
				refreshed("1", DUE, { expiresAt: new Date(DUE.getTime() + HOUR + 1_500) }),
			);
			expect(await retrieve()).toMatchObject({ ok: true, accessToken: "at-1", expiresIn: 3600 });
			// Dated inside the call, not in the future: its life is not lengthened.
			expect((await stored())?.accessToken?.obtainedAt).toEqual(DUE);
		});

		it("returns a fresh token that is still shorter than min_ttl, with its true lifetime: a call refreshes at most once", async () => {
			await h.seed();
			setNow(at(30 * MIN));
			h.refresh.mockResolvedValue(
				refreshed("1", at(30 * MIN), { expiresIn: 1200, expiresAt: at(50 * MIN) }),
			);
			// 30 minutes are left of the stored token; 40 are asked for.
			expect(await retrieve({ minTtlSeconds: 2400 })).toMatchObject({
				ok: true,
				accessToken: "at-1",
				expiresIn: 1200,
				refreshed: true,
			});
			expect(h.refresh).toHaveBeenCalledTimes(1);
		});

		it("returns its own fresh token below min_ttl with the life it has left by the time the answer is in", async () => {
			// The upstream took three seconds: the lifetime a caller is told counts
			// from when the token was obtained, not from when it is handed over.
			await h.seed();
			setNow(at(30 * MIN));
			const call = pendingUpstream();
			const answer = retrieve({ minTtlSeconds: 2400 });
			await vi.advanceTimersByTimeAsync(3_000);
			call.resolve(refreshed("1", at(30 * MIN), { expiresIn: 1200, expiresAt: at(50 * MIN) }));
			expect(await answer).toMatchObject({
				ok: true,
				accessToken: "at-1",
				expiresIn: 1197,
				refreshed: true,
			});
		});

		it("answers invalid_scope for a fresh token that lacks what was asked for — after keeping its rotated refresh token", async () => {
			await h.seed();
			setNow(DUE);
			h.refresh.mockResolvedValue(refreshed("1", DUE, { scope: "openid" }));
			expect(await retrieve({ scope: ["calendar.read"] })).toStrictEqual({
				ok: false,
				code: "invalid_scope",
			});
			expect((await stored())?.refreshToken).toBe(`${SECRET}-1`);
		});

		it("refuses a connection whose federation cannot refresh for a grant", async () => {
			await h.seed();
			setNow(DUE);
			h.deps.refresher = () => undefined;
			expect(await retrieve()).toStrictEqual({
				ok: false,
				code: "access_denied",
				reason: "connection_not_permitted",
			});
			const lock = await h.store.acquireRefreshLock("g-1", { ttlMs: 1_000, waitForMs: 0 });
			expect(lock.acquired).toBe(true);
		});
	});

	describe("a fresh token that may not be disclosed (D5)", () => {
		const cases: Array<[string, Partial<DelegatedTokens>, string]> = [
			[
				"a lifetime over the maximum",
				{ expiresIn: 7200, expiresAt: at(3 * HOUR) },
				"lifetime_over_maximum",
			],
			["no lifetime at all", { expiresIn: null, expiresAt: null }, "no_finite_lifetime"],
			["a lifetime without the adapter's anchor", { expiresAt: null }, "no_finite_lifetime"],
			["scopes beyond the consent", { scope: "openid files.readwrite" }, "scope_exceeded"],
			// Named, but naming no scope-token, is not silence: it must not read as
			// "the grant's scopes" and so be disclosed as if it were.
			["a scope that names no scope-token", { scope: '"openid"' }, "malformed_token_response"],
			// oauth4webapi lower-cases what the upstream sent; a route with no proof
			// key cannot present a sender-constrained token.
			["a token that is not a bearer token", { tokenType: "dpop" }, "token_type_unsupported"],
		];

		for (const [what, over, reason] of cases) {
			it(`${what}: the rotated refresh token is kept, the access token is never written, and a marker is left`, async () => {
				await h.seed();
				setNow(GONE);
				h.refresh.mockResolvedValue(refreshed("1", GONE, over));

				expect(await retrieve()).toStrictEqual({
					ok: false,
					code: "upstream_token_ineligible",
					reason,
					retryAfterSeconds: 300,
				});
				expect(await stored()).toStrictEqual({
					refreshToken: `${SECRET}-1`,
					accessToken: undefined,
				});
				expect(await h.store.find("g-1", GONE)).toMatchObject({
					status: "active",
					ineligible: { reason, at: GONE, judgedAgainst: 3600 },
				});
				expect(await types()).toEqual([
					`federation.grant.refreshed upstream_token_ineligible/${reason}`,
					`federation.grant.token.denied upstream_token_ineligible/${reason}`,
				]);
			});
		}

		it("a wider consent on the same connection does not widen the narrower grant (row 7: G1, G2)", async () => {
			// G1 consented for the narrow set; G2, later, for the whole
			// connection. An IdP that accumulates consent (D19) answers G1's
			// refresh with G2's scopes. G1 is starved — the token is never
			// written, the rotated refresh token is kept for the
			// reauthorization — and G2, whose consent covers the answer, is
			// served by the same answer. The judgement is against what each
			// grant's user consented to, so both are seeded here by hand.
			const seededAt = now();
			const consented = async (id: string, scopes: readonly string[]) => {
				await h.store.createPending({
					id,
					subject: "u-1",
					clientId: "agent",
					connection: connection.name,
					intent: { handle: `h-${id}`, expiresAt: new Date(seededAt.getTime() + 10 * MIN) },
					now: seededAt,
				});
				const written = await h.store.activate({
					grantId: id,
					intentHandle: `h-${id}`,
					authorization: {
						identityRevision: federationGrantIdentityRevision(connection),
						authorizationRevision: federationGrantAuthorizationRevision(connection),
						upstream: { issuer: connection.upstreamIssuer, subject: "00u-alice" },
						scopes: [...scopes],
						consent: { at: seededAt, sid: `sid-${id}`, scopes: [...scopes] },
						authorizedAt: seededAt,
						expiresAt: new Date(seededAt.getTime() + 30 * DAY),
						resource: undefined,
					},
					credentials: {
						refreshToken: `${SECRET}-${id}`,
						accessToken: {
							value: `at-${id}-0`,
							tokenType: "Bearer",
							obtainedAt: seededAt,
							issuedLifetime: 3600,
							scopes: [...scopes],
						},
					},
					now: seededAt,
				});
				expect(written.ok).toBe(true);
			};
			await consented("g-1", SCOPES);
			await consented("g-2", CONSENTED);

			setNow(GONE);
			h.refresh.mockResolvedValue(refreshed("w", GONE, { scope: CONSENTED.join(" ") }));

			expect(await retrieve()).toMatchObject({
				ok: false,
				code: "upstream_token_ineligible",
				reason: "scope_exceeded",
			});
			expect(await stored()).toStrictEqual({ refreshToken: `${SECRET}-w`, accessToken: undefined });
			expect(await h.store.find("g-1", GONE)).toMatchObject({
				status: "active",
				ineligible: { reason: "scope_exceeded" },
			});

			expect(await retrieve({ grantId: "g-2" })).toMatchObject({ ok: true, accessToken: "at-w" });
			expect(await h.store.find("g-2", now())).toHaveProperty("ineligible", undefined);
		});

		it("asks the upstream once per retry interval, and not once per request", async () => {
			await h.seed();
			setNow(DUE);
			h.refresh.mockResolvedValue(
				refreshed("1", DUE, { expiresIn: 7200, expiresAt: at(3 * HOUR) }),
			);
			await retrieve();
			await retrieve();
			setNow(new Date(DUE.getTime() + 4 * MIN));
			await retrieve();
			expect(h.refresh).toHaveBeenCalledTimes(1);

			setNow(new Date(DUE.getTime() + 5 * MIN));
			h.refresh.mockResolvedValue(refreshed("2", new Date(DUE.getTime() + 5 * MIN)));
			expect(await retrieve()).toMatchObject({ ok: true, accessToken: "at-2" });
			expect(h.refresh).toHaveBeenCalledTimes(2);
			// An eligible refresh clears the marker.
			expect(await h.store.find("g-1", now())).toHaveProperty("ineligible", undefined);
		});
	});

	describe("an upstream that refuses (D11, D12)", () => {
		it("requires reauthorization for a STRUCTURED invalid_grant, and deletes the credentials", async () => {
			await h.seed();
			setNow(DUE);
			h.refresh.mockRejectedValue(
				Object.assign(new Error("server responded with an error"), { error: "invalid_grant" }),
			);
			expect(await retrieve()).toStrictEqual({
				ok: false,
				code: "reauthorization_required",
				reason: "upstream_invalid_grant",
			});
			expect((await h.store.find("g-1", DUE))?.status).toBe("reauthorization_required");
			expect(h.store.holdsCredential("g-1")).toBe(false);
			expect(await types()).toContain(
				"federation.grant.reauthorization_required upstream_invalid_grant",
			);
		});

		it("answers 503 when the mark cannot be written, and what is there when it lost to another write", async () => {
			await h.seed();
			setNow(GONE);
			const rejected = Object.assign(new Error("x"), { error: "invalid_grant" });
			h.refresh.mockRejectedValue(rejected);
			const mark = vi
				.spyOn(h.store, "requireReauthorization")
				.mockRejectedValueOnce(new Error("redis down"));
			expect(await retrieve()).toStrictEqual({
				ok: false,
				code: "temporarily_unavailable",
				reason: "storage",
			});
			expect((await h.store.find("g-1", DUE))?.status).toBe("active");

			// The grant was revoked while the upstream was answering: the mark is
			// refused, and the revocation is what is reported.
			mark.mockImplementationOnce(async () => {
				await h.store.revoke("g-1", "subject", now());
				return { ok: false };
			});
			expect(await retrieve()).toStrictEqual({
				ok: false,
				code: "grant_revoked",
				reason: "subject",
			});
		});

		describe("an upstream that asked for the user (#616, D11, D12)", () => {
			// The four codes an IdP answers with when it wants the user and not a
			// new token. Nothing said the refresh token is bad, so both tokens are
			// kept; nothing is mended by waiting, so no wait is told; and the
			// answer is read off the record, never off the error in hand.
			const codes = [
				"interaction_required",
				"login_required",
				"consent_required",
				"account_selection_required",
			] as const;
			const asksFor = (code: string, over: object = {}) =>
				Object.assign(new Error("server responded with an error"), { error: code, ...over });
			const renewal = () => ({
				identityRevision: federationGrantIdentityRevision(connection),
				authorizationRevision: federationGrantAuthorizationRevision(connection),
				upstream: { issuer: connection.upstreamIssuer, subject: "00u-alice" },
				resource: undefined,
				scopes: [...SCOPES],
				consent: { at: now(), sid: "sid-re", scopes: [...CONSENTED] },
				authorizedAt: now(),
				expiresAt: new Date(now().getTime() + 30 * DAY),
			});

			for (const code of codes) {
				it(`remembers a structured ${code} as the user being asked for: both tokens kept, named, no wait`, async () => {
					const grant = await h.seed();
					setNow(DUE);
					h.refresh.mockRejectedValue(asksFor(code));
					expect(await retrieve()).toStrictEqual({
						ok: false,
						code: "reauthorization_required",
						reason: `upstream_${code}`,
					});
					expect(await h.store.find("g-1", DUE)).toMatchObject({
						status: "active",
						version: grant.version,
						refreshFailure: { kind: "rejected", upstreamCode: code, count: 1 },
					});
					expect(h.store.holdsCredential("g-1")).toBe(true);
					expect(await stored()).toMatchObject({
						refreshToken: SECRET,
						accessToken: { value: "at-0" },
					});
					expect(await types()).toEqual(
						expect.arrayContaining([
							`federation.grant.reauthorization_required upstream_${code}`,
							`federation.grant.token.denied reauthorization_required/upstream_${code}`,
						]),
					);
				});
			}

			it("prefers the structured code to the transport it came with: beside a 429 it is still the user", async () => {
				await h.seed();
				setNow(DUE);
				h.refresh.mockRejectedValue(
					asksFor("consent_required", {
						status: 429,
						response: new Response(null, { status: 429, headers: { "retry-after": "120" } }),
					}),
				);
				expect(await retrieve()).toStrictEqual({
					ok: false,
					code: "reauthorization_required",
					reason: "upstream_consent_required",
				});
			});

			it("and beside a 503 as well: an outage that names the user is the user", async () => {
				await h.seed();
				setNow(DUE);
				h.refresh.mockRejectedValue(asksFor("login_required", { status: 503 }));
				expect(await retrieve()).toStrictEqual({
					ok: false,
					code: "reauthorization_required",
					reason: "upstream_login_required",
				});
			});

			it("does not establish it from a message alone: a proxy's page that says consent_required is a refusal nobody can read", async () => {
				await h.seed();
				setNow(GONE);
				h.refresh.mockRejectedValue(new Error("consent_required: said a proxy's error page"));
				expect(await retrieve()).toMatchObject({
					ok: false,
					code: "upstream_rejected",
					reason: "unknown",
				});
				expect((await h.store.find("g-1", DUE))?.refreshFailure).toHaveProperty(
					"upstreamCode",
					undefined,
				);
			});

			it("asks the upstream once and never again while the stamp stands: a call a week on is answered from the record", async () => {
				await h.seed();
				setNow(DUE);
				h.refresh.mockRejectedValue(asksFor("login_required"));
				await retrieve();
				setNow(new Date(DUE.getTime() + 7 * DAY));
				expect(await retrieve({ correlationId: "req-2" })).toStrictEqual({
					ok: false,
					code: "reauthorization_required",
					reason: "upstream_login_required",
				});
				expect(h.refresh).toHaveBeenCalledTimes(1);
			});

			it("answers storage when the stamp could not be written — nothing remembered, the credentials kept — and what is stored when it lost", async () => {
				await h.seed();
				setNow(GONE);
				h.refresh.mockRejectedValue(asksFor("consent_required"));
				const note = vi
					.spyOn(h.store, "noteRefreshFailure")
					.mockRejectedValueOnce(new Error("redis down"));
				expect(await retrieve()).toStrictEqual({
					ok: false,
					code: "temporarily_unavailable",
					reason: "storage",
				});
				expect(await h.store.find("g-1", DUE)).toMatchObject({ status: "active" });
				expect(await h.store.find("g-1", DUE)).toHaveProperty("refreshFailure", undefined);
				expect(await stored()).toMatchObject({ refreshToken: SECRET });
				expect(await types()).toContain("federation.grant.refresh_failed mark_not_written");

				// Lost: the grant was revoked while the upstream was answering. The
				// revocation is what is reported, never the denial in hand.
				note.mockImplementationOnce(async () => {
					await h.store.revoke("g-1", "subject", now());
					return { ok: false };
				});
				expect(await retrieve({ correlationId: "req-2" })).toStrictEqual({
					ok: false,
					code: "grant_revoked",
					reason: "subject",
				});
				expect(await types()).toContain("federation.grant.refresh_failed mark_lost");
			});

			it("does not repeat a denial the record no longer carries: a renewal that landed between the stamp and the last look is what is answered", async () => {
				await h.seed();
				setNow(DUE);
				h.refresh.mockRejectedValue(asksFor("consent_required"));
				const real = h.store.noteRefreshFailure.bind(h.store);
				vi.spyOn(h.store, "noteRefreshFailure").mockImplementationOnce(async (input) => {
					const noted = await real(input);
					// The user came back meanwhile: a reauthorization activates over the stamp.
					await h.store.nameIntent({
						grantId: "g-1",
						intent: { handle: "h-re", expiresAt: new Date(now().getTime() + 10 * MIN) },
						now: now(),
					});
					const renewed = await h.store.activate({
						grantId: "g-1",
						intentHandle: "h-re",
						authorization: renewal(),
						credentials: {
							refreshToken: `${SECRET}-re`,
							accessToken: {
								value: "at-re",
								tokenType: "Bearer",
								obtainedAt: now(),
								issuedLifetime: 3600,
								scopes: [...SCOPES],
							},
						},
						now: now(),
					});
					if (!renewed.ok) throw new Error("fixture: the renewal did not activate");
					return noted;
				});
				expect(await retrieve()).toMatchObject({ ok: true, accessToken: "at-re" });
				expect(await h.store.find("g-1", now())).toHaveProperty("refreshFailure", undefined);
			});

			it("answers concurrent_update, never the user, when the record was replaced under it by a token that does not serve", async () => {
				// The stamp was written, and between that and the last look another
				// writer replaced the credentials — with a token already run out, so
				// the look would refresh. The denial in hand says the user; the
				// record says nothing of the kind any more. What is answered is
				// that this call was overtaken.
				await h.seed();
				setNow(GONE);
				h.refresh.mockRejectedValue(asksFor("consent_required"));
				const real = h.store.noteRefreshFailure.bind(h.store);
				vi.spyOn(h.store, "noteRefreshFailure").mockImplementationOnce(async (input) => {
					const noted = await real(input);
					const replaced = await h.store.replaceCredentials({
						grantId: "g-1",
						expectedVersion: input.expectedVersion,
						credentials: {
							refreshToken: `${SECRET}-other`,
							accessToken: {
								value: "at-other",
								tokenType: "Bearer",
								obtainedAt: new Date(now().getTime() - 2 * HOUR),
								issuedLifetime: 3600,
								scopes: [...SCOPES],
							},
						},
						ineligible: null,
						now: now(),
					});
					if (!replaced.ok) throw new Error("fixture: the replacement did not land");
					return noted;
				});
				expect(await retrieve()).toStrictEqual({
					ok: false,
					code: "temporarily_unavailable",
					reason: "concurrent_update",
				});
				expect(await stamp()).toBeUndefined();
			});

			it("keeps the lease while the stamp is still being written: one past the budget must not land under the next holder", async () => {
				await h.seed();
				setNow(GONE);
				h.refresh.mockRejectedValue(asksFor("consent_required"));
				vi.spyOn(h.store, "noteRefreshFailure").mockReturnValue(new Promise(() => {}));
				const answer = retrieve();
				await vi.advanceTimersByTimeAsync(limits.persistRetryBudgetMs + 50);
				expect(await answer).toStrictEqual({
					ok: false,
					code: "temporarily_unavailable",
					reason: "storage",
				});
				const second = retrieve({ correlationId: "req-2" });
				await vi.advanceTimersByTimeAsync(limits.lockWaitMs + 3_100);
				expect(await second).toStrictEqual({
					ok: false,
					code: "temporarily_unavailable",
					reason: "lock_timeout",
				});
				expect(h.refresh).toHaveBeenCalledTimes(1);
			});

			it("is not overwritten by an admitted refresh's failure: a stamp that landed late stands, and the next holder is answered from it", async () => {
				// A's stamp hangs past the budget and past the lease; B takes the
				// lock and is asking the upstream when A's stamp lands; B's outage
				// arrives after it. The store refuses B's stamp (commit 1), and B's
				// last look reads the user.
				await h.seed();
				setNow(GONE);
				const real = h.store.noteRefreshFailure.bind(h.store);
				vi.spyOn(h.store, "noteRefreshFailure").mockImplementationOnce(async (input) => {
					await new Promise((resolve) => setTimeout(resolve, limits.refreshLockTtlMs + 5_000));
					return real(input);
				});
				h.refresh.mockRejectedValueOnce(asksFor("consent_required"));
				const first = retrieve();
				await vi.advanceTimersByTimeAsync(limits.persistRetryBudgetMs + 100);
				expect(await first).toMatchObject({ code: "temporarily_unavailable", reason: "storage" });

				await vi.advanceTimersByTimeAsync(limits.refreshLockTtlMs + 1_000);
				const call = pendingUpstream();
				const second = retrieve({ correlationId: "req-2" });
				await vi.advanceTimersByTimeAsync(100);
				expect(h.refresh).toHaveBeenCalledTimes(2);
				// A's stamp lands while B is still waiting on the upstream — and
				// inside B's own deadline, so that what B does next is B's write.
				await vi.advanceTimersByTimeAsync(2_000);
				expect(await stamp()).toMatchObject({ kind: "rejected", upstreamCode: "consent_required" });
				call.reject(Object.assign(new Error("x"), { status: 503 }));
				expect(await second).toStrictEqual({
					ok: false,
					code: "reauthorization_required",
					reason: "upstream_consent_required",
				});
				await Promise.all(h.background);
				expect(await stamp()).toMatchObject({ kind: "rejected", upstreamCode: "consent_required" });
			});

			it("is overtaken by an admitted refresh that succeeds: its rotated credential is what is stored, and the stamp is gone", async () => {
				await h.seed();
				setNow(GONE);
				const real = h.store.noteRefreshFailure.bind(h.store);
				vi.spyOn(h.store, "noteRefreshFailure").mockImplementationOnce(async (input) => {
					await new Promise((resolve) => setTimeout(resolve, limits.refreshLockTtlMs + 5_000));
					return real(input);
				});
				h.refresh.mockRejectedValueOnce(asksFor("consent_required"));
				const first = retrieve();
				await vi.advanceTimersByTimeAsync(limits.persistRetryBudgetMs + 100);
				expect(await first).toMatchObject({ code: "temporarily_unavailable", reason: "storage" });

				await vi.advanceTimersByTimeAsync(limits.refreshLockTtlMs + 1_000);
				const call = pendingUpstream();
				const second = retrieve({ correlationId: "req-2" });
				await vi.advanceTimersByTimeAsync(100);
				expect(h.refresh).toHaveBeenCalledTimes(2);
				await vi.advanceTimersByTimeAsync(2_000);
				expect(await stamp()).toMatchObject({ kind: "rejected", upstreamCode: "consent_required" });
				call.resolve(refreshed("b", now()));
				expect(await second).toMatchObject({ ok: true, accessToken: "at-b" });
				await Promise.all(h.background);
				expect(await stamp()).toBeUndefined();
				expect(await stored()).toMatchObject({ refreshToken: `${SECRET}-b` });
			});
		});

		const refusals: Array<[string, unknown, object]> = [
			[
				"a message that only mentions invalid_grant",
				new Error("invalid_grant: said a proxy's error page"),
				{ code: "upstream_rejected", reason: "unknown" },
			],
			[
				"an error code this provider knows",
				Object.assign(new Error("x"), { error: "invalid_client", status: 401 }),
				// A refusal is remembered at once (D12): the wait is what the stamp says.
				{ code: "upstream_rejected", reason: "invalid_client", retryAfterSeconds: 300 },
			],
			// An upstream that echoes what it was sent, in the one field that gets
			// echoed on: not a code, so not repeated.
			[
				"an error code that is a secret",
				Object.assign(new Error(`leaked ${SECRET}`), { error: `bad token ${SECRET}` }),
				{ code: "upstream_rejected", reason: "unknown" },
			],
			[
				"a rate limit with advice",
				Object.assign(new Error("x"), {
					status: 429,
					response: new Response(null, { status: 429, headers: { "retry-after": "17" } }),
				}),
				// The advice is honoured for the backoff at least: thirty seconds.
				{ code: "rate_limited", reason: "upstream", retryAfterSeconds: 30 },
			],
			[
				"a rate limit without",
				Object.assign(new Error("x"), { status: 429 }),
				{ code: "rate_limited", reason: "upstream", retryAfterSeconds: 30 },
			],
			[
				"an outage",
				Object.assign(new Error("x"), { status: 503 }),
				{ code: "temporarily_unavailable", reason: "upstream" },
			],
		];

		it.each(refusals)(
			"changes nothing in the record for anything else — %s",
			async (_, error, denial) => {
				const grant = await h.seed();
				setNow(GONE);
				const before = await h.store.open("g-1", GONE);
				h.refresh.mockRejectedValueOnce(error);
				expect(await retrieve()).toStrictEqual({ ok: false, ...denial });
				const after = await h.store.open("g-1", GONE);
				expect(after).toMatchObject({
					grant: { status: "active", version: grant.version },
					credentials: { state: "ok", value: { refreshToken: SECRET } },
				});
				// Nothing but the failure stamp: the credentials whole, and the grant
				// whole apart from it — key for key (#626).
				expect(after?.credentials).toStrictEqual(before?.credentials);
				const { refreshFailure: _after, ...afterRest } = after?.grant ?? {};
				const { refreshFailure: _before, ...beforeRest } = before?.grant ?? {};
				expect(afterRest).toStrictEqual(beforeRest);
				expect(
					(await types()).filter((entry) => entry.startsWith("federation.grant.refresh_failed ")),
				).toHaveLength(1);
			},
		);
	});

	describe("a writer that loses never returns the token it fetched (D2, D10)", () => {
		it("the grant is revoked while the upstream is being asked", async () => {
			await h.seed();
			setNow(DUE);
			const call = pendingUpstream();
			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(100);
			await h.store.revoke("g-1", "client", now());
			call.resolve(refreshed("fetched", DUE));

			expect(await answer).toStrictEqual({ ok: false, code: "grant_revoked", reason: "client" });
			expect(h.store.holdsCredential("g-1")).toBe(false);
		});

		it("a reauthorization lands while the upstream is being asked: what it stored is what is answered", async () => {
			await h.seed();
			setNow(DUE);
			await h.store.nameIntent({
				grantId: "g-1",
				intent: { handle: "h-re", expiresAt: new Date(DUE.getTime() + 10 * MIN) },
				now: DUE,
			});
			const call = pendingUpstream();
			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(100);
			const moment = now();
			await h.store.activate({
				grantId: "g-1",
				intentHandle: "h-re",
				authorization: {
					identityRevision: federationGrantIdentityRevision(connection),
					authorizationRevision: federationGrantAuthorizationRevision(connection),
					upstream: { issuer: connection.upstreamIssuer, subject: "00u-alice" },
					scopes: [...SCOPES],
					consent: { at: moment, sid: "sid-2", scopes: [...SCOPES] },
					authorizedAt: moment,
					expiresAt: new Date(moment.getTime() + 30 * DAY),
					resource: undefined,
				},
				credentials: {
					refreshToken: `${SECRET}-renewed`,
					accessToken: {
						value: "at-renewed",
						tokenType: "Bearer",
						obtainedAt: moment,
						issuedLifetime: 3600,
						scopes: [...SCOPES],
					},
				},
				now: moment,
			});
			call.resolve(refreshed("fetched", DUE));

			expect(await answer).toMatchObject({ ok: true, accessToken: "at-renewed", refreshed: false });
			expect((await stored())?.refreshToken).toBe(`${SECRET}-renewed`);
		});

		it("a reauthorization lands after this call's write and before its last look: what it stored is answered, and not as this call's refresh", async () => {
			// A reauthorization does not take the refresh lock. `refreshed` says
			// that the token answered is the one this call fetched, and here it is
			// not.
			await h.seed();
			setNow(DUE);
			await h.store.nameIntent({
				grantId: "g-1",
				intent: { handle: "h-re", expiresAt: new Date(DUE.getTime() + 10 * MIN) },
				now: DUE,
			});
			h.refresh.mockResolvedValue(refreshed("fetched", DUE));
			const write = h.store.replaceCredentials.bind(h.store);
			vi.spyOn(h.store, "replaceCredentials").mockImplementationOnce(async (input) => {
				const written = await write(input);
				const moment = now();
				await h.store.activate({
					grantId: "g-1",
					intentHandle: "h-re",
					authorization: {
						identityRevision: federationGrantIdentityRevision(connection),
						authorizationRevision: federationGrantAuthorizationRevision(connection),
						upstream: { issuer: connection.upstreamIssuer, subject: "00u-alice" },
						scopes: [...SCOPES],
						consent: { at: moment, sid: "sid-2", scopes: [...SCOPES] },
						authorizedAt: moment,
						expiresAt: new Date(moment.getTime() + 30 * DAY),
						resource: undefined,
					},
					credentials: {
						refreshToken: `${SECRET}-renewed`,
						accessToken: {
							value: "at-renewed",
							tokenType: "Bearer",
							obtainedAt: moment,
							issuedLifetime: 3600,
							scopes: [...SCOPES],
						},
					},
					now: moment,
				});
				return written;
			});
			expect(await retrieve()).toMatchObject({
				ok: true,
				accessToken: "at-renewed",
				refreshed: false,
			});
		});

		it("what replaced this call's write is judged as somebody else's: one that does not serve the request is not answered, and the reason says what happened", async () => {
			await h.seed();
			setNow(DUE);
			await h.store.nameIntent({
				grantId: "g-1",
				intent: { handle: "h-re", expiresAt: new Date(DUE.getTime() + 10 * MIN) },
				now: DUE,
			});
			h.refresh.mockResolvedValue(refreshed("fetched", DUE));
			const write = h.store.replaceCredentials.bind(h.store);
			vi.spyOn(h.store, "replaceCredentials").mockImplementationOnce(async (input) => {
				const written = await write(input);
				const moment = now();
				await h.store.activate({
					grantId: "g-1",
					intentHandle: "h-re",
					authorization: {
						identityRevision: federationGrantIdentityRevision(connection),
						authorizationRevision: federationGrantAuthorizationRevision(connection),
						upstream: { issuer: connection.upstreamIssuer, subject: "00u-alice" },
						scopes: [...SCOPES],
						consent: { at: moment, sid: "sid-2", scopes: [...SCOPES] },
						authorizedAt: moment,
						expiresAt: new Date(moment.getTime() + 30 * DAY),
						resource: undefined,
					},
					credentials: {
						refreshToken: `${SECRET}-renewed`,
						accessToken: {
							value: "at-renewed",
							tokenType: "Bearer",
							// Half spent already, and narrower than what this request
							// asserts: one the look would refresh.
							obtainedAt: new Date(moment.getTime() - 50 * MIN),
							issuedLifetime: 3600,
							scopes: ["openid"],
						},
					},
					now: moment,
				});
				return written;
			});
			// A call refreshes once. What it wrote was replaced before its last look
			// (D11): that is what it says, and not that the upstream failed it.
			expect(await retrieve({ scope: ["calendar.read"] })).toStrictEqual({
				ok: false,
				code: "temporarily_unavailable",
				reason: "concurrent_update",
			});
		});

		it("the refresh starts before the grant's expiry and finishes after it", async () => {
			await h.seed({ expiresAt: at(HOUR) });
			setNow(DUE);
			const call = pendingUpstream();
			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(100);
			setNow(at(HOUR + 1_000));
			call.resolve(refreshed("fetched", DUE));

			expect(await answer).toStrictEqual({
				ok: false,
				code: "grant_expired",
				reason: "consented_lifetime",
			});
			// And the write was made with the time AT the write: the store refused
			// it, so nothing was stored after the expiry.
			expect(await h.store.find("g-1", at(HOUR + 1_000))).toMatchObject({ version: 2 });
		});

		it("a subject-wide revocation stamps its boundary while the upstream is being asked, and never reaches this grant", async () => {
			await h.seed();
			setNow(DUE);
			const call = pendingUpstream();
			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(100);
			// The grant pass was omitted: only the watermark says so.
			h.world.boundary = now();
			call.resolve(refreshed("fetched", DUE));

			expect(await answer).toStrictEqual({ ok: false, code: "grant_revoked", reason: "backstop" });
			expect((await h.store.find("g-1", now()))?.status).toBe("revoked");
		});

		it("answers concurrent_update when what won left nothing to answer with", async () => {
			await h.seed();
			setNow(GONE);
			h.refresh.mockResolvedValue(refreshed("fetched", DUE));
			// The guarded write is refused, and nothing else has changed: the stored
			// token is still the one that had run down.
			vi.spyOn(h.store, "replaceCredentials").mockResolvedValue({ ok: false });
			expect(await retrieve()).toStrictEqual({
				ok: false,
				code: "temporarily_unavailable",
				reason: "concurrent_update",
			});
			expect(h.refresh).toHaveBeenCalledTimes(1);
		});
	});

	describe("the lock (D12)", () => {
		it("makes a second caller wait, look again, and answer with what the first one stored: the upstream is asked once", async () => {
			await h.seed();
			setNow(DUE);
			const call = pendingUpstream();
			const first = retrieve();
			await vi.advanceTimersByTimeAsync(50);
			const second = retrieve({ correlationId: "req-2" });
			await vi.advanceTimersByTimeAsync(200);
			call.resolve(refreshed("1", DUE));
			await vi.advanceTimersByTimeAsync(200);

			expect(await first).toMatchObject({ ok: true, accessToken: "at-1", refreshed: true });
			expect(await second).toMatchObject({ ok: true, accessToken: "at-1", refreshed: false });
			expect(h.refresh).toHaveBeenCalledTimes(1);
			// The waiter let go of the lock it got, though it had nothing to refresh.
			const lock = await h.store.acquireRefreshLock("g-1", { ttlMs: 1_000, waitForMs: 0 });
			expect(lock.acquired).toBe(true);
		});

		it("answers lock_timeout when the holder is still at it, and asks the upstream nothing", async () => {
			await h.seed();
			setNow(GONE);
			pendingUpstream();
			const first = retrieve();
			await vi.advanceTimersByTimeAsync(50);
			const second = retrieve({ correlationId: "req-2" });
			await vi.advanceTimersByTimeAsync(limits.lockWaitMs + 100);

			expect(await second).toStrictEqual({
				ok: false,
				code: "temporarily_unavailable",
				reason: "lock_timeout",
			});
			expect(h.refresh).toHaveBeenCalledTimes(1);
			await vi.advanceTimersByTimeAsync(limits.upstreamHardTimeoutMs);
			await first;
			await Promise.all(h.background);
		});

		it("looks once more after a lock timeout, and answers with what somebody else stored meanwhile", async () => {
			const grant = await h.seed();
			setNow(DUE);
			// Held by a replica that is not this test's: it refreshes, and is slow
			// to let go.
			const theirs = await h.store.acquireRefreshLock("g-1", { ttlMs: 60_000, waitForMs: 0 });
			if (!theirs.acquired) throw new Error("fixture");
			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(1_000);
			const moment = now();
			await h.store.replaceCredentials({
				grantId: "g-1",
				expectedVersion: grant.version,
				credentials: {
					refreshToken: `${SECRET}-theirs`,
					accessToken: {
						value: "at-theirs",
						tokenType: "Bearer",
						obtainedAt: moment,
						issuedLifetime: 3600,
						scopes: [...SCOPES],
					},
				},
				ineligible: null,
				now: moment,
			});
			await vi.advanceTimersByTimeAsync(limits.lockWaitMs);

			expect(await answer).toMatchObject({ ok: true, accessToken: "at-theirs", refreshed: false });
			expect(h.refresh).not.toHaveBeenCalled();
			await theirs.release();
		});

		it("answers 503 when the lock cannot be asked for", async () => {
			await h.seed();
			setNow(GONE);
			vi.spyOn(h.store, "acquireRefreshLock").mockRejectedValue(new Error("redis down"));
			expect(await retrieve()).toStrictEqual({
				ok: false,
				code: "temporarily_unavailable",
				reason: "storage",
			});
			expect(h.refresh).not.toHaveBeenCalled();
		});
	});

	describe("a slow upstream must not cost users their grants (D12)", () => {
		it("answers the caller at the soft deadline, and persists the late result all the same", async () => {
			await h.seed();
			setNow(GONE);
			const call = pendingUpstream();
			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(limits.upstreamTimeoutMs);

			expect(await answer).toStrictEqual({
				ok: false,
				code: "temporarily_unavailable",
				reason: "upstream",
			});
			// The request goes on, holding the lock.
			expect(await h.store.acquireRefreshLock("g-1", { ttlMs: 1_000, waitForMs: 0 })).toEqual({
				acquired: false,
				reason: "timeout",
			});

			// A rotating upstream answers between the two deadlines: the new
			// credential is the only valid one, and it is kept.
			await vi.advanceTimersByTimeAsync(5_000);
			call.resolve(refreshed("late", now()));
			await Promise.all(h.background);
			expect((await stored())?.refreshToken).toBe(`${SECRET}-late`);
			expect(await types()).toContain("federation.grant.refreshed success");

			// The next call succeeds, without asking the upstream again.
			expect(await retrieve()).toMatchObject({
				ok: true,
				accessToken: "at-late",
				refreshed: false,
			});
			expect(h.refresh).toHaveBeenCalledTimes(1);
		});

		it("aborts at the hard deadline, accepts nothing that arrives later, and releases the lock", async () => {
			await h.seed();
			setNow(DUE);
			const call = pendingUpstream();
			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(limits.upstreamHardTimeoutMs);
			await answer;
			await Promise.all(h.background);

			expect(h.refresh.mock.calls[0]?.[0].signal?.aborted).toBe(true);
			expect(await types()).toContain("federation.grant.refresh_persist_failed hard_timeout");
			// The aborted request may have rotated the refresh token all the same.
			// The lock is left to run out: whoever got it now would present the old
			// token beside that, and an IdP that detects reuse revokes the family.
			expect(await h.store.acquireRefreshLock("g-1", { ttlMs: 1_000, waitForMs: 0 })).toEqual({
				acquired: false,
				reason: "timeout",
			});
			await vi.advanceTimersByTimeAsync(limits.refreshLockTtlMs - limits.upstreamHardTimeoutMs);
			const lock = await h.store.acquireRefreshLock("g-1", { ttlMs: 1_000, waitForMs: 0 });
			expect(lock.acquired).toBe(true);

			// An acknowledged loss: what arrives now is not persisted.
			call.resolve(refreshed("too-late", now()));
			await vi.advanceTimersByTimeAsync(1_000);
			expect((await stored())?.refreshToken).toBe(SECRET);
		});

		it("counts every deadline from the moment the store took the lock: what the call spends under the lock is spent of the same lease", async () => {
			await h.seed();
			setNow(GONE);
			// The look under the lock is slow: four seconds for the boundary.
			let reads = 0;
			h.deps.grantsBoundary = async () => {
				reads += 1;
				if (reads === 2) await new Promise((resolve) => setTimeout(resolve, 4_000));
				return null;
			};
			pendingUpstream();
			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(4_000);
			expect(h.refresh).toHaveBeenCalledTimes(1);
			// Six more seconds, not ten: the soft deadline is ten from the lock.
			await vi.advanceTimersByTimeAsync(6_000);
			expect(await answer).toMatchObject({ code: "temporarily_unavailable", reason: "upstream" });
			// And the abort is twenty-five from the lock, not from the call.
			await vi.advanceTimersByTimeAsync(15_000);
			await Promise.all(h.background);
			expect(h.refresh.mock.calls[0]?.[0].signal?.aborted).toBe(true);
		});
	});

	describe("a replacement that cannot be persisted (D12)", () => {
		it("is retried inside the lock, within a budget, and then answered as a storage outage", async () => {
			const grant = await h.seed();
			setNow(GONE);
			h.refresh.mockResolvedValue(refreshed("1", DUE));
			const write = vi
				.spyOn(h.store, "replaceCredentials")
				.mockRejectedValue(new Error("redis down"));

			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(limits.persistRetryBudgetMs + 500);
			expect(await answer).toStrictEqual({
				ok: false,
				code: "temporarily_unavailable",
				reason: "storage",
			});
			expect(write.mock.calls.length).toBeGreaterThan(1);
			expect(await types()).toContain("federation.grant.refresh_persist_failed storage");
			// The grant is untouched, and the lock is released.
			write.mockRestore();
			expect(await h.store.find("g-1", now())).toMatchObject({ version: grant.version });
			const lock = await h.store.acquireRefreshLock("g-1", { ttlMs: 1_000, waitForMs: 0 });
			expect(lock.acquired).toBe(true);
		});

		it("succeeds on a later try", async () => {
			await h.seed();
			setNow(DUE);
			h.refresh.mockResolvedValue(refreshed("1", DUE));
			vi.spyOn(h.store, "replaceCredentials").mockRejectedValueOnce(new Error("blip"));

			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(500);
			expect(await answer).toMatchObject({ ok: true, accessToken: "at-1", refreshed: true });
		});

		it("finds its own token stored when a write landed and only its acknowledgement was lost", async () => {
			await h.seed();
			setNow(DUE);
			h.refresh.mockResolvedValue(refreshed("1", DUE));
			const real = h.store.replaceCredentials.bind(h.store);
			vi.spyOn(h.store, "replaceCredentials").mockImplementationOnce(async (input) => {
				await real(input);
				throw new Error("connection reset after commit");
			});

			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(500);
			// The retry is refused on the version its own write bumped. It does not
			// force the write through; the last look finds the token there.
			expect(await answer).toMatchObject({ ok: true, accessToken: "at-1" });
			expect(h.refresh).toHaveBeenCalledTimes(1);
		});

		it("does not wait for a write that hangs past the budget", async () => {
			await h.seed();
			setNow(GONE);
			h.refresh.mockResolvedValue(refreshed("1", DUE));
			vi.spyOn(h.store, "replaceCredentials").mockReturnValue(new Promise(() => {}));

			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(limits.persistRetryBudgetMs + 100);
			expect(await answer).toMatchObject({ code: "temporarily_unavailable", reason: "storage" });
			expect(await types()).toContain("federation.grant.refresh_persist_failed write_in_flight");
			// The write may yet land, and the refresh token it replaces has been
			// rotated away at the upstream. Until the lock runs out nobody else is
			// let at it.
			expect(await h.store.acquireRefreshLock("g-1", { ttlMs: 1_000, waitForMs: 0 })).toEqual({
				acquired: false,
				reason: "timeout",
			});
			await vi.advanceTimersByTimeAsync(limits.refreshLockTtlMs);
			const lock = await h.store.acquireRefreshLock("g-1", { ttlMs: 1_000, waitForMs: 0 });
			expect(lock.acquired).toBe(true);
		});
	});

	describe("what is presented to the upstream, and asked of the store (D12)", () => {
		it("presents the refresh token read UNDER the lock, not the one read before waiting for it", async () => {
			// Another replica rotated the refresh token while this call waited. What
			// this call read before the wait is the old one, and presenting it is
			// what an IdP that detects reuse answers by revoking the family.
			const grant = await h.seed();
			setNow(DUE);
			const theirs = await h.store.acquireRefreshLock("g-1", { ttlMs: 60_000, waitForMs: 0 });
			if (!theirs.acquired) throw new Error("fixture");
			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(1_000);
			await h.store.replaceCredentials({
				grantId: "g-1",
				expectedVersion: grant.version,
				credentials: { refreshToken: `${SECRET}-rotated-by-them`, accessToken: undefined },
				ineligible: null,
				now: now(),
			});
			await theirs.release();
			h.refresh.mockResolvedValue(refreshed("1", now()));
			await vi.advanceTimersByTimeAsync(100);

			expect(await answer).toMatchObject({ ok: true, accessToken: "at-1" });
			expect(h.refresh).toHaveBeenCalledTimes(1);
			expect(h.refresh.mock.calls[0]?.[0].refreshToken).toBe(`${SECRET}-rotated-by-them`);
		});

		it("asks again for exactly what the upstream granted, not for everything the user consented to", async () => {
			await h.seed();
			setNow(DUE);
			h.refresh.mockResolvedValue(refreshed("1", DUE));
			await retrieve();
			expect(h.refresh.mock.calls[0]?.[0].scopes).toStrictEqual([...SCOPES]);
		});

		it("judges a fresh token against the consent: a consented scope the upstream adds later is no excess", async () => {
			await h.seed();
			setNow(DUE);
			h.refresh.mockResolvedValue(refreshed("1", DUE, { scope: CONSENTED.join(" ") }));
			expect(await retrieve({ scope: ["calendar.write"] })).toMatchObject({
				ok: true,
				scopes: [...CONSENTED],
			});
		});

		it("takes the lock for as long, and waits for it for as long, as it is configured to", async () => {
			await h.seed();
			setNow(DUE);
			h.refresh.mockResolvedValue(refreshed("1", DUE));
			const asked = vi.spyOn(h.store, "acquireRefreshLock");
			await retrieve();
			expect(asked).toHaveBeenCalledExactlyOnceWith("g-1", {
				ttlMs: limits.refreshLockTtlMs,
				waitForMs: limits.lockWaitMs,
			});
		});

		it("does not force a mark through: an invalid_grant for a refresh token the grant no longer has ends nothing", async () => {
			// The user reauthorized while the upstream was answering. Its rejection
			// is for the OLD refresh token; marked with a version read again, it
			// would cost the user the grant they have just renewed.
			await h.seed();
			setNow(DUE);
			await h.store.nameIntent({
				grantId: "g-1",
				intent: { handle: "h-re", expiresAt: new Date(DUE.getTime() + 10 * MIN) },
				now: DUE,
			});
			const call = pendingUpstream();
			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(100);
			const moment = now();
			await h.store.activate({
				grantId: "g-1",
				intentHandle: "h-re",
				authorization: {
					identityRevision: federationGrantIdentityRevision(connection),
					authorizationRevision: federationGrantAuthorizationRevision(connection),
					upstream: { issuer: connection.upstreamIssuer, subject: "00u-alice" },
					scopes: [...SCOPES],
					consent: { at: moment, sid: "sid-2", scopes: [...CONSENTED] },
					authorizedAt: moment,
					expiresAt: new Date(moment.getTime() + 30 * DAY),
					resource: undefined,
				},
				credentials: {
					refreshToken: `${SECRET}-renewed`,
					accessToken: {
						value: "at-renewed",
						tokenType: "Bearer",
						obtainedAt: moment,
						issuedLifetime: 3600,
						scopes: [...SCOPES],
					},
				},
				now: moment,
			});
			call.reject(Object.assign(new Error("x"), { error: "invalid_grant" }));

			expect(await answer).toMatchObject({ ok: true, accessToken: "at-renewed", refreshed: false });
			expect((await h.store.find("g-1", now()))?.status).toBe("active");
			expect(await types()).toContain("federation.grant.refresh_failed mark_lost");
		});

		it("dates the marker when the answer was judged, not when the upstream was asked", async () => {
			await h.seed();
			setNow(DUE);
			const call = pendingUpstream();
			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(3_000);
			const judged = now();
			call.resolve(refreshed("1", DUE, { expiresIn: 7200, expiresAt: at(3 * HOUR) }));
			await answer;
			expect(await h.store.find("g-1", now())).toMatchObject({ ineligible: { at: judged } });
		});

		it("leaves a trail when the upstream was asked and the write then lost", async () => {
			await h.seed();
			setNow(DUE);
			const call = pendingUpstream();
			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(100);
			await h.store.revoke("g-1", "client", now());
			call.resolve(refreshed("fetched", DUE));
			await answer;
			expect(await types()).toEqual([
				"federation.grant.refresh_failed write_lost",
				"federation.grant.token.denied grant_revoked/client",
			]);
		});
	});

	describe("when something in the composition is broken", () => {
		it("lets go of the lock when the look under it throws", async () => {
			await h.seed();
			setNow(DUE);
			let lookups = 0;
			const connectionOf = h.deps.connection;
			h.deps.connection = (name) => {
				lookups += 1;
				if (lookups === 2) throw new Error("composition bug");
				return connectionOf(name);
			};
			await expect(retrieve()).rejects.toThrow("composition bug");
			const lock = await h.store.acquireRefreshLock("g-1", { ttlMs: 1_000, waitForMs: 0 });
			expect(lock.acquired).toBe(true);
		});

		it("answers 503, says so to the logger, and leaves the lock to run out when the worker itself fails: the upstream may have been asked", async () => {
			await h.seed();
			setNow(GONE);
			h.refresh.mockResolvedValue(refreshed("1", DUE));
			const reported: Array<{ during: string }> = [];
			h.deps.report = (failure) => reported.push(failure);
			let readings = 0;
			h.deps.now = () => {
				readings += 1;
				// The eighth reading is the worker's first: two for each of the two
				// looks, one before the lock is asked for, one when it is acknowledged,
				// and one when the upstream is about to be asked.
				if (readings === 8) throw new Error("clock bug");
				return now();
			};
			expect(await retrieve()).toStrictEqual({
				ok: false,
				code: "temporarily_unavailable",
				reason: "upstream",
			});
			expect(reported.map((failure) => failure.during)).toContain("refresh");
			expect(await types()).toContain("federation.grant.refresh_failed internal_error");
			expect(await h.store.acquireRefreshLock("g-1", { ttlMs: 1_000, waitForMs: 0 })).toEqual({
				acquired: false,
				reason: "timeout",
			});
		});

		it("is not troubled by a lock that cannot be let go of: it runs out, and the logger is told", async () => {
			await h.seed();
			setNow(DUE);
			h.refresh.mockResolvedValue(refreshed("1", DUE));
			const reported: Array<{ during: string }> = [];
			h.deps.report = (failure) => reported.push(failure);
			const real = h.store.acquireRefreshLock.bind(h.store);
			vi.spyOn(h.store, "acquireRefreshLock").mockImplementation(async (id, options) => {
				const lock = await real(id, options);
				return lock.acquired
					? { ...lock, release: () => Promise.reject(new Error("redis down")) }
					: lock;
			});
			expect(await retrieve()).toMatchObject({ ok: true, accessToken: "at-1" });
			await Promise.all(h.background);
			expect(reported.map((failure) => failure.during)).toEqual(["release"]);
		});

		it("tells the logger what an upstream refusal was, and an audit sink's failure, and puts neither in the answer", async () => {
			await h.seed();
			setNow(GONE);
			const refusal = Object.assign(new Error(`echoed ${SECRET}`), { status: 503 });
			h.refresh.mockRejectedValue(refusal);
			const reported: Array<{ during: string; error: unknown }> = [];
			h.deps.report = (failure) => reported.push(failure);
			h.deps.audit = () => {
				throw new Error("sink down");
			};
			const result = await retrieve();
			await Promise.all(h.background);
			expect(JSON.stringify(result)).not.toContain(SECRET);
			expect(reported.find((failure) => failure.during === "upstream")?.error).toBe(refusal);
			expect(reported.filter((failure) => failure.during === "audit").length).toBeGreaterThan(0);

			// A reporter that throws is not worth an answer either.
			h.deps.report = () => {
				throw new Error("logger down");
			};
			expect(await retrieve()).toMatchObject({ code: "temporarily_unavailable" });
		});
	});

	describe("the audit sink", () => {
		it("never skips a write or a release by failing", async () => {
			await h.seed();
			setNow(DUE);
			h.refresh.mockResolvedValue(refreshed("1", DUE));
			h.deps.audit = () => {
				throw new Error("sink down");
			};
			expect(await retrieve()).toMatchObject({ ok: true, accessToken: "at-1" });

			h.deps.audit = async () => {
				throw new Error("sink down");
			};
			setNow(new Date(DUE.getTime() + HOUR));
			h.refresh.mockResolvedValue(refreshed("2", now()));
			expect(await retrieve()).toMatchObject({ ok: true, accessToken: "at-2" });
			const lock = await h.store.acquireRefreshLock("g-1", { ttlMs: 1_000, waitForMs: 0 });
			expect(lock.acquired).toBe(true);
		});

		it("is told who, what and which request, and never a secret", async () => {
			await h.seed();
			setNow(DUE);
			h.refresh.mockResolvedValue(refreshed("1", DUE));
			await retrieve();
			await Promise.all(h.background);
			expect(h.events.find((event) => event.type === "federation.grant.refreshed")).toStrictEqual({
				type: "federation.grant.refreshed",
				correlationId: "req-1",
				grantId: "g-1",
				clientId: "agent",
				subject: "u-1",
				connection: "okta-calendar",
				upstream: { issuer: "https://dev-1.okta.test", subject: "00u-alice" },
				scopes: [...SCOPES],
				outcome: "success",
			});
			const everything = JSON.stringify(h.events);
			expect(everything).not.toContain(SECRET);
			expect(everything).not.toContain("at-1");
		});
	});
});

describe("assertFederationGrantRetrievalLimits (#593, D12)", () => {
	it("accepts the defaults: 25 s + 3 s leave two of the lock's 30", () => {
		expect(() => assertFederationGrantRetrievalLimits(limits)).not.toThrow();
	});

	it("refuses a lock that could run out before a refresh has settled, and wants a margin: a fit by a millisecond is not one", () => {
		// The lease is counted from when the acquisition was acknowledged, which
		// is after the store started the lock's TTL; and timers fire late.
		const fits = limits.upstreamHardTimeoutMs + limits.persistRetryBudgetMs;
		expect(FEDERATION_GRANT_REFRESH_LOCK_MARGIN_MS).toBe(1_000);
		for (const refreshLockTtlMs of [fits, fits + 1, fits + 999]) {
			expect(() => assertFederationGrantRetrievalLimits({ ...limits, refreshLockTtlMs })).toThrow(
				RangeError,
			);
		}
		expect(() =>
			assertFederationGrantRetrievalLimits({ ...limits, refreshLockTtlMs: fits + 1_000 }),
		).not.toThrow();
	});

	it("refuses a soft deadline past the hard one", () => {
		expect(() =>
			assertFederationGrantRetrievalLimits({
				...limits,
				upstreamTimeoutMs: limits.upstreamHardTimeoutMs + 1,
			}),
		).toThrow(RangeError);
		expect(() =>
			assertFederationGrantRetrievalLimits({
				...limits,
				upstreamTimeoutMs: limits.upstreamHardTimeoutMs,
			}),
		).not.toThrow();
	});

	it("refuses every limit that is not a finite number: NaN compares as fine everywhere", () => {
		// Under a NaN refresh buffer no token is refreshed before it has died; a
		// NaN retry interval switches the marker's limit off; a NaN soft deadline
		// answers at once.
		for (const key of Object.keys(limits) as Array<keyof typeof limits>) {
			for (const bad of [
				Number.NaN,
				-1,
				Number.POSITIVE_INFINITY,
				undefined as unknown as number,
			]) {
				expect(() => assertFederationGrantRetrievalLimits({ ...limits, [key]: bad }), key).toThrow(
					RangeError,
				);
			}
		}
	});

	it("refuses zero where a timer or a lock is given the value, and takes it for an allowance", () => {
		for (const key of [
			"upstreamTimeoutMs",
			"upstreamHardTimeoutMs",
			"refreshLockTtlMs",
			"persistRetryBudgetMs",
			"ineligibleRetryAfterMs",
			"maxExpiresInMs",
		] as const) {
			expect(() => assertFederationGrantRetrievalLimits({ ...limits, [key]: 0 }), key).toThrow(
				RangeError,
			);
		}
		for (const key of ["revocationSkewMs", "refreshBufferMs", "lockWaitMs"] as const) {
			expect(
				() => assertFederationGrantRetrievalLimits({ ...limits, [key]: 0 }),
				key,
			).not.toThrow();
		}
	});

	it("refuses a lock wait that does not fit a timer once the three seconds a store is given over it are added", () => {
		const roomy = { ...limits, refreshLockTtlMs: 2_147_483_647 };
		expect(() =>
			assertFederationGrantRetrievalLimits({ ...roomy, lockWaitMs: 2_147_483_647 - 3_000 }),
		).not.toThrow();
		expect(() =>
			assertFederationGrantRetrievalLimits({ ...roomy, lockWaitMs: 2_147_483_647 - 2_999 }),
		).toThrow(/does not fit a timer/);
	});

	it("refuses a duration a timer cannot hold: past 2^31 ms it fires at once", () => {
		// Each on its own, with the lock long enough that nothing else is what
		// refuses it: every one of these is handed to a timer.
		const roomy = { ...limits, refreshLockTtlMs: 2_147_483_647 };
		const tooLong = 2_147_483_648;
		expect(() => assertFederationGrantRetrievalLimits(roomy)).not.toThrow();
		for (const key of [
			"upstreamTimeoutMs",
			"upstreamHardTimeoutMs",
			"refreshLockTtlMs",
			"persistRetryBudgetMs",
			"lockWaitMs",
		] as const) {
			expect(
				() =>
					assertFederationGrantRetrievalLimits({
						...roomy,
						// Kept in order, so that the order is not what refuses it.
						...(key === "upstreamTimeoutMs" ? { upstreamHardTimeoutMs: tooLong } : {}),
						[key]: tooLong,
					}),
				key,
			).toThrow(/does not fit a timer/);
		}
	});
});
