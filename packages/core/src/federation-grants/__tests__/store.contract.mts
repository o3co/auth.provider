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

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { FEDERATION_GRANT_LIFETIME_CEILING_MS } from "#/federation-grants/lifetime.mjs";
import type { FederationGrantStore, FederationGrantWrite } from "#/federation-grants/store.mjs";
import {
	type AuthorizedFederationGrant,
	type FederationGrantAuthorization,
	type FederationGrantCredentials,
	type FederationGrantIneligibilityMarker,
	type FederationGrantRefreshFailureInput,
	hasFederationGrantAuthorization,
} from "#/federation-grants/types.mjs";

export interface FederationGrantStoreContractFactory<
	S extends FederationGrantStore = FederationGrantStore,
> {
	create(): Promise<S>;
	teardown?(store: S): Promise<void>;
	/**
	 * Whether the store still HOLDS a credential for the grant — looked at from
	 * outside the port, on purpose. Through the port a grant that is not `active`
	 * reads as `absent` whether its secret was deleted or is only hidden behind a
	 * status check, so an adapter whose revocation forgot the delete would pass
	 * every other test here, with a live refresh token at rest beside a revoked
	 * grant. For a Redis adapter this is whether the credential key exists.
	 */
	credentialResident(store: S, grantId: string): Promise<boolean>;
}

const MIN = 60_000;
const DAY = 86_400_000;

/**
 * The real clock, and not a fixed date. Every rule below is judged against the
 * `now` a test passes in, but an adapter also hangs a key TTL on the stored
 * `expiresAt` as a safety net, and a fixture dated in the past would have a
 * real store expire the record before the test reads it.
 *
 * Not on a whole second: an adapter that truncates an instant to seconds when
 * it stores it would otherwise hand every fixture back unchanged.
 *
 * Taken per test, and not once at import: a fixture's intent lapses ten
 * minutes after this instant, and a suite that runs against a real store —
 * a container to start, connections to open, locks that wait on real timers —
 * takes long enough for a clock fixed at import to put that lapse in the
 * past. The record would then be reclaimed by the store's own clock partway
 * through the suite, which reads as a failure of whatever test looked next.
 */
let T0 = new Date(Math.floor(Date.now() / 1000) * 1000 + 137);
const at = (ms: number): Date => new Date(T0.getTime() + ms);
const INVALID = new Date(Number.NaN);

/** Never handed out by reference: a fixture that shares it would hide a store that does too. */
const SCOPES: readonly string[] = ["openid", "offline_access", "calendar.read"];

const pendingInput = (id = "g-1", handle = "h-1") => ({
	id,
	subject: "u-1",
	clientId: "agent",
	connection: "okta-calendar",
	intent: { handle, expiresAt: at(10 * MIN) },
	now: T0,
});

const authorization = (
	over: Partial<FederationGrantAuthorization> = {},
): FederationGrantAuthorization => ({
	identityRevision: "identity-1",
	authorizationRevision: "authorization-1",
	upstream: { issuer: "https://dev-1.okta.test", subject: "00u-alice" },
	scopes: [...SCOPES],
	consent: { at: at(MIN), sid: "sid-1", scopes: [...SCOPES] },
	authorizedAt: at(2 * MIN),
	expiresAt: at(30 * DAY),
	...over,
});

const credentials = (tag: string): FederationGrantCredentials => ({
	refreshToken: `rt-${tag}`,
	accessToken: {
		value: `at-${tag}`,
		tokenType: "Bearer",
		obtainedAt: at(2 * MIN),
		issuedLifetime: 3600,
		scopes: [...SCOPES],
	},
});

const marker = (): FederationGrantIneligibilityMarker => ({
	reason: "lifetime_over_maximum",
	at: at(DAY),
	judgedAgainst: 1800,
});

/** The consent a reauthorization a day later records. */
const renewal = (over: Partial<FederationGrantAuthorization> = {}) =>
	authorization({
		authorizationRevision: "authorization-2",
		scopes: ["openid", "offline_access"],
		consent: { at: at(DAY + MIN), sid: "sid-2", scopes: ["openid", "offline_access"] },
		authorizedAt: at(DAY + 2 * MIN),
		expiresAt: at(60 * DAY),
		...over,
	});

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** Long enough that a stalled test process (#357) does not read as an expired lock. */
const HELD = { ttlMs: 120_000, waitForMs: 0 };

/**
 * The behaviour every {@link FederationGrantStore} adapter shares (#593, D2,
 * D16). The memory adapter runs this in-tree; the Redis adapter runs the same
 * suite against a real Redis, so the two cannot disagree about what a grant
 * is, or about which write wins.
 *
 * Time is passed in, never faked: the port takes it from its caller. The lock
 * is the exception — its TTL is real time in any adapter — and its tests use
 * real, short waits.
 */
export function runFederationGrantStoreContract<S extends FederationGrantStore>(
	name: string,
	factory: FederationGrantStoreContractFactory<S>,
): void {
	describe(`FederationGrantStore contract — ${name}`, () => {
		let store: S;

		beforeEach(async () => {
			store = await factory.create();
			// After the store is up: whatever creating it cost is not spent out of
			// the fixtures' ten minutes.
			T0 = new Date(Math.floor(Date.now() / 1000) * 1000 + 137);
		});

		afterEach(async () => {
			await factory.teardown?.(store);
		});

		const resident = (grantId: string): Promise<boolean> =>
			factory.credentialResident(store, grantId);

		/** A grant taken from `pending` to `active`: version 2, credentials `1`, intent `h-<id>` retired. */
		const activated = async (id = "g-1"): Promise<AuthorizedFederationGrant> => {
			await store.createPending(pendingInput(id, `h-${id}`));
			const written = await store.activate({
				grantId: id,
				intentHandle: `h-${id}`,
				authorization: authorization(),
				credentials: credentials("1"),
				now: at(2 * MIN),
			});
			if (!written.ok || written.grant.status !== "active") {
				throw new Error("fixture: the activation did not succeed");
			}
			return written.grant;
		};

		/** The same, then marked as needing the user: version 3, no credentials. */
		const needingUser = async (id = "g-1"): Promise<AuthorizedFederationGrant> => {
			const grant = await activated(id);
			const written = await store.requireReauthorization({
				grantId: id,
				expectedVersion: grant.version,
				now: at(3 * MIN),
			});
			if (!written.ok || written.grant.status !== "reauthorization_required") {
				throw new Error("fixture: the grant was not marked");
			}
			return written.grant;
		};

		/**
		 * An active grant that carries both usage fields, so that a write which
		 * drops one shows: version 3, credentials `{ refreshToken: "rt-2" }`.
		 */
		const inUse = async (id = "g-1"): Promise<AuthorizedFederationGrant> => {
			const grant = await activated(id);
			await store.touch(id, at(3 * MIN));
			const written = await store.replaceCredentials({
				grantId: id,
				expectedVersion: grant.version,
				credentials: { refreshToken: "rt-2" },
				ineligible: marker(),
				now: at(4 * MIN),
			});
			if (!written.ok || written.grant.status !== "active") {
				throw new Error("fixture: the refresh did not succeed");
			}
			return written.grant;
		};

		/** Names `h-re` as the current intent of `g-1`, a day in, good for ten minutes. */
		const nameRenewalIntent = (
			handle = "h-re",
			now = at(DAY),
			grantId = "g-1",
		): Promise<FederationGrantWrite> =>
			store.nameIntent({ grantId, intent: { handle, expiresAt: at(DAY + 10 * MIN) }, now });

		const renew = (
			over: Partial<Parameters<FederationGrantStore["activate"]>[0]> = {},
		): Promise<FederationGrantWrite> =>
			store.activate({
				grantId: "g-1",
				intentHandle: "h-re",
				authorization: renewal(),
				credentials: credentials("2"),
				now: at(DAY + 2 * MIN),
				...over,
			});

		const openedCredentials = async (id: string, now: Date) => {
			const opened = await store.open(id, now);
			return opened?.credentials;
		};

		it("declares a non-empty kind", () => {
			expect(store.kind).toBeTruthy();
		});

		describe("createPending", () => {
			it("creates the pending record, at version 1, with nothing an authorization would add", async () => {
				const written = await store.createPending(pendingInput());
				const expected = {
					id: "g-1",
					subject: "u-1",
					clientId: "agent",
					connection: "okta-calendar",
					status: "pending",
					createdAt: T0,
					version: 1,
				};
				expect(written).toStrictEqual({ ok: true, grant: expected });
				expect(await store.find("g-1", T0)).toStrictEqual(expected);
				expect(await resident("g-1")).toBe(false);
			});

			it("refuses an ID that is taken, whatever state that record is in, and leaves it alone", async () => {
				const other = (id: string) => ({
					...pendingInput(id, "h-other"),
					subject: "u-2",
					now: at(3 * MIN),
				});

				await store.createPending(pendingInput("g-pending"));
				expect(await store.createPending(other("g-pending"))).toEqual({ ok: false });
				expect((await store.find("g-pending", at(3 * MIN)))?.subject).toBe("u-1");
				expect(await store.isCurrentIntent("g-pending", "h-1", at(3 * MIN))).toBe(true);
				expect(await store.isCurrentIntent("g-pending", "h-other", at(3 * MIN))).toBe(false);

				const active = await activated("g-active");
				expect(await store.createPending(other("g-active"))).toEqual({ ok: false });
				expect(await store.open("g-active", at(3 * MIN))).toStrictEqual({
					grant: active,
					credentials: { state: "ok", value: credentials("1") },
				});

				await store.createPending(pendingInput("g-revoked"));
				await store.revoke("g-revoked", "client", at(MIN));
				expect(await store.createPending(other("g-revoked"))).toEqual({ ok: false });
				expect((await store.find("g-revoked", at(3 * MIN)))?.status).toBe("revoked");
			});

			it("lets the pending grant lapse with its first intent, from the instant the intent does", async () => {
				await store.createPending(pendingInput());
				expect(await store.find("g-1", at(10 * MIN - 1))).not.toBeNull();

				const lapsed = at(10 * MIN);
				expect(await store.find("g-1", lapsed)).toBeNull();
				expect(await store.listBySubject("u-1", lapsed)).toEqual([]);
				expect(await store.inspect("g-1", lapsed)).toBeNull();
				expect(await store.open("g-1", lapsed)).toBeNull();
				expect(await store.isCurrentIntent("g-1", "h-1", lapsed)).toBe(false);
				expect(
					await store.activate({
						grantId: "g-1",
						intentHandle: "h-1",
						authorization: authorization({
							consent: { at: lapsed, sid: "sid-1", scopes: [...SCOPES] },
							authorizedAt: lapsed,
						}),
						credentials: credentials("1"),
						now: lapsed,
					}),
				).toEqual({ ok: false });
				expect(await store.revoke("g-1", "client", lapsed)).toEqual({ ok: false });
				expect(await resident("g-1")).toBe(false);
			});

			it("creates nothing for an intent that has already lapsed, or whose expiry is not a date", async () => {
				for (const expiresAt of [T0, at(-1), INVALID]) {
					expect(
						await store.createPending({ ...pendingInput(), intent: { handle: "h-1", expiresAt } }),
					).toEqual({ ok: false });
				}
				expect(await store.find("g-1", T0)).toBeNull();
			});
		});

		describe("the intent a grant points at", () => {
			describe("isCurrentIntent", () => {
				it("is true for the current handle until it lapses, and for nothing else", async () => {
					await store.createPending(pendingInput());
					expect(await store.isCurrentIntent("g-1", "h-1", T0)).toBe(true);
					expect(await store.isCurrentIntent("g-1", "h-other", T0)).toBe(false);
					expect(await store.isCurrentIntent("g-1", "", T0)).toBe(false);
					expect(await store.isCurrentIntent("g-unknown", "h-1", T0)).toBe(false);
					expect(await store.isCurrentIntent("g-1", "h-1", at(10 * MIN - 1))).toBe(true);
					expect(await store.isCurrentIntent("g-1", "h-1", at(10 * MIN))).toBe(false);
				});

				it("spends nothing: the callback asks before it exchanges the code, and the activation still succeeds (D7)", async () => {
					await store.createPending(pendingInput());
					expect(await store.isCurrentIntent("g-1", "h-1", at(MIN))).toBe(true);
					expect(await store.isCurrentIntent("g-1", "h-1", at(MIN))).toBe(true);
					const written = await store.activate({
						grantId: "g-1",
						intentHandle: "h-1",
						authorization: authorization(),
						credentials: credentials("1"),
						now: at(2 * MIN),
					});
					expect(written.ok).toBe(true);
				});

				it("follows a reauthorization intent: the newer handle is current, the older one is superseded", async () => {
					await activated();
					await nameRenewalIntent("h-re-1");
					await store.nameIntent({
						grantId: "g-1",
						intent: { handle: "h-re-2", expiresAt: at(DAY + 11 * MIN) },
						now: at(DAY + MIN),
					});
					expect(await store.isCurrentIntent("g-1", "h-re-1", at(DAY + 2 * MIN))).toBe(false);
					expect(await store.isCurrentIntent("g-1", "h-re-2", at(DAY + 2 * MIN))).toBe(true);
					expect(await store.isCurrentIntent("g-1", "h-re-2", at(DAY + 11 * MIN))).toBe(false);
				});

				it("is false once the intent is retired: by the activation it led to, and by a revocation", async () => {
					await activated();
					expect(await store.isCurrentIntent("g-1", "h-g-1", at(3 * MIN))).toBe(false);

					await nameRenewalIntent();
					await store.revoke("g-1", "subject", at(DAY + MIN));
					expect(await store.isCurrentIntent("g-1", "h-re", at(DAY + 2 * MIN))).toBe(false);
				});

				it("is false from the stored expiry on: a code exchanged for a grant that cannot be activated is a refresh token nothing will use", async () => {
					await activated("g-active");
					await needingUser("g-needs-user");
					for (const grantId of ["g-active", "g-needs-user"]) {
						await store.nameIntent({
							grantId,
							intent: { handle: "h-late", expiresAt: at(30 * DAY + 9 * MIN) },
							now: at(30 * DAY - MIN),
						});
						expect(await store.isCurrentIntent(grantId, "h-late", at(30 * DAY - 1)), grantId).toBe(
							true,
						);
						expect(await store.isCurrentIntent(grantId, "h-late", at(30 * DAY)), grantId).toBe(
							false,
						);
					}
				});
			});

			describe("nameIntent", () => {
				it("changes nothing a client can see, and does not bump the version", async () => {
					const grant = await inUse();
					expect(grant).toHaveProperty("lastUsedAt");
					expect(grant).toHaveProperty("ineligible");
					expect(await nameRenewalIntent()).toStrictEqual({ ok: true, grant });
					expect(await store.find("g-1", at(DAY))).toStrictEqual(grant);
				});

				it("does not cost a refresh in flight its write", async () => {
					// A reauthorization the user may never finish must not make a
					// refresh drop the rotated refresh token it is about to store.
					const grant = await activated();
					await nameRenewalIntent();
					const written = await store.replaceCredentials({
						grantId: "g-1",
						expectedVersion: grant.version,
						credentials: credentials("2"),
						ineligible: null,
						now: at(DAY + MIN),
					});
					expect(written.ok).toBe(true);
				});

				it("names an intent for a grant that needs the user", async () => {
					await needingUser();
					expect((await nameRenewalIntent()).ok).toBe(true);
					expect(await store.isCurrentIntent("g-1", "h-re", at(DAY + MIN))).toBe(true);
				});

				it("refuses a pending grant: a first-time intent makes a new grant, and never takes over this one's", async () => {
					await store.createPending(pendingInput());
					expect(
						await store.nameIntent({
							grantId: "g-1",
							intent: { handle: "h-re", expiresAt: at(20 * MIN) },
							now: at(MIN),
						}),
					).toEqual({ ok: false });
					expect(await store.isCurrentIntent("g-1", "h-1", at(MIN))).toBe(true);
					expect(await store.isCurrentIntent("g-1", "h-re", at(MIN))).toBe(false);
				});

				it("refuses a grant whose consented lifetime has ended, whichever state it was in", async () => {
					await activated("g-active");
					await needingUser("g-needs-user");
					for (const grantId of ["g-active", "g-needs-user"]) {
						expect(
							await store.nameIntent({
								grantId,
								intent: { handle: "h-late", expiresAt: at(30 * DAY + 10 * MIN) },
								now: at(30 * DAY),
							}),
							grantId,
						).toEqual({ ok: false });
						expect(await store.isCurrentIntent(grantId, "h-late", at(30 * DAY - 1)), grantId).toBe(
							false,
						);
					}
				});

				it("refuses a revoked grant and an unknown one", async () => {
					expect(await nameRenewalIntent()).toEqual({ ok: false });
					await activated();
					await store.revoke("g-1", "client", at(DAY - MIN));
					expect(await nameRenewalIntent()).toEqual({ ok: false });
					expect(await store.isCurrentIntent("g-1", "h-re", at(DAY))).toBe(false);
				});

				it("names nothing for an intent that has already lapsed, or whose expiry is not a date", async () => {
					await activated();
					for (const expiresAt of [at(DAY), at(DAY - 1), INVALID]) {
						expect(
							await store.nameIntent({
								grantId: "g-1",
								intent: { handle: "h-re", expiresAt },
								now: at(DAY),
							}),
						).toEqual({ ok: false });
					}
					expect(await store.isCurrentIntent("g-1", "h-re", at(DAY - 2))).toBe(false);
				});
			});

			describe("retireIntent", () => {
				it("retires whichever intent is current, and changes nothing else: the renewal in flight cannot finish (D13)", async () => {
					const grant = await inUse();
					await nameRenewalIntent();
					expect(await store.retireIntent({ grantId: "g-1", now: at(DAY + MIN) })).toStrictEqual({
						ok: true,
						grant,
					});
					expect(await store.isCurrentIntent("g-1", "h-re", at(DAY + MIN))).toBe(false);
					expect(await renew()).toEqual({ ok: false });
					expect(await store.open("g-1", at(DAY + 3 * MIN))).toStrictEqual({
						grant,
						credentials: { state: "ok", value: { refreshToken: "rt-2" } },
					});
				});

				it("retires a named handle only while it is the current one: a refusal for a superseded intent does not end the newer one", async () => {
					await activated();
					await nameRenewalIntent("h-re-1");
					await nameRenewalIntent("h-re-2", at(DAY + MIN));

					// A superseded handle, and an empty one: a handle that is given is a
					// handle to match, and "" matches nothing — it is not "whichever".
					for (const handle of ["h-re-1", ""]) {
						expect(
							await store.retireIntent({ grantId: "g-1", handle, now: at(DAY + 2 * MIN) }),
							JSON.stringify(handle),
						).toEqual({ ok: false });
					}
					expect(await store.isCurrentIntent("g-1", "h-re-2", at(DAY + 2 * MIN))).toBe(true);

					expect(
						(await store.retireIntent({ grantId: "g-1", handle: "h-re-2", now: at(DAY + 2 * MIN) }))
							.ok,
					).toBe(true);
					expect(await store.isCurrentIntent("g-1", "h-re-2", at(DAY + 2 * MIN))).toBe(false);
				});

				it("does not cost a refresh in flight its write", async () => {
					const grant = await activated();
					await nameRenewalIntent();
					await store.retireIntent({ grantId: "g-1", now: at(DAY + MIN) });
					const written = await store.replaceCredentials({
						grantId: "g-1",
						expectedVersion: grant.version,
						credentials: credentials("2"),
						ineligible: null,
						now: at(DAY + 2 * MIN),
					});
					expect(written.ok).toBe(true);
				});

				it("fails when there is nothing to retire", async () => {
					expect(await store.retireIntent({ grantId: "g-unknown", now: at(DAY) })).toEqual({
						ok: false,
					});

					// The intent that led to the activation is retired already.
					await activated();
					expect(await store.retireIntent({ grantId: "g-1", now: at(DAY) })).toEqual({ ok: false });

					await nameRenewalIntent();
					await store.revoke("g-1", "client", at(DAY + MIN));
					expect(await store.retireIntent({ grantId: "g-1", now: at(DAY + 2 * MIN) })).toEqual({
						ok: false,
					});
				});

				it("refuses a pending grant: its first intent is its life, and the grant lapses with it", async () => {
					await store.createPending(pendingInput());
					expect(await store.retireIntent({ grantId: "g-1", now: at(MIN) })).toEqual({ ok: false });
					expect(await store.retireIntent({ grantId: "g-1", handle: "h-1", now: at(MIN) })).toEqual(
						{
							ok: false,
						},
					);
					expect(await store.isCurrentIntent("g-1", "h-1", at(MIN))).toBe(true);
				});
			});

			it("survives what happens in the background: a refresh must not cost the user the reauthorization they are in the middle of", async () => {
				const background: Array<
					[name: string, run: (grant: AuthorizedFederationGrant) => Promise<unknown>]
				> = [
					[
						"replaceCredentials",
						(grant) =>
							store.replaceCredentials({
								grantId: grant.id,
								expectedVersion: grant.version,
								credentials: credentials("bg"),
								ineligible: marker(),
								now: at(DAY + MIN),
							}),
					],
					[
						"requireReauthorization",
						(grant) =>
							store.requireReauthorization({
								grantId: grant.id,
								expectedVersion: grant.version,
								now: at(DAY + MIN),
							}),
					],
					["touch", (grant) => store.touch(grant.id, at(DAY + MIN))],
				];
				for (const [what, run] of background) {
					const grant = await activated(`g-${what}`);
					await nameRenewalIntent("h-re", at(DAY), grant.id);
					await run(grant);
					expect(await store.isCurrentIntent(grant.id, "h-re", at(DAY + 2 * MIN)), what).toBe(true);
					expect((await renew({ grantId: grant.id })).ok, what).toBe(true);
				}
			});

			it("is never on a record, whichever read or write returns it: records go into responses and audit events", async () => {
				const lodged = await store.createPending(pendingInput("g-pending", "h-secret-first"));
				const grant = await activated("g-1");
				const named = await nameRenewalIntent("h-secret-renewal");
				// With an intent named, each of the writes that leave it alone.
				const refreshed = await store.replaceCredentials({
					grantId: "g-1",
					expectedVersion: grant.version,
					credentials: credentials("2"),
					ineligible: marker(),
					now: at(DAY),
				});
				await activated("g-marked");
				await nameRenewalIntent("h-secret-marked", at(DAY), "g-marked");
				const marked = await store.requireReauthorization({
					grantId: "g-marked",
					expectedVersion: 2,
					now: at(DAY),
				});
				await activated("g-ended");
				await nameRenewalIntent("h-secret-ended", at(DAY), "g-ended");
				const ended = await store.revoke("g-ended", "client", at(DAY));
				expect([lodged.ok, named.ok, refreshed.ok, marked.ok, ended.ok]).toEqual([
					true,
					true,
					true,
					true,
					true,
				]);

				const everything = JSON.stringify([
					lodged,
					named,
					refreshed,
					marked,
					ended,
					await store.find("g-pending", at(DAY)),
					await store.find("g-1", at(DAY)),
					await store.inspect("g-pending", T0),
					await store.inspect("g-1", at(DAY)),
					await store.open("g-pending", T0),
					await store.open("g-1", at(DAY)),
					await store.listBySubject("u-1", T0),
					await store.listBySubject("u-1", at(DAY)),
					await store.retireIntent({ grantId: "g-1", now: at(DAY + MIN) }),
				]);
				expect(everything).toContain("g-pending");
				expect(everything).not.toContain("h-secret");
				expect(everything).not.toContain("h-g-");
			});
		});

		describe("activate", () => {
			it("takes a pending grant to active: authorization set, credentials written, version bumped", async () => {
				const grant = await activated();
				expect(grant).toStrictEqual({
					id: "g-1",
					subject: "u-1",
					clientId: "agent",
					connection: "okta-calendar",
					status: "active",
					createdAt: T0,
					version: 2,
					...authorization(),
				});
				expect(await store.find("g-1", at(3 * MIN))).toStrictEqual(grant);
				expect(await store.open("g-1", at(3 * MIN))).toStrictEqual({
					grant,
					credentials: { state: "ok", value: credentials("1") },
				});
				expect(await store.inspect("g-1", at(3 * MIN))).toStrictEqual({ grant, credentials: "ok" });
				expect(await resident("g-1")).toBe(true);
			});

			it("retires the intent: the same handle cannot activate twice", async () => {
				const grant = await activated();
				expect(
					await store.activate({
						grantId: "g-1",
						intentHandle: "h-g-1",
						authorization: authorization({ scopes: ["openid"] }),
						credentials: credentials("replayed"),
						now: at(3 * MIN),
					}),
				).toEqual({ ok: false });
				expect(await store.open("g-1", at(3 * MIN))).toStrictEqual({
					grant,
					credentials: { state: "ok", value: credentials("1") },
				});
			});

			it("refuses a handle that is not the current one, and leaves the grant pending", async () => {
				await store.createPending(pendingInput());
				for (const intentHandle of ["h-stale", ""]) {
					expect(
						await store.activate({
							grantId: "g-1",
							intentHandle,
							authorization: authorization(),
							credentials: credentials("1"),
							now: at(2 * MIN),
						}),
					).toEqual({ ok: false });
				}
				expect((await store.find("g-1", at(2 * MIN)))?.status).toBe("pending");
				expect(await resident("g-1")).toBe(false);
				expect(await store.isCurrentIntent("g-1", "h-1", at(2 * MIN))).toBe(true);
			});

			it("refuses an unknown grant", async () => {
				expect(
					await store.activate({
						grantId: "g-unknown",
						intentHandle: "h-1",
						authorization: authorization(),
						credentials: credentials("1"),
						now: at(2 * MIN),
					}),
				).toEqual({ ok: false });
				expect(await store.find("g-unknown", at(2 * MIN))).toBeNull();
				expect(await resident("g-unknown")).toBe(false);
			});

			it("refuses an expiry beyond the lifetime ceiling of the consent, and accepts one at it (D3)", async () => {
				await store.createPending(pendingInput());
				const consentAt = at(MIN);
				const beyond = new Date(consentAt.getTime() + FEDERATION_GRANT_LIFETIME_CEILING_MS + 1);
				expect(
					await store.activate({
						grantId: "g-1",
						intentHandle: "h-1",
						authorization: authorization({ expiresAt: beyond }),
						credentials: credentials("1"),
						now: at(2 * MIN),
					}),
				).toEqual({ ok: false });
				expect((await store.find("g-1", at(2 * MIN)))?.status).toBe("pending");
				expect(await resident("g-1")).toBe(false);

				const atCeiling = new Date(consentAt.getTime() + FEDERATION_GRANT_LIFETIME_CEILING_MS);
				const written = await store.activate({
					grantId: "g-1",
					intentHandle: "h-1",
					authorization: authorization({ expiresAt: atCeiling }),
					credentials: credentials("1"),
					now: at(2 * MIN),
				});
				expect(written.ok).toBe(true);
			});

			it("refuses an expiry that is not after the write", async () => {
				await store.createPending(pendingInput());
				expect(
					await store.activate({
						grantId: "g-1",
						intentHandle: "h-1",
						authorization: authorization({ expiresAt: at(2 * MIN) }),
						credentials: credentials("1"),
						now: at(2 * MIN),
					}),
				).toEqual({ ok: false });
			});

			it("refuses a consent or an authorization dated after the write: a boundary stamped from then on must always cover it (D13)", async () => {
				// With no allowance at all. The backstop's comparison has its own, for
				// the clocks of two replicas; any this rule added would come on top of
				// it, and a consent dated thirty seconds ahead would slip past a
				// revocation stamped ten seconds after the activation — for good,
				// since neither instant ever changes.
				await store.createPending(pendingInput());
				const now = at(2 * MIN);
				const ahead = new Date(now.getTime() + 1);
				for (const over of [
					{ consent: { at: ahead, sid: "sid-1", scopes: [...SCOPES] } },
					{ authorizedAt: ahead },
				]) {
					expect(
						await store.activate({
							grantId: "g-1",
							intentHandle: "h-1",
							authorization: authorization(over),
							credentials: credentials("1"),
							now,
						}),
					).toEqual({ ok: false });
					expect(await resident("g-1")).toBe(false);
					expect(await store.isCurrentIntent("g-1", "h-1", now)).toBe(true);
				}

				const written = await store.activate({
					grantId: "g-1",
					intentHandle: "h-1",
					authorization: authorization({
						consent: { at: now, sid: "sid-1", scopes: [...SCOPES] },
						authorizedAt: now,
					}),
					credentials: credentials("1"),
					now,
				});
				expect(written.ok).toBe(true);
			});

			it("refuses dates that are not dates, wherever they are", async () => {
				await store.createPending(pendingInput());
				const token = credentials("1").accessToken;
				if (token === undefined) throw new Error("fixture");
				const attempts = [
					{ authorization: authorization({ expiresAt: INVALID }) },
					{
						authorization: authorization({
							consent: { at: INVALID, sid: "sid-1", scopes: [...SCOPES] },
						}),
					},
					{ authorization: authorization({ authorizedAt: INVALID }) },
					{
						credentials: { refreshToken: "rt-1", accessToken: { ...token, obtainedAt: INVALID } },
					},
				];
				for (const attempt of attempts) {
					expect(
						await store.activate({
							grantId: "g-1",
							intentHandle: "h-1",
							authorization: authorization(),
							credentials: credentials("1"),
							now: at(2 * MIN),
							...attempt,
						}),
					).toEqual({ ok: false });
				}
				expect((await store.find("g-1", at(2 * MIN)))?.status).toBe("pending");
				expect(await resident("g-1")).toBe(false);
			});

			describe("as a reauthorization", () => {
				it("keeps the grant's ID and createdAt, and replaces the authorization as a whole", async () => {
					await store.createPending(pendingInput());
					await store.activate({
						grantId: "g-1",
						intentHandle: "h-1",
						authorization: authorization({ resource: "https://calendar.example/" }),
						credentials: credentials("1"),
						now: at(2 * MIN),
					});
					expect(await store.find("g-1", at(3 * MIN))).toHaveProperty(
						"resource",
						"https://calendar.example/",
					);

					await nameRenewalIntent();
					expect((await renew()).ok).toBe(true);
					const grant = await store.find("g-1", at(DAY + 3 * MIN));
					expect(grant).toStrictEqual({
						id: "g-1",
						subject: "u-1",
						clientId: "agent",
						connection: "okta-calendar",
						status: "active",
						createdAt: T0,
						version: 3,
						...renewal(),
					});
					// The first authorization named a resource and the renewal names
					// none: a merge would have kept it.
					expect(grant).not.toHaveProperty("resource");
					expect(await openedCredentials("g-1", at(DAY + 3 * MIN))).toStrictEqual({
						state: "ok",
						value: credentials("2"),
					});
				});

				it("replaces the credentials as a whole: a renewal that brings no access token leaves none", async () => {
					await activated();
					await nameRenewalIntent();
					await renew({ credentials: { refreshToken: "rt-2" } });
					expect(await openedCredentials("g-1", at(DAY + 3 * MIN))).toStrictEqual({
						state: "ok",
						value: { refreshToken: "rt-2" },
					});
				});

				it("clears the ineligibility marker, and keeps when the grant was last used", async () => {
					const grant = await activated();
					await store.touch("g-1", at(3 * MIN));
					await store.replaceCredentials({
						grantId: "g-1",
						expectedVersion: grant.version,
						credentials: { refreshToken: "rt-starved" },
						ineligible: marker(),
						now: at(DAY - MIN),
					});

					await nameRenewalIntent();
					expect((await renew()).ok).toBe(true);
					const renewed = await store.find("g-1", at(DAY + 3 * MIN));
					expect(renewed).not.toHaveProperty("ineligible");
					expect(renewed).toHaveProperty("lastUsedAt", at(3 * MIN));
				});

				it("takes a grant that needs the user back to active, with credentials again", async () => {
					await needingUser();
					expect(await resident("g-1")).toBe(false);
					await nameRenewalIntent();
					expect((await renew()).ok).toBe(true);
					expect((await store.find("g-1", at(DAY + 3 * MIN)))?.status).toBe("active");
					expect(await resident("g-1")).toBe(true);
				});

				it("refuses an intent that lapsed while the code was being exchanged", async () => {
					await activated();
					await nameRenewalIntent();
					expect(await renew({ now: at(DAY + 10 * MIN) })).toEqual({ ok: false });
					expect(await openedCredentials("g-1", at(DAY + 11 * MIN))).toStrictEqual({
						state: "ok",
						value: credentials("1"),
					});
				});

				it("never resurrects a grant whose consented lifetime has ended, whichever state it was in", async () => {
					// "Unless pending" is not "if active": a grant that needs the user
					// has a consented lifetime too, and a reauthorization is how it
					// would come back.
					const grants = [await activated("g-active"), await needingUser("g-needs-user")];
					for (const grant of grants) {
						// Named a minute before the stored expiry, activated at it.
						await store.nameIntent({
							grantId: grant.id,
							intent: { handle: "h-late", expiresAt: at(30 * DAY + 9 * MIN) },
							now: at(30 * DAY - MIN),
						});
						expect(
							await store.activate({
								grantId: grant.id,
								intentHandle: "h-late",
								authorization: authorization({
									consent: { at: at(30 * DAY - MIN), sid: "sid-2", scopes: [...SCOPES] },
									authorizedAt: at(30 * DAY),
									expiresAt: at(60 * DAY),
								}),
								credentials: credentials("2"),
								now: at(30 * DAY),
							}),
							grant.status,
						).toEqual({ ok: false });
						expect(await store.find(grant.id, at(30 * DAY)), grant.status).toStrictEqual(grant);
						expect(await resident(grant.id), grant.status).toBe(grant.status === "active");
					}
				});

				it("never re-points a grant: a renewal for another upstream account, or under another identity, is refused (D4, D7)", async () => {
					// The connect callback checks the account before it gets here. This
					// is the same rule at the write, where D2 says rules are enforced:
					// one slip in that check would otherwise hand a grant ID, and the
					// client that holds it, to another upstream account.
					const grant = await activated();
					await nameRenewalIntent();
					const refused = [
						renewal({ upstream: { issuer: "https://dev-1.okta.test", subject: "00u-mallory" } }),
						renewal({ upstream: { issuer: "https://dev-2.okta.test", subject: "00u-alice" } }),
						renewal({ identityRevision: "identity-2" }),
					];
					for (const bad of refused) {
						expect(await renew({ authorization: bad })).toEqual({ ok: false });
						expect(await store.open("g-1", at(DAY + 2 * MIN))).toStrictEqual({
							grant,
							credentials: { state: "ok", value: credentials("1") },
						});
					}
					expect((await renew()).ok).toBe(true);
				});

				it("leaves an existing grant exactly as it was when it is refused for what it carries (D7)", async () => {
					// A credential written beside a `pending` grant is invisible through
					// the port; beside an active one it is the user's working refresh
					// token that a partial write would have replaced.
					const grant = await activated();
					await nameRenewalIntent();
					const now = at(DAY + 2 * MIN);
					const ahead = new Date(now.getTime() + 1);
					const consentAt = renewal().consent.at.getTime();
					const refused = [
						renewal({ expiresAt: now }),
						renewal({ expiresAt: new Date(consentAt + FEDERATION_GRANT_LIFETIME_CEILING_MS + 1) }),
						renewal({ authorizedAt: ahead }),
						// The consent of a renewal replaces the only evidence the
						// revocation backstop has (D13): it is bounded like the first one.
						renewal({ consent: { at: ahead, sid: "sid-2", scopes: ["openid", "offline_access"] } }),
						renewal({ expiresAt: INVALID }),
					];
					for (const bad of refused) {
						expect(await renew({ authorization: bad, now })).toEqual({ ok: false });
						expect(await store.open("g-1", now)).toStrictEqual({
							grant,
							credentials: { state: "ok", value: credentials("1") },
						});
						expect(await store.isCurrentIntent("g-1", "h-re", now)).toBe(true);
					}
					// And the refusals cost nothing: the same intent still renews.
					expect((await renew({ now })).ok).toBe(true);
				});
			});
		});

		describe("replaceCredentials", () => {
			it("replaces the credentials and bumps the version", async () => {
				const grant = await activated();
				const written = await store.replaceCredentials({
					grantId: "g-1",
					expectedVersion: grant.version,
					credentials: credentials("2"),
					ineligible: null,
					now: at(DAY),
				});
				expect(written).toStrictEqual({ ok: true, grant: { ...grant, version: 3 } });
				expect(await store.open("g-1", at(DAY))).toStrictEqual({
					grant: { ...grant, version: 3 },
					credentials: { state: "ok", value: credentials("2") },
				});
			});

			it("replaces as a whole: without an access token the record keeps the refresh token only", async () => {
				// How an ineligible access token is never written (D5). A merge
				// would leave the previous access token in the record.
				const grant = await activated();
				await store.replaceCredentials({
					grantId: "g-1",
					expectedVersion: grant.version,
					credentials: { refreshToken: "rt-2" },
					ineligible: marker(),
					now: at(DAY),
				});
				const opened = await store.open("g-1", at(DAY));
				expect(opened?.credentials).toStrictEqual({ state: "ok", value: { refreshToken: "rt-2" } });
			});

			it("sets the marker and clears it, in the same write as the credentials", async () => {
				const grant = await activated();
				const starved = await store.replaceCredentials({
					grantId: "g-1",
					expectedVersion: grant.version,
					credentials: { refreshToken: "rt-2" },
					ineligible: marker(),
					now: at(DAY),
				});
				if (!starved.ok) throw new Error("the first refresh was refused");
				expect(starved.grant).toHaveProperty("ineligible", marker());
				expect(await store.find("g-1", at(DAY))).toHaveProperty("ineligible", marker());

				const fed = await store.replaceCredentials({
					grantId: "g-1",
					expectedVersion: grant.version + 1,
					credentials: credentials("3"),
					ineligible: null,
					now: at(DAY + MIN),
				});
				if (!fed.ok) throw new Error("the second refresh was refused");
				expect(fed.grant).not.toHaveProperty("ineligible");
				expect(await store.find("g-1", at(DAY + MIN))).not.toHaveProperty("ineligible");
			});

			it("fails on a version that is not the stored one, and changes nothing", async () => {
				const grant = await activated();
				for (const stale of [grant.version - 1, grant.version + 1]) {
					expect(
						await store.replaceCredentials({
							grantId: "g-1",
							expectedVersion: stale,
							credentials: credentials("2"),
							ineligible: marker(),
							now: at(DAY),
						}),
					).toEqual({ ok: false });
				}
				expect(await store.open("g-1", at(DAY))).toStrictEqual({
					grant,
					credentials: { state: "ok", value: credentials("1") },
				});
			});

			it("fails for every grant that is not active, and writes no credential beside it", async () => {
				await store.createPending(pendingInput("g-pending"));
				const needsUser = await needingUser("g-needs-user");
				const revoked = await activated("g-revoked");
				await store.revoke("g-revoked", "client", at(DAY - MIN));

				for (const [grantId, expectedVersion] of [
					["g-pending", 1],
					["g-needs-user", needsUser.version],
					["g-revoked", revoked.version + 1],
					["g-unknown", 1],
				] as const) {
					expect(
						await store.replaceCredentials({
							grantId,
							expectedVersion,
							credentials: credentials("2"),
							ineligible: null,
							now: at(DAY),
						}),
						grantId,
					).toEqual({ ok: false });
					expect(await resident(grantId), grantId).toBe(false);
				}
			});

			it("refuses dates that are not dates, and changes nothing", async () => {
				const grant = await activated();
				const token = credentials("2").accessToken;
				if (token === undefined) throw new Error("fixture");
				const attempts = [
					{ credentials: { refreshToken: "rt-2", accessToken: { ...token, obtainedAt: INVALID } } },
					{ ineligible: { ...marker(), at: INVALID } },
				];
				for (const attempt of attempts) {
					expect(
						await store.replaceCredentials({
							grantId: "g-1",
							expectedVersion: grant.version,
							credentials: credentials("2"),
							ineligible: null,
							now: at(DAY),
							...attempt,
						}),
					).toEqual({ ok: false });
				}
				expect(await store.open("g-1", at(DAY))).toStrictEqual({
					grant,
					credentials: { state: "ok", value: credentials("1") },
				});
			});
		});

		describe("requireReauthorization", () => {
			it("marks the grant, deletes its credentials, bumps the version, and keeps everything else", async () => {
				const grant = await activated();
				await store.touch("g-1", at(3 * MIN));
				const starved = await store.replaceCredentials({
					grantId: "g-1",
					expectedVersion: grant.version,
					credentials: { refreshToken: "rt-2" },
					ineligible: marker(),
					now: at(4 * MIN),
				});
				if (!starved.ok) throw new Error("fixture");

				const written = await store.requireReauthorization({
					grantId: "g-1",
					expectedVersion: starved.grant.version,
					now: at(DAY),
				});
				const expected = {
					...grant,
					status: "reauthorization_required",
					version: 4,
					lastUsedAt: at(3 * MIN),
					ineligible: marker(),
				};
				expect(written).toStrictEqual({ ok: true, grant: expected });
				expect(await store.open("g-1", at(DAY))).toStrictEqual({
					grant: expected,
					credentials: { state: "absent" },
				});
				expect(await store.inspect("g-1", at(DAY))).toStrictEqual({
					grant: expected,
					credentials: "absent",
				});
				expect(await resident("g-1")).toBe(false);
			});

			it("marks an expired grant too: the expiry is what is reported, and the mark is harmless", async () => {
				const grant = await activated();
				const written = await store.requireReauthorization({
					grantId: "g-1",
					expectedVersion: grant.version,
					now: at(30 * DAY),
				});
				expect(written.ok).toBe(true);
			});

			it("fails on a stale version, and for every grant that is not active, changing nothing", async () => {
				const grant = await activated();
				expect(
					await store.requireReauthorization({
						grantId: "g-1",
						expectedVersion: grant.version + 1,
						now: at(DAY),
					}),
				).toEqual({ ok: false });
				expect(await store.open("g-1", at(DAY))).toStrictEqual({
					grant,
					credentials: { state: "ok", value: credentials("1") },
				});

				await store.createPending(pendingInput("g-pending"));
				expect(
					await store.requireReauthorization({
						grantId: "g-pending",
						expectedVersion: 1,
						now: at(MIN),
					}),
				).toEqual({ ok: false });
				expect((await store.find("g-pending", at(MIN)))?.status).toBe("pending");

				// Already marked: a second upstream `invalid_grant` is not a second transition.
				const needsUser = await needingUser("g-needs-user");
				expect(
					await store.requireReauthorization({
						grantId: "g-needs-user",
						expectedVersion: needsUser.version,
						now: at(DAY),
					}),
				).toEqual({ ok: false });
				expect(await store.find("g-needs-user", at(DAY))).toStrictEqual(needsUser);

				await store.revoke("g-1", "client", at(DAY));
				expect(
					await store.requireReauthorization({
						grantId: "g-1",
						expectedVersion: grant.version + 1,
						now: at(DAY),
					}),
				).toEqual({ ok: false });
				expect((await store.find("g-1", at(DAY)))?.status).toBe("revoked");
				expect(
					await store.requireReauthorization({
						grantId: "g-unknown",
						expectedVersion: 1,
						now: at(DAY),
					}),
				).toEqual({ ok: false });
			});
		});

		describe("revoke", () => {
			it("ends an active grant: revocation recorded, credentials deleted, every other field kept", async () => {
				const grant = await activated();
				await store.touch("g-1", at(3 * MIN));
				const starved = await store.replaceCredentials({
					grantId: "g-1",
					expectedVersion: grant.version,
					credentials: { refreshToken: "rt-2" },
					ineligible: marker(),
					now: at(4 * MIN),
				});
				if (!starved.ok) throw new Error("fixture");

				const expected = {
					...starved.grant,
					status: "revoked",
					version: 4,
					revocation: { by: "subject", at: at(DAY) },
				};
				expect(await store.revoke("g-1", "subject", at(DAY))).toStrictEqual({
					ok: true,
					grant: expected,
				});
				expect(await store.open("g-1", at(DAY))).toStrictEqual({
					grant: expected,
					credentials: { state: "absent" },
				});
				expect(await resident("g-1")).toBe(false);
			});

			it("ends a grant that needs the user", async () => {
				await needingUser();
				expect((await store.revoke("g-1", "operator", at(DAY))).ok).toBe(true);
				expect(await store.find("g-1", at(DAY))).toMatchObject({
					status: "revoked",
					revocation: { by: "operator", at: at(DAY) },
				});
			});

			it("ends a pending grant, which then outlives its intent: the client is told revoked, not not-found", async () => {
				await store.createPending(pendingInput());
				const expected = {
					id: "g-1",
					subject: "u-1",
					clientId: "agent",
					connection: "okta-calendar",
					status: "revoked",
					createdAt: T0,
					version: 2,
					revocation: { by: "client", at: at(MIN) },
				};
				expect(await store.revoke("g-1", "client", at(MIN))).toStrictEqual({
					ok: true,
					grant: expected,
				});
				expect(await store.find("g-1", at(2 * MIN))).toStrictEqual(expected);
				expect(await store.find("g-1", at(DAY))).toStrictEqual(expected);
			});

			it("ends a grant past its expiry: a client that revokes is told revoked, and not that it had expired anyway", async () => {
				await activated();
				expect(await resident("g-1")).toBe(true);
				expect((await store.revoke("g-1", "client", at(30 * DAY + MIN))).ok).toBe(true);
				// Nobody can be handed that credential any more, and it is deleted all
				// the same: what a revocation leaves at rest is not the clock's to decide.
				expect(await resident("g-1")).toBe(false);
				expect(await store.find("g-1", at(30 * DAY + MIN))).toMatchObject({
					status: "revoked",
					revocation: { by: "client", at: at(30 * DAY + MIN) },
				});
			});

			it("keeps the first revocation as recorded, and says a second one changed nothing", async () => {
				await activated();
				await store.revoke("g-1", "subject", at(DAY));
				expect(await store.revoke("g-1", "operator", at(2 * DAY))).toEqual({ ok: false });
				expect(await store.find("g-1", at(2 * DAY))).toMatchObject({
					version: 3,
					revocation: { by: "subject", at: at(DAY) },
				});
			});

			it("says an unknown grant changed nothing", async () => {
				expect(await store.revoke("g-unknown", "client", at(DAY))).toEqual({ ok: false });
				expect(await store.find("g-unknown", at(DAY))).toBeNull();
			});
		});

		describe("noteRefreshFailure (D5, D12)", () => {
			const failure = (over: Partial<FederationGrantRefreshFailureInput> = {}) => ({
				at: at(DAY),
				kind: "unavailable" as const,
				...over,
			});
			const ROW_MS = 300_000;
			const note = (
				expectedVersion: number,
				over: Partial<FederationGrantRefreshFailureInput> = {},
				now = at(DAY),
			) =>
				store.noteRefreshFailure({
					grantId: "g-1",
					expectedVersion,
					failure: failure(over),
					rowMs: ROW_MS,
					now,
				});

			it("stamps an active grant with the failure, counted from one, and bumps nothing", async () => {
				const grant = await activated();
				await store.touch("g-1", at(DAY - MIN));
				const written = await note(grant.version, { kind: "rate_limited", retryAfterSeconds: 17 });
				const expected = {
					...grant,
					lastUsedAt: at(DAY - MIN),
					refreshFailure: { at: at(DAY), kind: "rate_limited", count: 1, retryAfterSeconds: 17 },
				};
				expect(written).toStrictEqual({ ok: true, grant: expected });
				expect(await store.find("g-1", at(DAY))).toStrictEqual(expected);
				// The version, the credentials and the intent are not its to touch.
				expect(await store.open("g-1", at(DAY))).toMatchObject({
					grant: { version: grant.version },
					credentials: { state: "ok", value: credentials("1") },
				});
				expect(await store.isCurrentIntent("g-1", "h-g-1", at(DAY))).toBe(false);
			});

			describe("a stamp that says the user has to come back (D11, D12, #616)", () => {
				// The four codes an IdP answers a refresh with when it wants the user
				// and not a new token. Such a stamp is the grant's memory of that,
				// read as `reauthorization_required` until an activation clears it —
				// so no later failure may replace it: an outage or a rate limit
				// stamped over it would turn a grant that needs the user back into
				// one that is merely waiting.
				const INTERACTION = [
					"interaction_required",
					"login_required",
					"consent_required",
					"account_selection_required",
				] as const;
				const later = at(DAY + MIN);
				const incoming: Array<Partial<FederationGrantRefreshFailureInput>> = [
					{ kind: "unavailable" },
					{ kind: "rate_limited", retryAfterSeconds: 30 },
					{ kind: "rejected", upstreamCode: "invalid_client" },
					{ kind: "rejected", upstreamCode: "login_required" },
				];

				for (const code of INTERACTION) {
					it(`does not replace ${code} with another failure, later or not, and bumps nothing`, async () => {
						const grant = await activated();
						const marked = await note(grant.version, { kind: "rejected", upstreamCode: code });
						expect(marked).toMatchObject({
							ok: true,
							grant: { refreshFailure: { kind: "rejected", upstreamCode: code, count: 1 } },
						});
						for (const failure of incoming) {
							expect(await note(grant.version, { at: later, ...failure }, later)).toStrictEqual({
								ok: false,
							});
							expect(await note(grant.version, { at: at(DAY), ...failure }, later)).toStrictEqual({
								ok: false,
							});
						}
						const kept = await store.find("g-1", later);
						expect(kept?.refreshFailure).toStrictEqual({
							at: at(DAY),
							kind: "rejected",
							count: 1,
							upstreamCode: code,
						});
						expect(kept?.version).toBe(grant.version);
						expect(await store.open("g-1", later)).toMatchObject({
							credentials: { state: "ok", value: credentials("1") },
						});
					});
				}

				it("is a refusal and nothing else: a stamp of another kind carrying the same string is replaced like any", async () => {
					const grant = await activated();
					await note(grant.version, { kind: "unavailable", upstreamCode: "consent_required" });
					expect(
						await note(
							grant.version,
							{ at: later, kind: "rejected", upstreamCode: "invalid_client" },
							later,
						),
					).toMatchObject({
						ok: true,
						grant: { refreshFailure: { upstreamCode: "invalid_client" } },
					});
				});

				it("is cleared by what clears any stamp: a credential replacement, the destructive transition", async () => {
					const grant = await activated();
					await note(grant.version, { kind: "rejected", upstreamCode: "consent_required" });
					const replaced = await store.replaceCredentials({
						grantId: "g-1",
						expectedVersion: grant.version,
						credentials: credentials("2"),
						ineligible: null,
						now: later,
					});
					expect(replaced).toMatchObject({ ok: true });
					expect(await store.find("g-1", later)).not.toHaveProperty("refreshFailure");

					const again = await note(
						(await store.find("g-1", later))?.version ?? -1,
						{
							at: later,
							kind: "rejected",
							upstreamCode: "consent_required",
						},
						later,
					);
					expect(again).toMatchObject({ ok: true });
					const ended = await store.requireReauthorization({
						grantId: "g-1",
						expectedVersion: (await store.find("g-1", later))?.version ?? -1,
						now: at(DAY + 2 * MIN),
					});
					expect(ended).toMatchObject({ ok: true });
					expect(await store.find("g-1", at(DAY + 2 * MIN))).not.toHaveProperty("refreshFailure");
				});
			});

			it("counts consecutive failures, in the store: the caller never tells it the count", async () => {
				const grant = await activated();
				await note(grant.version);
				const second = await note(grant.version, { at: at(DAY + MIN) }, at(DAY + MIN));
				expect(second).toMatchObject({
					ok: true,
					grant: { refreshFailure: { at: at(DAY + MIN), kind: "unavailable", count: 2 } },
				});
				// A different kind counts on: what is counted is failures in a row.
				const third = await note(
					grant.version,
					{ at: at(DAY + 2 * MIN), kind: "rejected" },
					at(DAY + 2 * MIN),
				);
				expect(third).toMatchObject({
					ok: true,
					grant: { refreshFailure: { kind: "rejected", count: 3 } },
				});
				expect((await store.find("g-1", at(DAY + 2 * MIN)))?.refreshFailure).not.toHaveProperty(
					"retryAfterSeconds",
				);
			});

			it("starts a new row when the stamp it replaces is older than the row window: a failure a day later is the first of its row again", async () => {
				const grant = await activated();
				await note(grant.version);
				await note(grant.version, { at: at(DAY + MIN) }, at(DAY + MIN));
				expect((await store.find("g-1", at(DAY + MIN)))?.refreshFailure).toHaveProperty("count", 2);
				// Exactly the window later: still the row. One more: a new one.
				await note(grant.version, { at: at(DAY + MIN + ROW_MS) }, at(DAY + MIN + ROW_MS));
				expect((await store.find("g-1", at(2 * DAY)))?.refreshFailure).toHaveProperty("count", 3);
				await note(
					grant.version,
					{ at: at(DAY + MIN + 2 * ROW_MS + 1) },
					at(DAY + MIN + 2 * ROW_MS + 1),
				);
				expect((await store.find("g-1", at(2 * DAY)))?.refreshFailure).toHaveProperty("count", 1);
			});

			it("never moves back: a stamp dated before the one it would replace is refused, as a write that outlived its budget is", async () => {
				const grant = await activated();
				const newer = await note(grant.version, { kind: "rate_limited", retryAfterSeconds: 120 });
				expect(newer.ok).toBe(true);
				expect(await note(grant.version, { at: at(DAY - 1) }, at(DAY))).toEqual({ ok: false });
				expect((await store.find("g-1", at(DAY)))?.refreshFailure).toMatchObject({
					at: at(DAY),
					kind: "rate_limited",
					retryAfterSeconds: 120,
					count: 1,
				});
				// The same instant is not before: a second stamp at the same date counts on.
				expect(await note(grant.version)).toMatchObject({
					ok: true,
					grant: { refreshFailure: { count: 2 } },
				});
			});

			it("refuses everything a refresh's own write would refuse, and changes nothing then", async () => {
				const grant = await activated();
				const before = await store.find("g-1", at(DAY));
				// The version the caller read is not the record's: the failure was
				// of a refresh token the grant no longer has.
				expect(await note(grant.version + 1)).toEqual({ ok: false });
				// After the stored expiry.
				expect(await note(grant.version, {}, at(31 * DAY))).toEqual({ ok: false });
				// A date that is not one.
				expect(await note(grant.version, { at: INVALID })).toEqual({ ok: false });
				expect(await store.find("g-1", at(DAY))).toStrictEqual(before);

				await store.createPending(pendingInput("g-pending", "h-p"));
				await needingUser("g-needs-user");
				await activated("g-revoked");
				await store.revoke("g-revoked", "client", at(DAY));
				for (const id of ["g-pending", "g-needs-user", "g-revoked", "g-unknown"]) {
					// With the version the record has, so that it is the status that refuses.
					const version = (await store.find(id, at(5 * MIN)))?.version ?? 1;
					expect(
						await store.noteRefreshFailure({
							grantId: id,
							expectedVersion: version,
							failure: failure({ at: at(5 * MIN) }),
							rowMs: 300_000,
							now: at(5 * MIN),
						}),
						id,
					).toEqual({ ok: false });
				}
				expect(await store.find("g-pending", at(5 * MIN))).not.toHaveProperty("refreshFailure");
				expect(await store.find("g-needs-user", at(DAY))).not.toHaveProperty("refreshFailure");
				expect(await store.find("g-revoked", at(DAY))).not.toHaveProperty("refreshFailure");
			});

			it("is cleared by whatever replaces or ends the credentials: a refresh that wrote, a renewal, a mark, a revocation", async () => {
				const grant = await activated();
				await note(grant.version);
				const replaced = await store.replaceCredentials({
					grantId: "g-1",
					expectedVersion: grant.version,
					credentials: { refreshToken: "rt-2" },
					ineligible: marker(),
					now: at(DAY + MIN),
				});
				expect(replaced.ok).toBe(true);
				expect(await store.find("g-1", at(DAY + MIN))).not.toHaveProperty("refreshFailure");

				// Stamped again, then renewed.
				await note(grant.version + 1, { at: at(DAY + 2 * MIN) }, at(DAY + 2 * MIN));
				await nameRenewalIntent();
				expect((await renew()).ok).toBe(true);
				expect(await store.find("g-1", at(DAY + 3 * MIN))).not.toHaveProperty("refreshFailure");

				// Stamped again, then marked.
				const renewed = await store.find("g-1", at(DAY + 3 * MIN));
				if (renewed === null) throw new Error("fixture: the grant is gone");
				await note(renewed.version, { at: at(DAY + 4 * MIN) }, at(DAY + 4 * MIN));
				const marked = await store.requireReauthorization({
					grantId: "g-1",
					expectedVersion: renewed.version,
					now: at(DAY + 4 * MIN),
				});
				expect(marked.ok).toBe(true);
				expect(await store.find("g-1", at(DAY + 4 * MIN))).not.toHaveProperty("refreshFailure");

				await activated("g-2");
				const other = await store.find("g-2", at(DAY));
				if (other === null || other.status !== "active") throw new Error("fixture");
				await store.noteRefreshFailure({
					grantId: "g-2",
					expectedVersion: other.version,
					failure: failure(),
					rowMs: 300_000,
					now: at(DAY),
				});
				await store.revoke("g-2", "client", at(DAY + MIN));
				expect(await store.find("g-2", at(DAY + MIN))).not.toHaveProperty("refreshFailure");
			});

			it("copies what it is given and what it returns: neither the caller's date nor the returned record reaches the store", async () => {
				const grant = await activated();
				const at1 = at(DAY);
				const written = await store.noteRefreshFailure({
					grantId: "g-1",
					expectedVersion: grant.version,
					failure: { at: at1, kind: "unavailable" },
					rowMs: 300_000,
					now: at(DAY),
				});
				at1.setTime(0);
				if (!written.ok || !hasFederationGrantAuthorization(written.grant))
					throw new Error("fixture");
				written.grant.refreshFailure?.at.setTime(1);
				expect((await store.find("g-1", at(DAY)))?.refreshFailure).toStrictEqual({
					at: at(DAY),
					kind: "unavailable",
					count: 1,
				});
			});

			it("is on what listBySubject, inspect and open return", async () => {
				const grant = await activated();
				await note(grant.version);
				const stamp = { at: at(DAY), kind: "unavailable", count: 1 };
				expect((await store.listBySubject("u-1", at(DAY)))[0]).toHaveProperty(
					"refreshFailure",
					stamp,
				);
				expect((await store.inspect("g-1", at(DAY)))?.grant).toHaveProperty(
					"refreshFailure",
					stamp,
				);
				expect((await store.open("g-1", at(DAY)))?.grant).toHaveProperty("refreshFailure", stamp);
			});
		});

		describe("touch", () => {
			it("sets lastUsedAt on an active grant, without bumping the version", async () => {
				const grant = await activated();
				await store.touch("g-1", at(DAY));
				expect(await store.find("g-1", at(DAY))).toStrictEqual({ ...grant, lastUsedAt: at(DAY) });
			});

			it("never moves it back: two retrievals may report out of order", async () => {
				await activated();
				await store.touch("g-1", at(2 * DAY));
				await store.touch("g-1", at(DAY));
				expect(await store.find("g-1", at(2 * DAY))).toHaveProperty("lastUsedAt", at(2 * DAY));
			});

			it("does nothing for any other grant, nor for a date that is not one", async () => {
				await store.createPending(pendingInput("g-pending"));
				await needingUser("g-needs-user");
				await activated("g-revoked");
				await store.revoke("g-revoked", "client", at(DAY));
				await activated("g-active");

				for (const id of ["g-pending", "g-needs-user", "g-revoked", "g-unknown"]) {
					await expect(store.touch(id, at(5 * MIN))).resolves.toBeUndefined();
				}
				await expect(store.touch("g-active", INVALID)).resolves.toBeUndefined();

				expect(await store.find("g-pending", at(5 * MIN))).not.toHaveProperty("lastUsedAt");
				expect(await store.find("g-needs-user", at(5 * MIN))).not.toHaveProperty("lastUsedAt");
				expect(await store.find("g-revoked", at(2 * DAY))).not.toHaveProperty("lastUsedAt");
				expect(await store.find("g-active", at(5 * MIN))).not.toHaveProperty("lastUsedAt");
				expect(await store.find("g-unknown", at(5 * MIN))).toBeNull();
			});
		});

		describe("reads", () => {
			it("lists a subject's records in every state, exactly as `find` returns them, and nobody else's", async () => {
				await store.createPending(pendingInput("g-pending"));
				await activated("g-active");
				await needingUser("g-needs-user");
				await activated("g-revoked");
				await store.revoke("g-revoked", "client", at(3 * MIN));
				await store.createPending(pendingInput("g-revoked-pending"));
				await store.revoke("g-revoked-pending", "subject", at(3 * MIN));
				await store.createPending({ ...pendingInput("g-theirs", "h-theirs"), subject: "u-2" });

				const ids = [
					"g-active",
					"g-needs-user",
					"g-pending",
					"g-revoked",
					"g-revoked-pending",
				] as const;
				const byId = <G extends { id: string }>(grants: readonly G[]): G[] =>
					[...grants].sort((a, b) => (a.id < b.id ? -1 : 1));

				const soon = at(4 * MIN);
				const found = await Promise.all(ids.map((id) => store.find(id, soon)));
				expect(found.map((grant) => grant?.status)).toEqual([
					"active",
					"reauthorization_required",
					"pending",
					"revoked",
					"revoked",
				]);
				expect(byId(await store.listBySubject("u-1", soon))).toStrictEqual(found);

				// At the expiry: the pending one has lapsed, the others are all still
				// answered for — by the listing as by `find`. (Not later than this: how
				// long a record revoked while pending is retained is the adapter's
				// configuration, thirty days by default, counted from minute three.)
				const later = at(30 * DAY);
				const still = (await Promise.all(ids.map((id) => store.find(id, later)))).filter(
					(grant) => grant !== null,
				);
				expect(still.map((grant) => grant.id)).toEqual([
					"g-active",
					"g-needs-user",
					"g-revoked",
					"g-revoked-pending",
				]);
				expect(byId(await store.listBySubject("u-1", later))).toStrictEqual(still);

				expect(await store.listBySubject("u-3", soon)).toEqual([]);
			});

			it("answers null for a grant it does not know", async () => {
				expect(await store.find("g-unknown", T0)).toBeNull();
				expect(await store.inspect("g-unknown", T0)).toBeNull();
				expect(await store.open("g-unknown", T0)).toBeNull();
			});

			it("reports a pending grant's credentials as absent", async () => {
				await store.createPending(pendingInput());
				expect((await store.inspect("g-1", T0))?.credentials).toBe("absent");
				expect((await store.open("g-1", T0))?.credentials).toEqual({ state: "absent" });
			});

			it("still returns an authorized grant past its expiry, and never its credentials", async () => {
				// The status route must answer `expired`, not `grant_not_found`. The
				// credential gets no such retention (D16) — judged on the caller's
				// clock, whatever TTL a key may still have.
				const grant = await activated();
				expect((await openedCredentials("g-1", at(30 * DAY - 1)))?.state).toBe("ok");
				for (const now of [at(30 * DAY), at(31 * DAY)]) {
					expect(await store.find("g-1", now)).toStrictEqual(grant);
					expect(await store.open("g-1", now)).toStrictEqual({
						grant,
						credentials: { state: "absent" },
					});
					expect(await store.inspect("g-1", now)).toStrictEqual({ grant, credentials: "absent" });
				}
			});

			it("judges, and does not destroy: a `now` that was wrong for one call costs nothing", async () => {
				// What a caller is told depends on its `now`. What the store reclaims
				// depends on the store's own clock, as a key TTL does. So a read far in
				// the future sees nothing, and takes nothing with it.
				const grant = await activated();
				await store.createPending(pendingInput("g-pending", "h-g-pending"));
				const farAhead = at(5_000 * DAY);

				expect(await store.find("g-1", farAhead)).toBeNull();
				expect(await store.open("g-1", farAhead)).toBeNull();
				expect(await store.inspect("g-pending", farAhead)).toBeNull();
				expect(await store.listBySubject("u-1", farAhead)).toEqual([]);
				expect(await store.isCurrentIntent("g-pending", "h-g-pending", farAhead)).toBe(false);
				expect(await store.open("g-1", at(30 * DAY))).toMatchObject({
					credentials: { state: "absent" },
				});

				expect(await store.open("g-1", at(3 * MIN))).toStrictEqual({
					grant,
					credentials: { state: "ok", value: credentials("1") },
				});
				expect(await store.isCurrentIntent("g-pending", "h-g-pending", at(3 * MIN))).toBe(true);
			});

			it("writes nothing under a `now` that is far ahead, and deletes nothing either: not the record, not its credential, not its intent", async () => {
				// "The key has lapsed, so delete it while we are here" is a natural
				// habit in a script, and it is what the two clocks forbid: a caller
				// whose clock is wrong must not cost everyone else the record.
				const grant = await activated();
				await nameRenewalIntent();
				await store.createPending(pendingInput("g-pending", "h-g-pending"));
				const farAhead = at(5_000 * DAY);

				expect(await store.revoke("g-1", "client", farAhead)).toEqual({ ok: false });
				expect(
					await store.replaceCredentials({
						grantId: "g-1",
						expectedVersion: grant.version,
						credentials: credentials("x"),
						ineligible: null,
						now: farAhead,
					}),
				).toEqual({ ok: false });
				expect(
					await store.requireReauthorization({
						grantId: "g-1",
						expectedVersion: grant.version,
						now: farAhead,
					}),
				).toEqual({ ok: false });
				expect(
					await store.nameIntent({
						grantId: "g-1",
						intent: { handle: "h-x", expiresAt: at(5_001 * DAY) },
						now: farAhead,
					}),
				).toEqual({ ok: false });
				expect(await store.retireIntent({ grantId: "g-1", now: farAhead })).toEqual({ ok: false });
				expect(
					await store.noteRefreshFailure({
						grantId: "g-1",
						expectedVersion: grant.version,
						failure: { at: farAhead, kind: "unavailable" },
						rowMs: 300_000,
						now: farAhead,
					}),
				).toEqual({ ok: false });
				await store.touch("g-1", farAhead);
				expect(await store.revoke("g-pending", "client", farAhead)).toEqual({ ok: false });
				// An ID is taken for as long as its record is there, and not only for
				// as long as this caller can see it.
				for (const id of ["g-1", "g-pending"]) {
					expect(
						await store.createPending({
							...pendingInput(id, "h-x"),
							subject: "u-2",
							intent: { handle: "h-x", expiresAt: at(5_001 * DAY) },
							now: farAhead,
						}),
						id,
					).toEqual({ ok: false });
				}

				expect(await store.open("g-1", at(DAY + MIN))).toStrictEqual({
					grant,
					credentials: { state: "ok", value: credentials("1") },
				});
				expect(await resident("g-1")).toBe(true);
				expect(await store.isCurrentIntent("g-1", "h-re", at(DAY + MIN))).toBe(true);
				expect(await store.find("g-pending", at(MIN))).toMatchObject({
					status: "pending",
					subject: "u-1",
				});
				expect(await store.isCurrentIntent("g-pending", "h-g-pending", at(MIN))).toBe(true);
			});

			it("hands out copies: changing what was read changes nothing stored", async () => {
				await activated();
				const first = await store.open("g-1", at(DAY));
				if (first === null || first.credentials.state !== "ok") throw new Error("fixture");
				(first.credentials.value as { refreshToken: string }).refreshToken = "rt-tampered";
				const token = first.credentials.value.accessToken;
				if (token === undefined) throw new Error("fixture");
				(token.scopes as string[]).push("files.readwrite");
				token.obtainedAt.setTime(0);

				// Every way a record leaves the store: the reads, and what a write returns.
				const named = await nameRenewalIntent();
				const handedOut = [
					first.grant,
					await store.find("g-1", at(DAY)),
					(await store.inspect("g-1", at(DAY)))?.grant,
					(await store.listBySubject("u-1", at(DAY)))[0],
					named.ok ? named.grant : undefined,
				];
				for (const grant of handedOut) {
					if (grant === undefined || grant === null || grant.status !== "active") {
						throw new Error("fixture");
					}
					(grant.scopes as string[]).push("files.readwrite");
					(grant.consent.scopes as string[]).push("files.readwrite");
					(grant.upstream as { subject: string }).subject = "00u-mallory";
					grant.consent.at.setTime(0);
					grant.expiresAt.setTime(at(300 * DAY).getTime());
					grant.createdAt.setTime(0);
					(grant as { version: number }).version = 99;
				}

				expect(await store.open("g-1", at(DAY))).toStrictEqual({
					grant: {
						id: "g-1",
						subject: "u-1",
						clientId: "agent",
						connection: "okta-calendar",
						status: "active",
						createdAt: T0,
						version: 2,
						...authorization(),
					},
					credentials: { state: "ok", value: credentials("1") },
				});
			});

			it("keeps its own copy of what it is handed: an activation, a refresh, and the intents", async () => {
				const firstIntent = { handle: "h-1", expiresAt: at(10 * MIN) };
				await store.createPending({ ...pendingInput(), intent: firstIntent });
				// A caller's Date must not be a way to extend an intent's life.
				firstIntent.expiresAt.setTime(at(300 * DAY).getTime());
				expect(await store.isCurrentIntent("g-1", "h-1", at(10 * MIN))).toBe(false);
				expect(await store.isCurrentIntent("g-1", "h-1", at(2 * MIN))).toBe(true);

				const mutableAuthorization = authorization();
				const mutableCredentials = credentials("1");
				await store.activate({
					grantId: "g-1",
					intentHandle: "h-1",
					authorization: mutableAuthorization,
					credentials: mutableCredentials,
					now: at(2 * MIN),
				});
				(mutableAuthorization.scopes as string[]).push("files.readwrite");
				(mutableAuthorization.consent.scopes as string[]).push("files.readwrite");
				(mutableAuthorization.upstream as { subject: string }).subject = "00u-mallory";
				mutableAuthorization.consent.at.setTime(0);
				mutableAuthorization.authorizedAt.setTime(0);
				mutableAuthorization.expiresAt.setTime(at(300 * DAY).getTime());
				(mutableCredentials as { refreshToken: string }).refreshToken = "rt-tampered";

				const grant = {
					id: "g-1",
					subject: "u-1",
					clientId: "agent",
					connection: "okta-calendar",
					status: "active",
					createdAt: T0,
					version: 2,
					...authorization(),
				};
				expect(await store.open("g-1", at(DAY))).toStrictEqual({
					grant,
					credentials: { state: "ok", value: credentials("1") },
				});

				const renewalIntent = { handle: "h-re", expiresAt: at(DAY + 10 * MIN) };
				await store.nameIntent({ grantId: "g-1", intent: renewalIntent, now: at(DAY) });
				renewalIntent.expiresAt.setTime(at(300 * DAY).getTime());
				expect(await store.isCurrentIntent("g-1", "h-re", at(DAY + 10 * MIN))).toBe(false);

				const refreshed = credentials("2");
				const mutableMarker = marker();
				await store.replaceCredentials({
					grantId: "g-1",
					expectedVersion: 2,
					credentials: refreshed,
					ineligible: mutableMarker,
					now: at(DAY),
				});
				(refreshed as { refreshToken: string }).refreshToken = "rt-tampered";
				const token = refreshed.accessToken;
				if (token === undefined) throw new Error("fixture");
				(token.scopes as string[]).push("files.readwrite");
				token.obtainedAt.setTime(0);
				mutableMarker.at.setTime(0);
				(mutableMarker as { judgedAgainst: number }).judgedAgainst = 1;

				expect(await store.open("g-1", at(DAY))).toStrictEqual({
					grant: { ...grant, version: 3, ineligible: marker() },
					credentials: { state: "ok", value: credentials("2") },
				});
			});
		});

		describe("a time that is not one", () => {
			it("is refused, and not compared: every comparison with NaN is false, and the record would read as lapsed", async () => {
				const grant = await activated();
				await store.createPending(pendingInput("g-pending", "h-g-pending"));
				await nameRenewalIntent();

				await expect(store.find("g-1", INVALID)).rejects.toThrow(RangeError);
				await expect(store.listBySubject("u-1", INVALID)).rejects.toThrow(RangeError);
				await expect(store.inspect("g-1", INVALID)).rejects.toThrow(RangeError);
				await expect(store.open("g-1", INVALID)).rejects.toThrow(RangeError);
				await expect(store.isCurrentIntent("g-pending", "h-g-pending", INVALID)).rejects.toThrow(
					RangeError,
				);
				await expect(
					store.createPending({ ...pendingInput("g-new"), now: INVALID }),
				).rejects.toThrow(RangeError);
				await expect(
					store.nameIntent({
						grantId: "g-1",
						intent: { handle: "h-other", expiresAt: at(2 * DAY) },
						now: INVALID,
					}),
				).rejects.toThrow(RangeError);
				await expect(store.retireIntent({ grantId: "g-1", now: INVALID })).rejects.toThrow(
					RangeError,
				);
				await expect(
					store.activate({
						grantId: "g-pending",
						intentHandle: "h-g-pending",
						authorization: authorization(),
						credentials: credentials("x"),
						now: INVALID,
					}),
				).rejects.toThrow(RangeError);
				await expect(
					store.replaceCredentials({
						grantId: "g-1",
						expectedVersion: grant.version,
						credentials: credentials("x"),
						ineligible: null,
						now: INVALID,
					}),
				).rejects.toThrow(RangeError);
				await expect(
					store.requireReauthorization({
						grantId: "g-1",
						expectedVersion: grant.version,
						now: INVALID,
					}),
				).rejects.toThrow(RangeError);
				await expect(store.revoke("g-1", "client", INVALID)).rejects.toThrow(RangeError);
				await expect(
					store.noteRefreshFailure({
						grantId: "g-1",
						expectedVersion: grant.version,
						failure: { at: at(DAY), kind: "unavailable" },
						rowMs: 300_000,
						now: INVALID,
					}),
				).rejects.toThrow(RangeError);

				// And nothing was changed, reclaimed or created on the way.
				expect(await store.open("g-1", at(DAY))).toStrictEqual({
					grant,
					credentials: { state: "ok", value: credentials("1") },
				});
				expect(await store.isCurrentIntent("g-1", "h-re", at(DAY))).toBe(true);
				expect((await store.find("g-pending", at(3 * MIN)))?.status).toBe("pending");
				expect(await store.find("g-new", at(3 * MIN))).toBeNull();
			});
		});

		describe("the races of D2, in the order they would happen", () => {
			it("a callback that passed its checks and activates after a revocation fails", async () => {
				await store.createPending(pendingInput());
				expect(await store.isCurrentIntent("g-1", "h-1", at(MIN))).toBe(true);
				await store.revoke("g-1", "subject", at(MIN));

				expect(
					await store.activate({
						grantId: "g-1",
						intentHandle: "h-1",
						authorization: authorization(),
						credentials: credentials("1"),
						now: at(2 * MIN),
					}),
				).toEqual({ ok: false });
				expect((await store.find("g-1", at(2 * MIN)))?.status).toBe("revoked");
				expect(await resident("g-1")).toBe(false);
			});

			it("a refresh in flight while the grant is revoked does not re-create the credential record", async () => {
				const grant = await activated();
				await store.revoke("g-1", "client", at(DAY));

				// With the version it read, and with the one the revocation left,
				// which a refresh that re-read the record would hold.
				for (const expectedVersion of [grant.version, grant.version + 1]) {
					expect(
						await store.replaceCredentials({
							grantId: "g-1",
							expectedVersion,
							credentials: credentials("2"),
							ineligible: null,
							now: at(DAY + 1),
						}),
					).toEqual({ ok: false });
					expect(await resident("g-1")).toBe(false);
				}
				expect(await openedCredentials("g-1", at(DAY + 1))).toEqual({ state: "absent" });
			});

			it("a refresh that starts before the expiry and finishes at it fails, and its token is not installed", async () => {
				const grant = await activated();
				expect(
					await store.replaceCredentials({
						grantId: "g-1",
						expectedVersion: grant.version,
						credentials: credentials("late"),
						ineligible: null,
						now: at(30 * DAY),
					}),
				).toEqual({ ok: false });

				// A refused write changes nothing, and reclaims nothing on the way:
				// what is reclaimed is the store's own clock's to decide, not this
				// caller's `now`.
				expect(await store.open("g-1", at(30 * DAY - 1))).toStrictEqual({
					grant,
					credentials: { state: "ok", value: credentials("1") },
				});
				expect(await resident("g-1")).toBe(true);
			});
		});

		describe("conflicting writes at once — a check and a write in two steps would show here", () => {
			// Started in both orders. Whichever is started first gets its check in
			// first, and the interleaving that matters — the write checks, the
			// revocation lands, the write applies — only exists when the write is.
			const orders = ["the revocation first", "the write first"] as const;

			const race = async (
				first: (typeof orders)[number],
				revoke: () => Promise<FederationGrantWrite>,
				write: () => Promise<unknown>,
			): Promise<FederationGrantWrite> => {
				let revoking: Promise<FederationGrantWrite>;
				let writing: Promise<unknown>;
				if (first === "the revocation first") {
					revoking = revoke();
					writing = write();
				} else {
					writing = write();
					revoking = revoke();
				}
				const [revoked] = await Promise.all([revoking, writing]);
				return revoked;
			};

			for (const first of orders) {
				describe(first, () => {
					it("against an activation: the grant ends revoked, with no credential left behind", async () => {
						await store.createPending(pendingInput());
						const revoked = await race(
							first,
							() => store.revoke("g-1", "subject", at(2 * MIN)),
							() =>
								store.activate({
									grantId: "g-1",
									intentHandle: "h-1",
									authorization: authorization(),
									credentials: credentials("1"),
									now: at(2 * MIN),
								}),
						);
						expect(revoked.ok).toBe(true);
						expect((await store.find("g-1", at(3 * MIN)))?.status).toBe("revoked");
						expect(await openedCredentials("g-1", at(3 * MIN))).toEqual({ state: "absent" });
						expect(await resident("g-1")).toBe(false);
					});

					it("against a renewal: the grant ends revoked, with no credential left behind", async () => {
						await activated();
						await nameRenewalIntent();
						const revoked = await race(
							first,
							() => store.revoke("g-1", "subject", at(DAY + 2 * MIN)),
							() => renew(),
						);
						expect(revoked.ok).toBe(true);
						expect((await store.find("g-1", at(DAY + 3 * MIN)))?.status).toBe("revoked");
						expect(await resident("g-1")).toBe(false);
					});

					it("against a refresh: the grant ends revoked, with no credential left behind", async () => {
						const grant = await activated();
						const revoked = await race(
							first,
							() => store.revoke("g-1", "client", at(DAY)),
							() =>
								store.replaceCredentials({
									grantId: "g-1",
									expectedVersion: grant.version,
									credentials: credentials("2"),
									ineligible: null,
									now: at(DAY),
								}),
						);
						expect(revoked.ok).toBe(true);
						expect((await store.find("g-1", at(DAY)))?.status).toBe("revoked");
						expect(await resident("g-1")).toBe(false);
					});

					it("against an upstream invalid_grant: the grant ends revoked, and not as one a reauthorization could bring back", async () => {
						const grant = await activated();
						const revoked = await race(
							first,
							() => store.revoke("g-1", "client", at(DAY)),
							() =>
								store.requireReauthorization({
									grantId: "g-1",
									expectedVersion: grant.version,
									now: at(DAY),
								}),
						);
						expect(revoked.ok).toBe(true);
						expect((await store.find("g-1", at(DAY)))?.status).toBe("revoked");
						expect(await resident("g-1")).toBe(false);
					});

					it("against the naming of an intent: the grant ends revoked, with no intent to activate", async () => {
						await activated();
						const revoked = await race(
							first,
							() => store.revoke("g-1", "client", at(DAY)),
							() => nameRenewalIntent(),
						);
						expect(revoked.ok).toBe(true);
						expect((await store.find("g-1", at(DAY)))?.status).toBe("revoked");
						expect(await store.isCurrentIntent("g-1", "h-re", at(DAY + MIN))).toBe(false);
						expect(await renew()).toEqual({ ok: false });
					});
				});
			}

			// The writes to the intent pointer do not bump `version`, on purpose. So
			// an activation that reads, checks the handle, and then writes behind a
			// compare-and-set on `version` passes every test above — and loses to
			// both of them.
			const inBothOrders = (
				title: string,
				run: (
					start: <A, B>(a: () => Promise<A>, b: () => Promise<B>) => Promise<[A, B]>,
				) => Promise<void>,
			): void => {
				for (const order of ["as named", "the other way round"] as const) {
					it(`${title} — started ${order}`, () =>
						run(async (a, b) => {
							if (order === "as named") {
								const first = a();
								const second = b();
								return Promise.all([first, second]);
							}
							const second = b();
							const first = a();
							return Promise.all([first, second]);
						}));
				}
			};

			// The stamp of a failed refresh does not bump `version` either, and it is
			// written on records that other writes replace or end at the same time.
			const stamp = (grant: AuthorizedFederationGrant, at1 = at(DAY)) =>
				store.noteRefreshFailure({
					grantId: "g-1",
					expectedVersion: grant.version,
					failure: { at: at1, kind: "unavailable" },
					rowMs: 300_000,
					now: at1,
				});

			inBothOrders("a stamp against a touch: both land", async (start) => {
				const grant = await activated();
				await start(
					() => stamp(grant),
					() => store.touch("g-1", at(DAY)),
				);
				expect(await store.find("g-1", at(DAY))).toMatchObject({
					lastUsedAt: at(DAY),
					refreshFailure: { count: 1 },
				});
			});

			inBothOrders(
				"two stamps: the one dated later is what stands, counted on when it came second and alone when it came first",
				async (start) => {
					const grant = await activated();
					const [earlier, later] = await start(
						() => stamp(grant),
						() => stamp(grant, at(DAY + 1)),
					);
					expect(later.ok).toBe(true);
					const stood = (await store.find("g-1", at(DAY + 1)))?.refreshFailure;
					expect(stood).toMatchObject({ at: at(DAY + 1), count: earlier.ok ? 2 : 1 });
				},
			);

			inBothOrders(
				"a stamp against a refresh that wrote: the record ends with the new credentials and no stamp",
				async (start) => {
					const grant = await activated();
					await start(
						() => stamp(grant),
						() =>
							store.replaceCredentials({
								grantId: "g-1",
								expectedVersion: grant.version,
								credentials: credentials("2"),
								ineligible: null,
								now: at(DAY),
							}),
					);
					expect(await store.find("g-1", at(DAY))).toMatchObject({ version: grant.version + 1 });
					expect(await store.find("g-1", at(DAY))).not.toHaveProperty("refreshFailure");
					expect(await store.open("g-1", at(DAY))).toMatchObject({
						credentials: { state: "ok", value: credentials("2") },
					});
				},
			);

			inBothOrders(
				"a stamp against a renewal: the record ends renewed, with no stamp",
				async (start) => {
					const grant = await activated();
					await nameRenewalIntent();
					await start(
						() => stamp(grant),
						() => renew(),
					);
					expect(await store.find("g-1", at(DAY + 2 * MIN))).toMatchObject({
						status: "active",
						version: grant.version + 1,
					});
					expect(await store.find("g-1", at(DAY + 2 * MIN))).not.toHaveProperty("refreshFailure");
				},
			);

			inBothOrders(
				"a stamp against a mark: the record ends needing the user, with no stamp",
				async (start) => {
					const grant = await activated();
					await start(
						() => stamp(grant),
						() =>
							store.requireReauthorization({
								grantId: "g-1",
								expectedVersion: grant.version,
								now: at(DAY),
							}),
					);
					expect(await store.find("g-1", at(DAY))).toMatchObject({
						status: "reauthorization_required",
					});
					expect(await store.find("g-1", at(DAY))).not.toHaveProperty("refreshFailure");
				},
			);

			inBothOrders(
				"a stamp against a revocation: the record ends revoked, with no stamp",
				async (start) => {
					const grant = await activated();
					await start(
						() => stamp(grant),
						() => store.revoke("g-1", "client", at(DAY)),
					);
					expect(await store.find("g-1", at(DAY))).toMatchObject({ status: "revoked" });
					expect(await store.find("g-1", at(DAY))).not.toHaveProperty("refreshFailure");
				},
			);

			inBothOrders(
				"the retiring of an intent against the renewal it would end: exactly one of them happens",
				async (start) => {
					const grant = await activated();
					await nameRenewalIntent();
					const [retired, renewed] = await start(
						() => store.retireIntent({ grantId: "g-1", now: at(DAY + 2 * MIN) }),
						() => renew(),
					);
					expect([retired.ok, renewed.ok].filter((ok) => ok)).toHaveLength(1);
					expect(await store.isCurrentIntent("g-1", "h-re", at(DAY + 3 * MIN))).toBe(false);
					// A "keep" that retired the renewal in flight left the established
					// grant exactly as it was (D13).
					expect(await store.open("g-1", at(DAY + 3 * MIN))).toStrictEqual(
						retired.ok
							? { grant, credentials: { state: "ok", value: credentials("1") } }
							: {
									grant: { ...grant, ...renewal(), version: grant.version + 1 },
									credentials: { state: "ok", value: credentials("2") },
								},
					);
				},
			);

			inBothOrders(
				"the naming of a newer intent against the activation of the older one: the newer one is current afterwards",
				async (start) => {
					await activated();
					await nameRenewalIntent("h-re");
					const [named, renewed] = await start(
						() => nameRenewalIntent("h-re-2", at(DAY + 2 * MIN)),
						() => renew(),
					);
					expect(named.ok).toBe(true);
					expect(await store.isCurrentIntent("g-1", "h-re-2", at(DAY + 3 * MIN))).toBe(true);
					expect(await store.isCurrentIntent("g-1", "h-re", at(DAY + 3 * MIN))).toBe(false);
					expect(await openedCredentials("g-1", at(DAY + 3 * MIN))).toStrictEqual({
						state: "ok",
						value: credentials(renewed.ok ? "2" : "1"),
					});
				},
			);

			inBothOrders(
				"the retiring of a superseded intent against the naming of the one that supersedes it: the newer one is current afterwards",
				async (start) => {
					await activated();
					await nameRenewalIntent("h-re-1");
					const [, named] = await start(
						() => store.retireIntent({ grantId: "g-1", handle: "h-re-1", now: at(DAY + 2 * MIN) }),
						() => nameRenewalIntent("h-re-2", at(DAY + 2 * MIN)),
					);
					expect(named.ok).toBe(true);
					expect(await store.isCurrentIntent("g-1", "h-re-2", at(DAY + 3 * MIN))).toBe(true);
				},
			);

			inBothOrders(
				"the retiring of an intent against a revocation: the grant ends revoked",
				async (start) => {
					await activated();
					await nameRenewalIntent();
					const [, revoked] = await start(
						() => store.retireIntent({ grantId: "g-1", now: at(DAY + 2 * MIN) }),
						() => store.revoke("g-1", "subject", at(DAY + 2 * MIN)),
					);
					expect(revoked.ok).toBe(true);
					expect(await store.find("g-1", at(DAY + 3 * MIN))).toMatchObject({
						status: "revoked",
						revocation: { by: "subject" },
					});
					expect(await resident("g-1")).toBe(false);
					expect(await renew({ now: at(DAY + 3 * MIN) })).toEqual({ ok: false });
				},
			);

			it("two revocations at once: exactly one changes anything, and the one recorded is that one", async () => {
				await activated();
				const by = ["client", "subject", "operator"] as const;
				const results = await Promise.all(by.map((who) => store.revoke("g-1", who, at(DAY))));
				const winners = by.filter((_, index) => results[index]?.ok === true);
				expect(winners).toHaveLength(1);
				expect(await store.find("g-1", at(DAY))).toMatchObject({
					status: "revoked",
					version: 3,
					revocation: { by: winners[0] },
				});
			});

			it("two refreshes on one version: exactly one wins, and the stored credential is the winner's", async () => {
				const grant = await activated();
				const tags = ["a", "b", "c", "d"];
				const results = await Promise.all(
					tags.map((tag) =>
						store.replaceCredentials({
							grantId: "g-1",
							expectedVersion: grant.version,
							credentials: credentials(tag),
							ineligible: null,
							now: at(DAY),
						}),
					),
				);
				const winners = tags.filter((_, index) => results[index]?.ok === true);
				expect(winners).toHaveLength(1);
				expect(await store.open("g-1", at(DAY))).toStrictEqual({
					grant: { ...grant, version: grant.version + 1 },
					credentials: { state: "ok", value: credentials(winners[0] as string) },
				});
			});

			it("two callbacks on one intent: exactly one activates, and its credential is the one stored", async () => {
				await store.createPending(pendingInput());
				const tags = ["a", "b"];
				const results = await Promise.all(
					tags.map((tag) =>
						store.activate({
							grantId: "g-1",
							intentHandle: "h-1",
							authorization: authorization(),
							credentials: credentials(tag),
							now: at(2 * MIN),
						}),
					),
				);
				const winners = tags.filter((_, index) => results[index]?.ok === true);
				expect(winners).toHaveLength(1);
				expect((await store.find("g-1", at(3 * MIN)))?.version).toBe(2);
				expect(await openedCredentials("g-1", at(3 * MIN))).toStrictEqual({
					state: "ok",
					value: credentials(winners[0] as string),
				});
			});

			it("two lodgings of one ID: exactly one creates, and the record is the winner's", async () => {
				const subjects = ["u-1", "u-2", "u-3"];
				const results = await Promise.all(
					subjects.map((subject) => store.createPending({ ...pendingInput(), subject })),
				);
				const winners = subjects.filter((_, index) => results[index]?.ok === true);
				expect(winners).toHaveLength(1);
				expect((await store.find("g-1", T0))?.subject).toBe(winners[0]);
			});
		});

		describe("acquireRefreshLock (D12)", () => {
			it("excludes a second holder of the same grant until the first releases", async () => {
				const first = await store.acquireRefreshLock("g-1", HELD);
				if (!first.acquired) throw new Error("fixture: the first acquire failed");
				expect(await store.acquireRefreshLock("g-1", HELD)).toEqual({
					acquired: false,
					reason: "timeout",
				});

				await first.release();
				const second = await store.acquireRefreshLock("g-1", HELD);
				expect(second.acquired).toBe(true);
				if (second.acquired) await second.release();
			});

			it("tells the holder how long it waited before it TOOK the lock: a duration, so that the holder can date the lease on its own clock", async () => {
				// The holder counts every deadline from when it asked plus this (D12).
				// Counting from the acknowledgement instead overstates what is left of
				// the TTL by however long the acknowledgement took, and a slow one
				// lets a second holder in while the first still refreshes.
				const lock = await store.acquireRefreshLock("g-1", HELD);
				if (!lock.acquired) throw new Error("fixture: the acquire failed");
				expect(lock.waitedMs).toBeGreaterThanOrEqual(0);
				expect(lock.waitedMs).toBeLessThan(50);
				await lock.release();
			});

			it("counts the wait for a lock that was held: not less than the time until it was released", async () => {
				const first = await store.acquireRefreshLock("g-1", HELD);
				if (!first.acquired) throw new Error("fixture: the first acquire failed");
				const asked = Date.now();
				const waiting = store.acquireRefreshLock("g-1", { ttlMs: 120_000, waitForMs: 15_000 });
				await sleep(150);
				const released = Date.now();
				await first.release();
				const second = await waiting;
				if (!second.acquired) throw new Error("fixture: the waiter did not get the lock");
				expect(second.waitedMs).toBeGreaterThanOrEqual(released - asked - 50);
				expect(second.waitedMs).toBeLessThanOrEqual(Date.now() - asked);
				await second.release();
			});

			it("keeps grants apart", async () => {
				const first = await store.acquireRefreshLock("g-1", HELD);
				const other = await store.acquireRefreshLock("g-2", HELD);
				expect(first.acquired && other.acquired).toBe(true);
				if (first.acquired) await first.release();
				if (other.acquired) await other.release();
			});

			it("needs no grant record: the lock is keyed by ID alone", async () => {
				expect(await store.find("g-none", T0)).toBeNull();
				const lock = await store.acquireRefreshLock("g-none", HELD);
				expect(lock.acquired).toBe(true);
				if (lock.acquired) await lock.release();
			});

			it("waits for a holder to release, up to waitForMs", async () => {
				const first = await store.acquireRefreshLock("g-1", HELD);
				if (!first.acquired) throw new Error("fixture: the first acquire failed");
				const waiting = store.acquireRefreshLock("g-1", { ttlMs: 120_000, waitForMs: 15_000 });
				await sleep(100);
				await first.release();
				const second = await waiting;
				expect(second.acquired).toBe(true);
				if (second.acquired) await second.release();
			});

			it("gives up after waitForMs while the lock is held", async () => {
				const first = await store.acquireRefreshLock("g-1", HELD);
				if (!first.acquired) throw new Error("fixture: the first acquire failed");
				const started = Date.now();
				expect(await store.acquireRefreshLock("g-1", { ttlMs: 120_000, waitForMs: 150 })).toEqual({
					acquired: false,
					reason: "timeout",
				});
				expect(Date.now() - started).toBeGreaterThanOrEqual(140);
				await first.release();
			});

			it("never acquires after waitForMs, even when the holder releases just then", async () => {
				// A waiter that tries once more after every poll, and looks at its
				// deadline only after a failed try, takes a lock released between its
				// deadline and its next poll — and its caller starts a refresh it had
				// already given up on.
				const first = await store.acquireRefreshLock("g-1", HELD);
				if (!first.acquired) throw new Error("fixture: the first acquire failed");
				const waiting = store.acquireRefreshLock("g-1", { ttlMs: 120_000, waitForMs: 5 });
				await sleep(15);
				await first.release();
				expect(await waiting).toEqual({ acquired: false, reason: "timeout" });

				const next = await store.acquireRefreshLock("g-1", HELD);
				expect(next.acquired).toBe(true);
				if (next.acquired) await next.release();
			});

			it("has no renewal: past its TTL another caller gets in, and the first release leaves that lock alone", async () => {
				const first = await store.acquireRefreshLock("g-1", { ttlMs: 100, waitForMs: 0 });
				if (!first.acquired) throw new Error("fixture: the first acquire failed");
				await sleep(250);

				const second = await store.acquireRefreshLock("g-1", HELD);
				expect(second.acquired).toBe(true);

				await first.release();
				expect(await store.acquireRefreshLock("g-1", HELD)).toEqual({
					acquired: false,
					reason: "timeout",
				});
				if (second.acquired) await second.release();
			});

			it("releases idempotently", async () => {
				const first = await store.acquireRefreshLock("g-1", HELD);
				if (!first.acquired) throw new Error("fixture: the first acquire failed");
				await first.release();
				await expect(first.release()).resolves.toBeUndefined();

				// A second release must not free a lock taken since the first.
				const second = await store.acquireRefreshLock("g-1", HELD);
				await first.release();
				expect(await store.acquireRefreshLock("g-1", HELD)).toEqual({
					acquired: false,
					reason: "timeout",
				});
				if (second.acquired) await second.release();
			});

			it("refuses a TTL or a wait that is not a usable number: a TTL of NaN compares as expired, and exclusion would be silently off", async () => {
				for (const ttlMs of [Number.NaN, 0, -5, Number.POSITIVE_INFINITY]) {
					await expect(store.acquireRefreshLock("g-1", { ttlMs, waitForMs: 0 })).rejects.toThrow(
						RangeError,
					);
				}
				for (const waitForMs of [Number.NaN, -1, Number.POSITIVE_INFINITY]) {
					await expect(
						store.acquireRefreshLock("g-1", { ttlMs: 120_000, waitForMs }),
					).rejects.toThrow(RangeError);
				}
				// None of the refusals took the lock.
				const lock = await store.acquireRefreshLock("g-1", HELD);
				expect(lock.acquired).toBe(true);
				if (lock.acquired) await lock.release();
			});
		});
	});
}
