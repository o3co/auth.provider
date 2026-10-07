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
 * `subjectRevocationServiceModule`: the wiring, and what it refuses to wire.
 * The service itself is core's and is tested there. Here is what only this
 * module can get wrong: each session closed through `SessionLifecycle.close`
 * for `subject_revocation`, the horizon
 * and the allowance read off the `oauthTokenSettings`, `sessionCookiePolicy`
 * and `federationGrantPolicy` slots, and the compositions that would let a
 * subject-wide revocation report success over grants it could not reach.
 */

import {
	type AuditEvent,
	BootError,
	createApp,
	createInMemorySessionLifecycleStore,
	createInMemorySubjectRevocation,
	createInMemorySubjectSessionIndex,
	createInMemoryUserSessionStore,
	createMemoryFederationGrantStore,
	createSessionLifecycle,
	type FederationGrantStore,
	type FederationTokenStore,
	type RefreshTokenFamilyRevocation,
	resolveSubjectRevocationHorizonMs,
	type SessionCloseNotice,
	type SessionCloseOutcome,
	type SessionLifecycle,
	type SubjectRevocation,
	type SubjectRevocationService,
} from "@o3co/auth-provider-core";
import {
	CORE_RELOCATIONS,
	coreConfigForTests,
	createTestFederationGrantPolicy,
	createTestOAuthTokenSettings,
	createTestSessionCookiePolicy,
	makeValidCoreConfig,
	renamedVariableCaptures,
} from "@o3co/auth-provider-core/testing";
import { describe, expect, it, vi } from "vitest";
import { outsideAnswer } from "#/__tests__/_helpers/sessionLifecycle.mjs";
import { oauthTokenSettingsFrom } from "#/tokenSettings.mjs";
import { subjectRevocationServiceModule } from "../subjectRevocationService.mjs";

const HOUR = 3_600_000;

/** The oauth module's slot: access tokens live five minutes, refresh tokens a day. */
const oauthTokenSettings = createTestOAuthTokenSettings({
	accessTokenLifetime: { defaultExpiresIn: 300, maxExpiresIn: 300 },
	refreshTokenExpiresIn: 86_400,
});

/** The session store's slot: a session lives a day. */
const sessionCookiePolicy = createTestSessionCookiePolicy({ maxAgeMs: 24 * HOUR });

/** A session lifecycle whose every close answers `done`, for a test about something else. */
const closingStores = () => ({
	sessionLifecycle: {
		close: vi.fn(async () => ({ outcome: "done", rps: [], federations: [] }) as const),
	} as unknown as SessionLifecycle,
});

const build = (over: Record<string, unknown> = {}): SubjectRevocationService => {
	const provides = subjectRevocationServiceModule.provides as unknown as {
		subjectRevocationService: (deps: unknown) => SubjectRevocationService;
	};
	return provides.subjectRevocationService({
		oauthTokenSettings,
		sessionCookiePolicy,
		...closingStores(),
		subjectSessionIndex: createInMemorySubjectSessionIndex(),
		subjectRevocation: createInMemorySubjectRevocation(),
		...over,
	});
};

/** What core's boot needs of a composition, beside the slots each test hands. */
const bootConfig = () => ({
	config: {
		...makeValidCoreConfig(),
		...coreConfigForTests({ declaredAbsent: ["auditSink"] }),
		"renamed-variables": renamedVariableCaptures({
			modules: [subjectRevocationServiceModule],
			core: CORE_RELOCATIONS,
			env: {},
		}),
	},
	pathResolver: (s: string) => s,
});

/** An adapter with only the single-boundary surface, which a grants deployment may not use. */
const olderAdapter = (): SubjectRevocation => ({
	kind: "redis",
	revokeBefore: async () => undefined,
	revokedBefore: async () => null,
});

/** The federation-grants module's slot, as it provides it while the feature is on. */
const grantsOn = (allowKeepOnSubjectRevocation = false) => ({
	federationGrantPolicy: createTestFederationGrantPolicy({
		enabled: true,
		allowKeepOnSubjectRevocation,
	}),
});

describe("subjectRevocationServiceModule", () => {
	it("requires the session lifecycle, which closes each session, and none of the per-session stores", () => {
		expect(subjectRevocationServiceModule.requires).toContain("sessionLifecycle");
		for (const slot of [
			"userSessionStore",
			"sessionRPRegistry",
			"sessionFamilyIndex",
			"sessionFederationIndex",
		]) {
			expect(subjectRevocationServiceModule.requires).not.toContain(slot);
			expect(subjectRevocationServiceModule.optional).not.toContain(slot);
		}
	});

	it("does not require subjectSessionIndex or subjectRevocation, the two slots a deployment may declare absent", () => {
		// A module that REQUIRED them could not be installed at all in a
		// deployment that declared the capability absent — a harder demand
		// than the operation it wraps, which reports the absence instead.
		expect(subjectRevocationServiceModule.optional).toEqual(
			expect.arrayContaining([
				"subjectSessionIndex",
				"subjectRevocation",
				// Nor the grant store: the feature may be off.
				"federationGrantStore",
			]),
		);
		expect(subjectRevocationServiceModule.requires).not.toContain("subjectRevocation");
		expect(subjectRevocationServiceModule.requires).not.toContain("subjectSessionIndex");
	});

	it("reports an absent boundary rather than refusing to be built", async () => {
		// The call answers, says what it could not do, and `complete` is false:
		// what a deployment that declared the capability absent lives with.
		const { subjectRevocation: _absent, ...withoutBoundary } = {
			oauthTokenSettings,
			sessionCookiePolicy,
			...closingStores(),
			subjectSessionIndex: createInMemorySubjectSessionIndex(),
			subjectRevocation: createInMemorySubjectRevocation(),
		};
		const provides = subjectRevocationServiceModule.provides as unknown as {
			subjectRevocationService: (deps: unknown) => SubjectRevocationService;
		};
		const service = provides.subjectRevocationService(withoutBoundary);

		const result = await service.revokeAllForSubject({ subject: "u-1" });

		expect(result.unavailable).toEqual(["subjectRevocation"]);
		expect(result.complete).toBe(false);
		expect(result.tokensRevoked).toBe(false);
	});

	it("refuses a deployment with grants on and no boundary at all", () => {
		const { subjectRevocation: _absent, ...withoutBoundary } = {
			oauthTokenSettings,
			...grantsOn(),
			sessionCookiePolicy,
			...closingStores(),
			subjectSessionIndex: createInMemorySubjectSessionIndex(),
			subjectRevocation: createInMemorySubjectRevocation(),
			federationGrantStore: createMemoryFederationGrantStore(),
		};
		const provides = subjectRevocationServiceModule.provides as unknown as {
			subjectRevocationService: (deps: unknown) => SubjectRevocationService;
		};
		expect(() => provides.subjectRevocationService(withoutBoundary)).toThrow(
			/requires a subjectRevocation component/,
		);
	});

	it("is built even though nothing in the graph asks for it", () => {
		// The consumer is the Store, which reads it off `handle.components`
		// after `createApp` returns — and the boot planner builds a component
		// when a module needs it. Without `eager` the module would install,
		// refuse nothing, and provide a component nobody ever built.
		expect(
			(
				subjectRevocationServiceModule.lifecycle as
					| { subjectRevocationService?: { eager?: boolean } }
					| undefined
			)?.subjectRevocationService?.eager,
		).toBe(true);
	});

	describe("the close of each session", () => {
		/**
		 * A lifecycle whose close answers `outcome` — `outside`: an answer outside
		 * the outcomes the service acts on — recording each call and what it was
		 * called after.
		 */
		const lifecycleAnswering = (outcome: "done" | "pending" | "outside", order: string[] = []) => {
			const close = vi.fn(async (sid: string, cause: string): Promise<SessionCloseOutcome> => {
				order.push(`close:${sid}:${cause}`);
				return outcome === "outside"
					? outsideAnswer<SessionCloseOutcome>()
					: { outcome, rps: [], federations: [] };
			});
			return { close, lifecycle: { close } as unknown as SessionLifecycle };
		};

		it("closes each of the subject's sessions for subject_revocation", async () => {
			const index = createInMemorySubjectSessionIndex();
			await index.addSid("u-1", "sid-1", new Date(Date.now() + HOUR));
			await index.addSid("u-1", "sid-2", new Date(Date.now() + HOUR));
			const { close, lifecycle } = lifecycleAnswering("done");
			const service = build({ subjectSessionIndex: index, sessionLifecycle: lifecycle });

			const result = await service.revokeAllForSubject({ subject: "u-1" });

			expect(close.mock.calls.map(([sid, cause]) => `${sid}:${cause}`).sort()).toEqual([
				"sid-1:subject_revocation",
				"sid-2:subject_revocation",
			]);
			expect([...result.sessionsRevoked].sort()).toEqual(["sid-1", "sid-2"]);
			expect(result.complete).toBe(true);
			expect(await index.listSids("u-1")).toEqual([]);
		});

		it("stamps the subject's boundary before it closes a session", async () => {
			const order: string[] = [];
			const index = createInMemorySubjectSessionIndex();
			await index.addSid("u-1", "sid-1", new Date(Date.now() + HOUR));
			const boundary = createInMemorySubjectRevocation();
			const subjectRevocation: SubjectRevocation = {
				...boundary,
				revokeBefore: async (...args) => {
					order.push("stamp");
					return boundary.revokeBefore(...args);
				},
			};
			const { lifecycle } = lifecycleAnswering("done", order);
			const service = build({
				subjectSessionIndex: index,
				subjectRevocation,
				sessionLifecycle: lifecycle,
			});

			await service.revokeAllForSubject({ subject: "u-1" });

			// Both of the boundary's stamps (`stampSubjectBoundary`), then the close.
			expect(order).toEqual(["stamp", "stamp", "close:sid-1:subject_revocation"]);
		});

		it.each(["pending", "outside"] as const)(
			"reads a close answering %s as a session not revoked: the report is not complete, and the sid stays for a retry",
			async (outcome) => {
				const index = createInMemorySubjectSessionIndex();
				await index.addSid("u-1", "sid-1", new Date(Date.now() + HOUR));
				const { lifecycle } = lifecycleAnswering(outcome);
				const service = build({ subjectSessionIndex: index, sessionLifecycle: lifecycle });

				const result = await service.revokeAllForSubject({ subject: "u-1" });

				expect(result.sessionsFailed).toEqual(["sid-1"]);
				expect(result.complete).toBe(false);
				expect(await index.listSids("u-1")).toEqual(["sid-1"]);
			},
		);

		/**
		 * Core's session lifecycle over in-memory stores, holding one session of
		 * `u-1` that relying party `rp-1` and family `fam-1` joined. Its notifier
		 * fails the first `failingNotices` notices.
		 */
		const lifecycleOverMemory = async (failingNotices = 0) => {
			const expiresAt = new Date(Date.now() + HOUR);
			const userSessionStore = createInMemoryUserSessionStore();
			await userSessionStore.create({
				sid: "sid-1",
				sub: "u-1",
				authTime: new Date(),
				expiresAt,
				claims: {},
				amr: ["pwd"],
				authentication: undefined,
			});
			const index = createInMemorySubjectSessionIndex();
			await index.addSid("u-1", "sid-1", expiresAt);
			const revoked: string[] = [];
			const refreshTokenFamilyRevocation: RefreshTokenFamilyRevocation = {
				revokeFamily: async (familyId) => {
					revoked.push(familyId);
				},
				isFamilyRevoked: async (familyId) => revoked.includes(familyId),
			};
			const notices: SessionCloseNotice[] = [];
			let failing = failingNotices;
			const lifecycle = createSessionLifecycle({
				store: createInMemorySessionLifecycleStore(),
				userSessionStore,
				refreshTokenFamilyRevocation,
				federationTokenStore: {
					removeBySid: async () => undefined,
					delete: async () => undefined,
				} as unknown as FederationTokenStore,
				subjectSessionIndex: index,
				notifier: () => ({
					notify: async (notice) => {
						if (failing > 0) {
							failing -= 1;
							throw new Error("relying party unreachable");
						}
						notices.push(notice);
					},
				}),
				retainMs: HOUR,
				logger: { warn: () => undefined, error: () => undefined },
			});
			expect(await lifecycle.open("sid-1", { sub: "u-1", expiresAt })).toEqual({
				outcome: "opened",
			});
			expect(
				await lifecycle.join("sid-1", {
					rp: {
						clientId: "rp-1",
						backchannelLogoutUri: "https://rp-1.example/logout",
						backchannelLogoutSessionRequired: true,
						frontchannelLogoutUri: undefined,
						frontchannelLogoutSessionRequired: undefined,
						registeredAt: new Date(),
					},
					familyId: "fam-1",
				}),
			).toEqual({ outcome: "joined" });
			return { lifecycle, index, userSessionStore, revoked, notices };
		};

		it("keeps a session whose close is pending listed, and a retry resumes the close and reports complete", async () => {
			const { lifecycle, index, userSessionStore, notices } = await lifecycleOverMemory(1);
			const service = build({ subjectSessionIndex: index, sessionLifecycle: lifecycle });

			const first = await service.revokeAllForSubject({ subject: "u-1" });

			expect(first.sessionsFailed).toEqual(["sid-1"]);
			expect(first.complete).toBe(false);
			expect(await index.listSids("u-1")).toEqual(["sid-1"]);
			expect(await lifecycle.liveness("sid-1")).toEqual({ outcome: "not_live" });

			const retry = await service.revokeAllForSubject({ subject: "u-1" });

			expect(retry.sessionsRevoked).toEqual(["sid-1"]);
			expect(retry.complete).toBe(true);
			expect(await index.listSids("u-1")).toEqual([]);
			expect(notices.map((n) => n.clientId)).toEqual(["rp-1"]);
			expect(await userSessionStore.get("sid-1")).toBeNull();
		});

		it("counts a listed sid with neither a lifecycle record nor a user session revoked, running no work", async () => {
			const { lifecycle, index, userSessionStore, revoked } = await lifecycleOverMemory();
			await index.addSid("u-1", "sid-gone", new Date(Date.now() + HOUR));
			const service = build({ subjectSessionIndex: index, sessionLifecycle: lifecycle });
			await userSessionStore.delete("sid-1");
			await index.removeSid("u-1", "sid-1");

			const result = await service.revokeAllForSubject({ subject: "u-1" });

			expect(result.sessionsRevoked).toEqual(["sid-gone"]);
			expect(result.complete).toBe(true);
			expect(await index.listSids("u-1")).toEqual([]);
			expect(revoked).toEqual([]);
		});

		it("tells the session's relying parties and revokes its families through the close", async () => {
			const { lifecycle, index, userSessionStore, revoked, notices } = await lifecycleOverMemory();
			const service = build({ subjectSessionIndex: index, sessionLifecycle: lifecycle });

			const result = await service.revokeAllForSubject({ subject: "u-1" });

			expect(result.complete).toBe(true);
			expect(revoked).toEqual(["fam-1"]);
			expect(notices).toEqual([
				{ sid: "sid-1", sub: "u-1", clientId: "rp-1", cause: "subject_revocation" },
			]);
			expect(await userSessionStore.get("sid-1")).toBeNull();
			expect(await lifecycle.liveness("sid-1")).toEqual({ outcome: "not_live" });
		});
	});

	describe("what it refuses when grants are on", () => {
		it("refuses a deployment with nowhere to read the grants from", () => {
			expect(() => build(grantsOn())).toThrow(
				/federation-grants\.enabled = true requires a federationGrantStore/,
			);
			// The refusal states the rule it enforces, with no design label.
			expect(() => build(grantsOn())).not.toThrow(/\bD\d+\b/);
		});

		it("refuses an adapter that cannot carry the grants boundary", () => {
			expect(() =>
				build({
					...grantsOn(),
					federationGrantStore: createMemoryFederationGrantStore(),
					subjectRevocation: olderAdapter(),
				}),
			).toThrow(/grantsRevokedBefore/);
		});

		it("refuses durable grants beside a boundary that dies with the process", () => {
			const durable = {
				...createMemoryFederationGrantStore(),
				kind: "redis",
			} as FederationGrantStore;
			expect(() => build({ ...grantsOn(), federationGrantStore: durable })).toThrow(
				/outlive the process/,
			);
		});

		it("asks none of it of a deployment that left the feature off", () => {
			// The module a session deployment installs must keep working with
			// the adapter it already has.
			expect(() => build({ subjectRevocation: olderAdapter() })).not.toThrow();
		});

		it("decides by federationGrantPolicy.enabled: a grant store wired with the feature off is not read", () => {
			// Whether grants are on is the slot's to say; a store alone does not
			// turn the grants' checks on.
			expect(() =>
				build({
					federationGrantPolicy: createTestFederationGrantPolicy({ enabled: false }),
					federationGrantStore: createMemoryFederationGrantStore(),
					subjectRevocation: olderAdapter(),
				}),
			).not.toThrow();
		});
	});

	describe("the allowance", () => {
		it("lets a caller keep the grants when the operator turned it on", async () => {
			const revocation = createInMemorySubjectRevocation();
			const service = build({
				...grantsOn(true),
				federationGrantStore: createMemoryFederationGrantStore(),
				subjectRevocation: revocation,
			});

			const result = await service.revokeAllForSubject({
				subject: "u-1",
				federationGrants: "keep",
			});

			expect(result.federationGrants.applied).toBe("keep");
			expect(await revocation.grantsRevokedBefore("u-1")).toBeNull();
		});

		it("revokes when the operator did not", async () => {
			const service = build({
				...grantsOn(),
				federationGrantStore: createMemoryFederationGrantStore(),
			});

			const result = await service.revokeAllForSubject({
				subject: "u-1",
				federationGrants: "keep",
			});

			expect(result.federationGrants).toEqual({
				requested: "keep",
				applied: "revoke",
				reason: "keep_not_allowed",
			});
		});

		it("refuses a federationGrantPolicy its contract refuses, naming the member", () => {
			// An allowance beside a feature that is off is an allowance over
			// nothing, and a switch that is not a boolean is not read as off.
			expect(() =>
				build({
					federationGrantPolicy: { enabled: false, allowKeepOnSubjectRevocation: true },
					subjectRevocation: olderAdapter(),
				}),
			).toThrow(/federationGrantPolicy\.allowKeepOnSubjectRevocation must be false/);
			expect(() =>
				build({
					federationGrantPolicy: { enabled: "true", allowKeepOnSubjectRevocation: false },
					federationGrantStore: createMemoryFederationGrantStore(),
				}),
			).toThrow(/federationGrantPolicy\.enabled must be true or false/);
		});
	});

	describe("what it refuses when it cannot tell whether grants are on", () => {
		it("refuses a grant store wired with no federationGrantPolicy, naming both and the fix", () => {
			// Without the slot grants read as off, and a subject-wide revocation
			// would leave every grant in that store standing while reporting
			// itself complete. Failing closed is the only safe reading.
			const attempt = () => build({ federationGrantStore: createMemoryFederationGrantStore() });
			expect(attempt).toThrow(/federationGrantStore/);
			expect(attempt).toThrow(/no federationGrantPolicy/);
			expect(attempt).toThrow(/federationGrantsModule/);
			expect(attempt).toThrow(/federation-grants.enabled = true/);
			expect(attempt).toThrow(
				/federationGrantPolicy { enabled: false, allowKeepOnSubjectRevocation: false } in bootstrapComponents/,
			);
		});

		it("refuses it at boot, from createApp, naming the module", async () => {
			const err = await createApp({
				modules: [subjectRevocationServiceModule],
				bootstrapComponents: {
					...bootConfig(),
					...closingStores(),
					oauthTokenSettings,
					sessionCookiePolicy,
					subjectRevocation: createInMemorySubjectRevocation(),
					subjectSessionIndex: createInMemorySubjectSessionIndex(),
					federationGrantStore: createMemoryFederationGrantStore(),
				} as never,
			}).then(
				async (handle) => {
					await handle.dispose();
					return expect.fail("boot should have been refused");
				},
				(caught: unknown) => caught as BootError,
			);

			expect(err).toBeInstanceOf(BootError);
			expect(err.reason).toBe("provides-factory-failed");
			expect(err.message).toContain("subject-revocation-service");
			expect(err.message).toContain("no federationGrantPolicy");
		});

		it("treats no grant store and no federationGrantPolicy as grants off", () => {
			expect(() => build({ subjectRevocation: olderAdapter() })).not.toThrow();
		});
	});

	describe("the horizon: what the boundary must outlive", () => {
		/** A boundary that records how long each stamp is kept, in milliseconds. */
		const recording = () => {
			const kept: number[] = [];
			const revocation: SubjectRevocation = {
				kind: "memory",
				// Each distinct lifetime once: a revocation stamps the boundary
				// twice, and both stamps must last the same horizon.
				revokeBefore: async (_subject, before, expiresAt) => {
					const ttl = expiresAt.getTime() - before.getTime();
					if (!kept.includes(ttl)) kept.push(ttl);
				},
				revokedBefore: async () => null,
			};
			return { kept, revocation };
		};

		it("sizes it from what the configuration said before, for every configuration: the oauth module's slot carries the same lifetimes", async () => {
			// Before, a composition without the slot sized the boundary from the
			// configuration. The oauth module fills the slot from that same
			// section with the same resolvers, so the boundary must last exactly
			// as long as it did.
			const issuer = { jwt: { issuer: "https://issuer.example" } };
			const sections = [
				{ accessToken: { defaultExpiresIn: 300 }, refreshToken: { expiresIn: 86_400 } },
				{
					accessToken: { defaultExpiresIn: 60, maxExpiresIn: 30 * 86_400 },
					refreshToken: { expiresIn: 86_400 },
				},
				{
					accessToken: { defaultExpiresIn: 600, maxExpiresIn: 7_200 },
					refreshToken: { expiresIn: 40 * 86_400 },
				},
				{ accessToken: { defaultExpiresIn: 900 }, refreshToken: { expiresIn: 3_600 } },
				{ accessToken: { defaultExpiresIn: 1, maxExpiresIn: 1 }, refreshToken: { expiresIn: 1 } },
			];
			const sessions = [
				sessionCookiePolicy,
				createTestSessionCookiePolicy({ maxAgeMs: 1 }),
				createTestSessionCookiePolicy({ maxAgeMs: 90 * 24 * HOUR }),
			];
			for (const section of sections) {
				for (const sessionCookie of sessions) {
					const oauth = { ...issuer, ...section };
					const { kept, revocation } = recording();
					await build({
						subjectRevocation: revocation,
						sessionCookiePolicy: sessionCookie,
						oauthTokenSettings: oauthTokenSettingsFrom(oauth),
					}).revokeAllForSubject({ subject: "u-1" });
					expect(kept, JSON.stringify({ section, maxAgeMs: sessionCookie.maxAgeMs })).toEqual([
						resolveSubjectRevocationHorizonMs({ oauth }, { sessionCookie }),
					]);
				}
			}
		});

		it("never reads the configuration", async () => {
			const { kept, revocation } = recording();
			const untouchable = new Proxy(
				{},
				{
					get: () => {
						throw new Error("the configuration was read");
					},
				},
			);
			await build({ config: untouchable, subjectRevocation: revocation }).revokeAllForSubject({
				subject: "u-1",
			});
			expect(kept).toHaveLength(1);
		});

		it("refuses to be built when it is handed no oauthTokenSettings, naming the slot", () => {
			expect(() => build({ oauthTokenSettings: undefined })).toThrow(/oauthTokenSettings/);
		});

		it("refuses a composition that holds no oauthTokenSettings at planning, naming the module and the slot", async () => {
			const err = await createApp({
				modules: [subjectRevocationServiceModule],
				bootstrapComponents: {
					...bootConfig(),
					...closingStores(),
					sessionCookiePolicy,
				} as never,
			}).then(
				async (handle) => {
					await handle.dispose();
					return expect.fail("boot should have been refused");
				},
				(caught: unknown) => caught as BootError,
			);

			expect(err).toBeInstanceOf(BootError);
			expect(err.reason).toBe("missing-required-component");
			expect(err.message).toContain("oauthTokenSettings");
			expect(err.message).toContain("subject-revocation-service");
		});

		it("refuses to be built when it is handed no sessionCookiePolicy, naming the slot", () => {
			expect(() => build({ sessionCookiePolicy: undefined })).toThrow(
				"no sessionCookiePolicy was handed",
			);
		});

		it("refuses a composition that holds no sessionCookiePolicy at planning, naming the module and the slot", async () => {
			const err = await createApp({
				modules: [subjectRevocationServiceModule],
				bootstrapComponents: {
					...bootConfig(),
					...closingStores(),
					oauthTokenSettings,
				} as never,
			}).then(
				async (handle) => {
					await handle.dispose();
					return expect.fail("boot should have been refused");
				},
				(caught: unknown) => caught as BootError,
			);

			expect(err).toBeInstanceOf(BootError);
			expect(err.reason).toBe("missing-required-component");
			expect(err.message).toContain("sessionCookiePolicy");
			expect(err.message).toContain("subject-revocation-service");
		});

		it("sizes it from the session lifetime of the sessionCookiePolicy the composition holds", async () => {
			const { kept, revocation } = recording();
			const longer = createTestSessionCookiePolicy({ maxAgeMs: 10 * 24 * HOUR });
			await build({
				subjectRevocation: revocation,
				sessionCookiePolicy: longer,
			}).revokeAllForSubject({
				subject: "u-1",
			});
			expect(kept).toEqual([
				resolveSubjectRevocationHorizonMs(undefined, {
					tokenSettings: oauthTokenSettings,
					sessionCookie: longer,
				}),
			]);
			expect(kept[0]).toBeGreaterThan(10 * 24 * HOUR);
		});

		it("sizes it from the refresh-token lifetime of the oauthTokenSettings the composition holds", async () => {
			const { kept, revocation } = recording();
			await build({
				subjectRevocation: revocation,
				oauthTokenSettings: createTestOAuthTokenSettings({
					accessTokenLifetime: { defaultExpiresIn: 300, maxExpiresIn: 300 },
					refreshTokenExpiresIn: 20 * 86_400,
				}),
			}).revokeAllForSubject({ subject: "u-1" });
			expect(kept[0]).toBeGreaterThan(20 * 86_400_000);
			expect(kept[0]).toBeLessThan(21 * 86_400_000);
		});

		it("sizes it from the access-token maximum of the oauthTokenSettings the composition holds, not its default", async () => {
			// The access maximum (30 days) outlives the refresh token (a day) and
			// the session (a day), and differs from the default (a minute).
			const { kept, revocation } = recording();
			await build({
				subjectRevocation: revocation,
				oauthTokenSettings: createTestOAuthTokenSettings({
					accessTokenLifetime: { defaultExpiresIn: 60, maxExpiresIn: 30 * 86_400 },
					refreshTokenExpiresIn: 86_400,
				}),
			}).revokeAllForSubject({ subject: "u-1" });
			expect(kept[0]).toBeGreaterThan(30 * 86_400_000);
			expect(kept[0]).toBeLessThan(31 * 86_400_000);
		});

		it("requires the session store's slot and the oauth module's, and not the configuration", () => {
			expect(subjectRevocationServiceModule.requires).toContain("sessionCookiePolicy");
			expect(subjectRevocationServiceModule.requires).toContain("oauthTokenSettings");
			expect(subjectRevocationServiceModule.requires).not.toContain("config");
			expect(subjectRevocationServiceModule.optional).not.toContain("config");
			expect(subjectRevocationServiceModule.optional).toContain("federationGrantPolicy");
		});
	});

	it("finishes while a sink that never answers is still thinking", async () => {
		// The caller is a Store in the middle of a credential change it cannot
		// undo. A sink that hangs would hang that, having already revoked the
		// grants — so the event is dispatched and the revocation reports what
		// it did.
		const store = createMemoryFederationGrantStore();
		const now = new Date();
		await store.createPending({
			id: "g-1",
			subject: "u-1",
			clientId: "agent",
			connection: "okta-calendar",
			intent: { handle: "h", expiresAt: new Date(now.getTime() + HOUR) },
			now,
		});
		const service = build({
			...grantsOn(),
			federationGrantStore: store,
			auditSink: { record: () => new Promise<void>(() => undefined) },
		});

		const result = await service.revokeAllForSubject({ subject: "u-1" });

		expect(result.grantsRevoked).toEqual(["g-1"]);
		expect(result.complete).toBe(true);
	});

	it("logs a sink that refuses the event, and revokes anyway", async () => {
		const store = createMemoryFederationGrantStore();
		const now = new Date();
		await store.createPending({
			id: "g-1",
			subject: "u-1",
			clientId: "agent",
			connection: "okta-calendar",
			intent: { handle: "h", expiresAt: new Date(now.getTime() + HOUR) },
			now,
		});
		const logged: string[] = [];
		const service = build({
			...grantsOn(),
			federationGrantStore: store,
			auditSink: {
				record: () => {
					throw new Error("the sink is down");
				},
			},
			logger: { error: (_fields: unknown, message: string) => logged.push(message) },
		});

		const result = await service.revokeAllForSubject({ subject: "u-1" });
		await Promise.resolve();

		expect(result.grantsRevoked).toEqual(["g-1"]);
		expect(logged).toContain("federation_grant_audit_failed");
	});

	it("refuses a lifetime the slot's contract refuses when it is built — at boot, never on a revocation", () => {
		// The horizon is resolved once, in this eager provider, so a
		// hand-filled slot whose lifetimes are not lifetimes stops the
		// composition. Nothing on the revocation path reads a lifetime again, so
		// such a value can never surface as a 500 mid-revocation.
		for (const broken of [
			{ ...oauthTokenSettings, refreshTokenExpiresIn: 1.5 },
			{ ...oauthTokenSettings, refreshTokenExpiresIn: undefined },
			{ ...oauthTokenSettings, accessTokenLifetime: { defaultExpiresIn: 0, maxExpiresIn: 0 } },
		]) {
			expect(() => build({ oauthTokenSettings: broken }), JSON.stringify(broken)).toThrow(
				/oauthTokenSettings\./,
			);
		}
	});

	it("sizes the boundary from the lifetimes this deployment is configured with", async () => {
		// The service takes the number and cannot derive it: a boundary that
		// expires before the credentials it covers is not a backstop, and what
		// those credentials live for is in slots only a module is handed.
		const revocation = createInMemorySubjectRevocation();
		const stamp = vi.spyOn(revocation, "revokeBefore");
		const session = createTestSessionCookiePolicy({ maxAgeMs: 40 * 24 * HOUR });
		const service = build({
			sessionCookiePolicy: session,
			subjectRevocation: revocation,
		});

		await service.revokeAllForSubject({ subject: "u-1" });

		const [, before, expiresAt] = stamp.mock.calls[0] as [string, Date, Date];
		const ttl = expiresAt.getTime() - before.getTime();
		// Two assertions, because the first one alone compares the module with
		// the function it calls and would pass whatever that function said.
		// The second is the property itself: the boundary outlasts the
		// longest-lived thing this deployment is configured to accept.
		expect(ttl).toBe(
			resolveSubjectRevocationHorizonMs(undefined, {
				tokenSettings: oauthTokenSettings,
				sessionCookie: session,
			}),
		);
		expect(ttl).toBeGreaterThan(40 * 24 * HOUR);
	});

	it("tells the deployment's sink what a revocation ended", async () => {
		const store = createMemoryFederationGrantStore();
		const now = new Date();
		await store.createPending({
			id: "g-1",
			subject: "u-1",
			clientId: "agent",
			connection: "okta-calendar",
			intent: { handle: "h", expiresAt: new Date(now.getTime() + HOUR) },
			now,
		});
		const record = vi.fn(async () => undefined);
		const service = build({
			...grantsOn(),
			federationGrantStore: store,
			auditSink: { record },
		});

		await service.revokeAllForSubject({ subject: "u-1" });

		// The sink is told, and it was not waited for: a `record` that never
		// settles must not hang a credential change that has already happened.
		expect(record).toHaveBeenCalledWith(
			expect.objectContaining({
				type: "federation.grant.revoked",
				subject: "u-1",
				details: expect.objectContaining({
					grantId: "g-1",
					operation: "subject-revocation",
					connection: "okta-calendar",
				}),
			}),
		);
	});

	it("hands the sink a grant's subject and id sanitised and capped, as the federation-grants bridge does", async () => {
		// Both come from the deployment's Store, which took them from a
		// request once; the sink writes them onto a line, so they are bounded
		// the same way on every path that audits a grant.
		const hostile = `u-1\r\nFORGED ${"x".repeat(10_000)}`;
		const grantId = `g-1\nFORGED ${"y".repeat(10_000)}`;
		const store = createMemoryFederationGrantStore();
		const now = new Date();
		await store.createPending({
			id: grantId,
			subject: hostile,
			clientId: "agent",
			connection: "okta-calendar",
			intent: { handle: "h", expiresAt: new Date(now.getTime() + HOUR) },
			now,
		});
		const record = vi.fn(async () => undefined);
		const service = build({
			...grantsOn(),
			federationGrantStore: store,
			auditSink: { record },
		});

		await service.revokeAllForSubject({ subject: hostile });

		expect(record).toHaveBeenCalledTimes(1);
		const event = (record.mock.calls[0] as unknown as [AuditEvent])[0];
		expect(event.subject).toMatch(/^u-1\?\?FORGED x+\.\.\.$/);
		expect(event.subject?.length).toBeLessThanOrEqual(200);
		const recordedId = (event.details as { grantId: string }).grantId;
		expect(recordedId).toMatch(/^g-1\?FORGED y+\.\.\.$/);
		expect(recordedId.length).toBeLessThanOrEqual(200);
	});
});
