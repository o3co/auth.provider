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
 * `subjectRevocationServiceModule` — the wiring, and what it refuses to wire
 * (#593, D13).
 *
 * The service itself is core's and is tested there. What is here is what only
 * this module can get wrong: the cascade closure over `cascadeLogout`, the
 * horizon read off configuration, the allowance read off configuration, and
 * the compositions that would let a subject-wide revocation report success
 * over grants it could not reach.
 */

import {
	type AuditEvent,
	createInMemorySubjectRevocation,
	createInMemorySubjectSessionIndex,
	createMemoryFederationGrantStore,
	type FederationGrantStore,
	resolveSubjectRevocationHorizonMs,
	type SubjectRevocation,
	type SubjectRevocationService,
} from "@o3co/auth-provider-core";
import { describe, expect, it, vi } from "vitest";
import { subjectRevocationServiceModule } from "../subjectRevocationService.mjs";

const HOUR = 3_600_000;

const config = (over: Record<string, unknown> = {}) => ({
	oauth: { accessToken: { expiresIn: 300 }, refreshToken: { expiresIn: 86_400 } },
	session: { maxAge: 24 * HOUR },
	...over,
});

/** Every store `cascadeLogout` fans out to, each one a spy that succeeds. */
const cascadeStores = () => ({
	userSessionStore: { delete: vi.fn(async () => undefined) },
	sessionRPRegistry: { removeBySid: vi.fn(async () => undefined) },
	sessionFamilyIndex: {
		listFamilyIds: vi.fn(async () => ["fam-1"]),
		removeBySid: vi.fn(async () => undefined),
	},
	sessionFederationIndex: { removeBySid: vi.fn(async () => undefined) },
	refreshTokenFamilyRevocation: { revokeFamily: vi.fn(async () => undefined) },
	federationTokenStore: { removeBySid: vi.fn(async () => undefined) },
});

const build = (over: Record<string, unknown> = {}): SubjectRevocationService => {
	const provides = subjectRevocationServiceModule.provides as unknown as {
		subjectRevocationService: (deps: unknown) => SubjectRevocationService;
	};
	return provides.subjectRevocationService({
		config: config(),
		...cascadeStores(),
		subjectSessionIndex: createInMemorySubjectSessionIndex(),
		subjectRevocation: createInMemorySubjectRevocation(),
		...over,
	});
};

/** The single-boundary surface #296 shipped, which a grants deployment may not use. */
const olderAdapter = (): SubjectRevocation => ({
	kind: "redis",
	revokeBefore: async () => undefined,
	revokedBefore: async () => null,
});

const enabled = (over: Record<string, unknown> = {}) =>
	config({ federationGrants: { enabled: true, ...over } });

describe("subjectRevocationServiceModule", () => {
	it("declares the whole cascade, because it cannot run without it", () => {
		expect(subjectRevocationServiceModule.requires).toEqual(
			expect.arrayContaining([
				"userSessionStore",
				"sessionRPRegistry",
				"sessionFamilyIndex",
				"sessionFederationIndex",
				"refreshTokenFamilyRevocation",
				"federationTokenStore",
			]),
		);
	});

	it("does not require the two slots #406 lets a deployment declare absent", () => {
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
		// #296's behaviour, unchanged: the call answers, says what it could not
		// do, and `complete` is false. A deployment that declared the
		// capability absent already lives with exactly this.
		const { subjectRevocation: _absent, ...withoutBoundary } = {
			config: config(),
			...cascadeStores(),
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
			config: enabled(),
			...cascadeStores(),
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

	describe("the cascade closure", () => {
		it("tears a session down through cascadeLogout and counts it revoked", async () => {
			const index = createInMemorySubjectSessionIndex();
			await index.addSid("u-1", "sid-1", new Date(Date.now() + HOUR));
			const stores = cascadeStores();
			const service = build({ ...stores, subjectSessionIndex: index });

			const result = await service.revokeAllForSubject({ subject: "u-1" });

			expect(stores.refreshTokenFamilyRevocation.revokeFamily).toHaveBeenCalledWith("fam-1");
			expect(stores.userSessionStore.delete).toHaveBeenCalledWith("sid-1");
			expect(result.sessionsRevoked).toEqual(["sid-1"]);
			expect(result.complete).toBe(true);
		});

		it("reads a cascade that did not finish as a session still live", async () => {
			// `cascadeLogout` answers with an outcome and a step, not with `ok`.
			// Anything that is not `done` left something behind, and the entry
			// stays in the index for the retry to find.
			const index = createInMemorySubjectSessionIndex();
			await index.addSid("u-1", "sid-1", new Date(Date.now() + HOUR));
			const stores = cascadeStores();
			stores.sessionFamilyIndex.listFamilyIds.mockRejectedValue(new Error("store is down"));
			const service = build({ ...stores, subjectSessionIndex: index });

			const result = await service.revokeAllForSubject({ subject: "u-1" });

			expect(result.sessionsFailed).toEqual(["sid-1"]);
			expect(result.complete).toBe(false);
			expect(await index.listSids("u-1")).toEqual(["sid-1"]);
		});
	});

	describe("what it refuses when grants are on", () => {
		it("refuses a deployment with nowhere to read the grants from", () => {
			expect(() => build({ config: enabled() })).toThrow(/requires a federationGrantStore/);
		});

		it("refuses an adapter that cannot carry the grants boundary", () => {
			expect(() =>
				build({
					config: enabled(),
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
			expect(() => build({ config: enabled(), federationGrantStore: durable })).toThrow(
				/outlive the process/,
			);
		});

		it("asks none of it of a deployment that left the feature off", () => {
			// The module a session deployment installs must keep working with
			// the adapter it already has.
			expect(() => build({ subjectRevocation: olderAdapter() })).not.toThrow();
		});
	});

	describe("the allowance", () => {
		it("lets a caller keep the grants when the operator turned it on", async () => {
			const revocation = createInMemorySubjectRevocation();
			const service = build({
				config: enabled({ allowKeepOnSubjectRevocation: true }),
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
				config: enabled(),
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

		it("ignores an allowance written for a feature that is off", () => {
			// Otherwise the service would refuse the adapter of a deployment
			// that has no grants to keep, over a flag about nothing.
			expect(() =>
				build({
					config: config({
						federationGrants: { enabled: false, allowKeepOnSubjectRevocation: true },
					}),
					subjectRevocation: olderAdapter(),
				}),
			).not.toThrow();
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
			config: enabled(),
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
			config: enabled(),
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

	it("refuses a lifetime the resolvers refuse when it is built — at boot, never on a revocation", () => {
		// The horizon is resolved once, in this eager provider, so a
		// hand-built configuration the lifetime resolvers refuse stops the
		// composition. Nothing on the revocation path reads a lifetime again, so
		// such a value can never surface as a 500 mid-revocation.
		for (const oauth of [
			{ accessToken: { expiresIn: 300 }, refreshToken: { expiresIn: 1.5 } },
			{ accessToken: { expiresIn: 300 }, refreshToken: {} },
			{ accessToken: { expiresIn: 0 }, refreshToken: { expiresIn: 86_400 } },
		]) {
			expect(() => build({ config: config({ oauth }) }), JSON.stringify(oauth)).toThrow(RangeError);
		}
	});

	it("sizes the boundary from the lifetimes this deployment is configured with", async () => {
		// The service takes the number and cannot derive it: a boundary that
		// expires before the credentials it covers is not a backstop, and what
		// those credentials live for is configuration only a module can read.
		const revocation = createInMemorySubjectRevocation();
		const stamp = vi.spyOn(revocation, "revokeBefore");
		const deployment = config({ session: { maxAge: 40 * 24 * HOUR } });
		const service = build({ config: deployment, subjectRevocation: revocation });

		await service.revokeAllForSubject({ subject: "u-1" });

		const [, before, expiresAt] = stamp.mock.calls[0] as [string, Date, Date];
		const ttl = expiresAt.getTime() - before.getTime();
		// Two assertions, because the first one alone compares the module with
		// the function it calls and would pass whatever that function said.
		// The second is the property itself: the boundary outlasts the
		// longest-lived thing this deployment is configured to accept.
		expect(ttl).toBe(resolveSubjectRevocationHorizonMs(deployment));
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
			config: enabled(),
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
			config: enabled(),
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
