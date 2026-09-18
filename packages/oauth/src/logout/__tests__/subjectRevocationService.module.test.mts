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
				"subjectSessionIndex",
				"subjectRevocation",
			]),
		);
		// Not required: a deployment with the feature off has no grant store,
		// and this module is the one a session deployment installs.
		expect(subjectRevocationServiceModule.optional).toEqual(
			expect.arrayContaining(["federationGrantStore"]),
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
		expect(expiresAt.getTime() - before.getTime()).toBe(
			resolveSubjectRevocationHorizonMs(deployment),
		);
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

		expect(record).toHaveBeenCalledWith(
			expect.objectContaining({
				type: "federation.grant.revoked",
				subject: "u-1",
				details: expect.objectContaining({ grantId: "g-1", operation: "subject-revocation" }),
			}),
		);
	});
});
