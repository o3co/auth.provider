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
 * The subject revocation service (#593, D13).
 *
 * What it adds over the free function is the one thing a free function cannot
 * have: an operator's policy. `"keep"` — end the subject's sessions and tokens
 * but leave their federation grants standing — is a decision about residual
 * access, and a caller that could turn it on per call would be deciding it
 * instead of the operator. So the allowance is configuration, the request is a
 * question, and the answer is reported back: `requested`, `applied`, `reason`.
 *
 * `complete: true` means **the applied action** completed. A Store that asked
 * to keep, was refused, and got `complete: true` has had every grant revoked.
 */

import { describe, expect, it, vi } from "vitest";
import { harness, MIN, now } from "#/federation-grants/__tests__/retrieve.harness.mjs";
import { createInMemorySubjectRevocation } from "#/user-sessions/memory/subjectRevocation.mjs";
import { createInMemorySubjectSessionIndex } from "#/user-sessions/memory/subjectSessionIndex.mjs";
import { createSubjectRevocationService } from "#/user-sessions/subjectRevocationService.mjs";
import type { SubjectRevocation } from "#/user-sessions/types.mjs";

const HORIZON_MS = 400 * 24 * 3_600_000;

/** Everything the service needs, with nothing kept and no grants. */
const deps = (over: Record<string, unknown> = {}) => ({
	subjectSessionIndex: createInMemorySubjectSessionIndex(),
	subjectRevocation: createInMemorySubjectRevocation(),
	cascadeSession: async () => ({ ok: true }),
	watermarkTtlMs: HORIZON_MS,
	allowKeep: false,
	now: () => now().getTime(),
	...over,
});

/** A subject revocation with the older, single-boundary surface and nothing more. */
const sessionsOnlyUnaware = (): SubjectRevocation => {
	const inner = createInMemorySubjectRevocation();
	return {
		kind: "legacy",
		revokeBefore: (subject, before, expiresAt) => inner.revokeBefore(subject, before, expiresAt),
		revokedBefore: (subject) => inner.revokedBefore(subject),
	};
};

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

describe("createSubjectRevocationService", () => {
	describe("what it refuses to be built as", () => {
		it("refuses to allow keeping on an adapter that cannot stamp sessions alone", () => {
			// Not a request-time answer: an operator who turned the allowance on
			// and got a full revocation every time would read the result as the
			// policy working. The composition is wrong, and boot is where a
			// wrong composition belongs.
			expect(() =>
				createSubjectRevocationService(
					deps({ allowKeep: true, subjectRevocation: sessionsOnlyUnaware() }),
				),
			).toThrow(/revokeSessionsBefore|sessions-only/i);
		});

		it("accepts the same adapter when keeping is not allowed", () => {
			expect(() =>
				createSubjectRevocationService(deps({ subjectRevocation: sessionsOnlyUnaware() })),
			).not.toThrow();
		});

		it("is built for a deployment that declared the boundary absent, and reports it", () => {
			// #406 lets a deployment declare either subject-level capability
			// absent. Refusing to construct would be a harder demand than the
			// operation this wraps makes, and the answer is the one
			// `revokeAllForSubject` has always given: say what was not done.
			const { subjectRevocation: _absent, ...withoutBoundary } = deps();
			const service = createSubjectRevocationService(
				withoutBoundary as Parameters<typeof createSubjectRevocationService>[0],
			);
			return expect(service.revokeAllForSubject({ subject: "u-1" })).resolves.toMatchObject({
				unavailable: ["subjectRevocation"],
				tokensRevoked: false,
				complete: false,
			});
		});

		it("still refuses to allow keeping with no boundary at all", () => {
			const { subjectRevocation: _absent, ...withoutBoundary } = deps({ allowKeep: true });
			expect(() =>
				createSubjectRevocationService(
					withoutBoundary as Parameters<typeof createSubjectRevocationService>[0],
				),
			).toThrow(/revokeSessionsBefore|sessions-only/i);
		});

		it("refuses a watermark that would expire immediately", () => {
			expect(() => createSubjectRevocationService(deps({ watermarkTtlMs: 0 }))).toThrow(
				/ttl|retention/i,
			);
		});
	});

	describe("revoking, which is what it does unless told otherwise", () => {
		it("ends the grants and stamps both boundaries", async () => {
			const h = harness();
			await h.seed();
			const revocation = createInMemorySubjectRevocation();
			const service = createSubjectRevocationService(
				deps({ subjectRevocation: revocation, federationGrantStore: h.store }),
			);

			const result = await service.revokeAllForSubject({ subject: "u-1" });

			expect(result.complete).toBe(true);
			expect(result.federationGrants).toEqual({ requested: "revoke", applied: "revoke" });
			expect(result.grantsRevoked).toEqual(["g-1"]);
			expect(await revocation.revokedBefore("u-1")).not.toBeNull();
			expect(await revocation.grantsRevokedBefore("u-1")).not.toBeNull();
		});

		it("revokes anyway when keeping was asked for and policy forbids it", async () => {
			const h = harness();
			await h.seed();
			const revocation = createInMemorySubjectRevocation();
			const service = createSubjectRevocationService(
				deps({ subjectRevocation: revocation, federationGrantStore: h.store }),
			);

			const result = await service.revokeAllForSubject({
				subject: "u-1",
				federationGrants: "keep",
			});

			expect(result.federationGrants).toEqual({
				requested: "keep",
				applied: "revoke",
				reason: "keep_not_allowed",
			});
			// The applied action completed. It is not a report that the grants survived.
			expect(result.complete).toBe(true);
			expect(result.grantsRevoked).toEqual(["g-1"]);
			expect(await revocation.grantsRevokedBefore("u-1")).not.toBeNull();
		});

		it("cascades the subject's sessions", async () => {
			const index = createInMemorySubjectSessionIndex();
			await index.addSid("u-1", "sid-1", new Date(now().getTime() + 60 * MIN));
			const cascadeSession = vi.fn(async () => ({ ok: true }));
			const service = createSubjectRevocationService(
				deps({ subjectSessionIndex: index, cascadeSession }),
			);

			const result = await service.revokeAllForSubject({ subject: "u-1" });

			expect(cascadeSession).toHaveBeenCalledWith("sid-1");
			expect(result.sessionsRevoked).toEqual(["sid-1"]);
		});
	});

	describe("keeping, when the operator allows it", () => {
		const keeping = (over: Record<string, unknown> = {}) => deps({ allowKeep: true, ...over });

		it("stamps the sessions boundary and leaves the grants boundary alone", async () => {
			const revocation = createInMemorySubjectRevocation();
			const service = createSubjectRevocationService(keeping({ subjectRevocation: revocation }));

			const result = await service.revokeAllForSubject({
				subject: "u-1",
				federationGrants: "keep",
			});

			expect(result.federationGrants).toEqual({ requested: "keep", applied: "keep" });
			expect(result.tokensRevoked).toBe(true);
			expect(await revocation.revokedBefore("u-1")).not.toBeNull();
			expect(await revocation.grantsRevokedBefore("u-1")).toBeNull();
		});

		it("reports a stamp that failed by the name of the call that failed", async () => {
			// `revokeBefore` and `revokeSessionsBefore` fail for different
			// reasons and send an operator to different places: one is the
			// boundary every deployment writes, the other is the second
			// boundary only an adapter that supports keeping has.
			const h = harness();
			await h.seed();
			const revocation = createInMemorySubjectRevocation();
			vi.spyOn(revocation, "revokeSessionsBefore").mockRejectedValue(new Error("store is down"));
			const service = createSubjectRevocationService(
				keeping({ subjectRevocation: revocation, federationGrantStore: h.store }),
			);

			const result = await service.revokeAllForSubject({
				subject: "u-1",
				federationGrants: "keep",
			});

			expect(result.tokensRevoked).toBe(false);
			expect(result.complete).toBe(false);
			expect(result.failures).toContainEqual(
				expect.objectContaining({
					capability: "subjectRevocation",
					operation: "revokeSessionsBefore",
				}),
			);
			// And the grants were still dealt with: a boundary that could not be
			// written does not make the renewal in flight less worth ending.
			expect(result.grantsRequested).toBe(true);
		});

		it("reports a session index the deployment declared absent", async () => {
			// The keep path answers the same way the revoke path does: what it
			// could not do is named, and `complete` is false.
			const { subjectSessionIndex: _absent, ...withoutIndex } = keeping();
			const service = createSubjectRevocationService(
				withoutIndex as Parameters<typeof createSubjectRevocationService>[0],
			);

			const result = await service.revokeAllForSubject({
				subject: "u-1",
				federationGrants: "keep",
			});

			expect(result.unavailable).toEqual(["subjectSessionIndex"]);
			expect(result.complete).toBe(false);
			// And the boundary was still stamped: one missing capability does
			// not cost the others.
			expect(result.tokensRevoked).toBe(true);
		});

		it("cascades the sessions all the same", async () => {
			const index = createInMemorySubjectSessionIndex();
			await index.addSid("u-1", "sid-1", new Date(now().getTime() + 60 * MIN));
			const service = createSubjectRevocationService(keeping({ subjectSessionIndex: index }));

			const result = await service.revokeAllForSubject({
				subject: "u-1",
				federationGrants: "keep",
			});

			expect(result.sessionsRevoked).toEqual(["sid-1"]);
		});

		it("ends a grant the subject was in the middle of giving", async () => {
			// A pending grant is a consent in flight. Keeping what the subject
			// established is not keeping what they had not finished agreeing to.
			const h = harness();
			await h.store.createPending({
				id: "g-pending",
				subject: "u-1",
				clientId: "agent",
				connection: "okta-calendar",
				intent: { handle: "h", expiresAt: new Date(now().getTime() + 10 * MIN) },
				now: now(),
			});
			const events: { grantId: string; outcome: string }[] = [];
			const service = createSubjectRevocationService(
				keeping({
					federationGrantStore: h.store,
					federationGrantAudit: (event: { grantId: string; outcome: string }) => {
						events.push(event);
					},
				}),
			);

			const result = await service.revokeAllForSubject({
				subject: "u-1",
				federationGrants: "keep",
			});

			expect(result.grantsRevoked).toEqual(["g-pending"]);
			expect((await h.store.find("g-pending", now()))?.status).toBe("revoked");
			// Ending a grant is the same fact however it was decided.
			expect(events).toEqual([
				expect.objectContaining({ grantId: "g-pending", outcome: "subject" }),
			]);
		});

		it("gives each call one correlation ID of its own when the service was composed without one (#618)", async () => {
			const h = harness();
			await h.seed();
			await h.seed({ id: "g-2" });
			const events: { correlationId: string }[] = [];
			const service = createSubjectRevocationService(
				keeping({
					federationGrantStore: h.store,
					federationGrantAudit: (event: { correlationId: string }) => {
						events.push(event);
					},
				}),
			);

			await service.revokeAllForSubject({ subject: "u-1" });
			expect(events).toHaveLength(2);
			const ids = new Set(events.map((event) => event.correlationId));
			expect(ids.size).toBe(1);
			for (const id of ids) expect(id).toMatch(UUID);
		});

		it("treats a service composed with an empty correlation ID as composed without one (#618)", async () => {
			const h = harness();
			await h.seed();
			const events: { correlationId: string }[] = [];
			const service = createSubjectRevocationService(
				keeping({
					federationGrantStore: h.store,
					correlationId: "",
					federationGrantAudit: (event: { correlationId: string }) => {
						events.push(event);
					},
				}),
			);
			await service.revokeAllForSubject({ subject: "u-1" });
			expect(events[0]?.correlationId).toMatch(UUID);
		});

		it("gives a keep pass one correlation ID of its own too: what it ends — the pending grants — reads as one operation (#618)", async () => {
			const h = harness();
			for (const id of ["g-p1", "g-p2"]) {
				await h.store.createPending({
					id,
					subject: "u-1",
					clientId: "agent",
					connection: "okta-calendar",
					intent: { handle: `h-${id}`, expiresAt: new Date(now().getTime() + 10 * MIN) },
					now: now(),
				});
			}
			const events: { correlationId: string }[] = [];
			const service = createSubjectRevocationService(
				keeping({
					federationGrantStore: h.store,
					federationGrantAudit: (event: { correlationId: string }) => {
						events.push(event);
					},
				}),
			);

			const result = await service.revokeAllForSubject({
				subject: "u-1",
				federationGrants: "keep",
			});
			expect([...result.grantsRevoked].sort()).toEqual(["g-p1", "g-p2"]);
			expect(events).toHaveLength(2);
			const ids = new Set(events.map((event) => event.correlationId));
			expect(ids.size).toBe(1);
			for (const id of ids) expect(id).toMatch(UUID);
		});

		it("writes nothing to a grant that is already over", async () => {
			// A tombstone is retained so the status route can answer from it.
			// Revoking it again, or retiring an intent it cannot have, is a
			// write against a record nothing can change.
			const h = harness();
			await h.seed();
			await h.store.revoke("g-1", "operator", now());
			const revoke = vi.spyOn(h.store, "revoke");
			const retire = vi.spyOn(h.store, "retireIntent");
			const service = createSubjectRevocationService(keeping({ federationGrantStore: h.store }));

			const result = await service.revokeAllForSubject({
				subject: "u-1",
				federationGrants: "keep",
			});

			expect(revoke).not.toHaveBeenCalled();
			expect(retire).not.toHaveBeenCalled();
			expect(result.complete).toBe(true);
		});

		it("ends an established grant consented at or after the instant given", async () => {
			const h = harness();
			const since = new Date(now().getTime() - 10 * MIN);
			await h.seed({ id: "g-at", consentAt: since });
			await h.seed({ id: "g-after", consentAt: new Date(since.getTime() + 1) });
			await h.seed({ id: "g-before", consentAt: new Date(since.getTime() - 1) });
			const service = createSubjectRevocationService(keeping({ federationGrantStore: h.store }));

			const result = await service.revokeAllForSubject({
				subject: "u-1",
				federationGrants: "keep",
				revokeGrantsConsentedSince: since,
			});

			// Inclusive: a compromise dated to the minute takes the grant given
			// in that minute with it.
			expect([...result.grantsRevoked].sort()).toEqual(["g-after", "g-at"]);
			expect((await h.store.find("g-before", now()))?.status).toBe("active");
		});

		it("ends the renewal in flight of every grant it kept", async () => {
			// The grant stays. What does not is the reauthorization somebody
			// walked the subject into: it would widen a grant this call was
			// meant to freeze, and the pointer is the only part of it the
			// provider can still reach.
			const h = harness();
			await h.seed();
			await h.store.nameIntent({
				grantId: "g-1",
				intent: { handle: "renewal", expiresAt: new Date(now().getTime() + 10 * MIN) },
				now: now(),
			});
			const service = createSubjectRevocationService(keeping({ federationGrantStore: h.store }));

			const result = await service.revokeAllForSubject({
				subject: "u-1",
				federationGrants: "keep",
			});

			expect(result.grantsRetired).toEqual(["g-1"]);
			expect(result.grantsRevoked).toEqual([]);
			expect(await h.store.isCurrentIntent("g-1", "renewal", now())).toBe(false);
			expect((await h.store.find("g-1", now()))?.status).toBe("active");
		});

		it("counts a retirement that could not be written", async () => {
			const h = harness();
			await h.seed();
			vi.spyOn(h.store, "retireIntent").mockRejectedValue(new Error("store is down"));
			const logged: string[] = [];
			const service = createSubjectRevocationService(
				keeping({
					federationGrantStore: h.store,
					logger: { error: (_fields: unknown, message: string) => logged.push(message) },
				}),
			);

			const result = await service.revokeAllForSubject({
				subject: "u-1",
				federationGrants: "keep",
			});

			// Reporting a completed revocation while a renewal somebody else
			// started is still current would be the wrong half of the truth.
			expect(result.complete).toBe(false);
			// NOT `grantsFailed`, which means "the revocation write threw, still
			// live, safe to retry". A Store retrying these two as one list would
			// revoke the grants its operator's policy had just chosen to keep.
			expect(result.grantsRetireFailed).toEqual(["g-1"]);
			expect(result.grantsFailed).toEqual([]);
			expect(result.failures).toContainEqual(
				expect.objectContaining({ operation: "retireIntent", grantId: "g-1" }),
			);
			expect(logged).toContain("revoke_all_retire_intent_failed");
		});

		it("leaves a grant the operator dated still live when its write threw, and says so", async () => {
			// The incident the runbook is about. There is no grants boundary
			// behind a keep, so this grant is usable until somebody retries —
			// unlike the same failure under a full revocation, where the
			// boundary refuses it at `/token` meanwhile.
			const h = harness();
			const since = new Date(now().getTime() - 10 * MIN);
			await h.seed({ id: "g-bad", consentAt: since });
			vi.spyOn(h.store, "revoke").mockRejectedValue(new Error("store is down"));
			const logged: string[] = [];
			const service = createSubjectRevocationService(
				keeping({
					federationGrantStore: h.store,
					logger: { error: (_fields: unknown, message: string) => logged.push(message) },
				}),
			);

			const result = await service.revokeAllForSubject({
				subject: "u-1",
				federationGrants: "keep",
				revokeGrantsConsentedSince: since,
			});

			expect(result.complete).toBe(false);
			expect(result.grantsFailed).toEqual(["g-bad"]);
			expect(result.grantsRetireFailed).toEqual([]);
			expect(result.failures).toContainEqual(
				expect.objectContaining({ operation: "revoke", grantId: "g-bad" }),
			);
			expect((await h.store.find("g-bad", now()))?.status).toBe("active");
			// A failed revocation and a failed retirement are different lines,
			// because they send an operator to different places.
			expect(logged).toContain("revoke_all_revoke_grant_failed");
		});

		it("reports a listing outage rather than calling it a subject with no grants", async () => {
			const h = harness();
			await h.seed();
			vi.spyOn(h.store, "listBySubject").mockRejectedValue(new Error("store is down"));
			const service = createSubjectRevocationService(keeping({ federationGrantStore: h.store }));

			const result = await service.revokeAllForSubject({
				subject: "u-1",
				federationGrants: "keep",
			});

			expect(result.complete).toBe(false);
			expect(result.failures).toContainEqual(
				expect.objectContaining({ capability: "federationGrantStore", operation: "listBySubject" }),
			);
			// The sessions still ended: one pass failing does not cost another.
			expect(result.tokensRevoked).toBe(true);
		});

		it("does not count a dated grant somebody else had already ended", async () => {
			const h = harness();
			const since = new Date(now().getTime() - 10 * MIN);
			await h.seed({ id: "g-race", consentAt: since });
			vi.spyOn(h.store, "revoke").mockResolvedValue({ ok: false });
			const service = createSubjectRevocationService(keeping({ federationGrantStore: h.store }));

			const result = await service.revokeAllForSubject({
				subject: "u-1",
				federationGrants: "keep",
				revokeGrantsConsentedSince: since,
			});

			expect(result.complete).toBe(true);
			expect(result.grantsRevoked).toEqual([]);
			expect(result.grantsFailed).toEqual([]);
		});

		it("runs on the real clock when no clock is injected", async () => {
			const revocation = createInMemorySubjectRevocation();
			const { now: _injected, ...withoutClock } = keeping({ subjectRevocation: revocation });
			const service = createSubjectRevocationService(
				withoutClock as Parameters<typeof createSubjectRevocationService>[0],
			);

			await service.revokeAllForSubject({ subject: "u-1", federationGrants: "keep" });

			const stamped = await revocation.revokedBefore("u-1");
			expect(stamped).not.toBeNull();
			expect(Math.abs((stamped as Date).getTime() - Date.now())).toBeLessThan(5_000);
		});

		it("does not count a grant that had no renewal to end", async () => {
			const h = harness();
			await h.seed();
			const service = createSubjectRevocationService(keeping({ federationGrantStore: h.store }));

			const result = await service.revokeAllForSubject({
				subject: "u-1",
				federationGrants: "keep",
			});

			expect(result.complete).toBe(true);
			expect(result.grantsRetired).toEqual([]);
		});

		it("cannot rescue a grant an earlier revocation already covered", async () => {
			const revocation = createInMemorySubjectRevocation();
			const before = new Date(now().getTime() - MIN);
			await revocation.revokeBefore("u-1", before, new Date(now().getTime() + HORIZON_MS));
			const service = createSubjectRevocationService(keeping({ subjectRevocation: revocation }));

			await service.revokeAllForSubject({ subject: "u-1", federationGrants: "keep" });

			const grants = await revocation.grantsRevokedBefore("u-1");
			expect(grants?.getTime()).toBe(before.getTime());
		});

		it("refuses a consent instant that is not one, before it writes anything", async () => {
			const revocation = createInMemorySubjectRevocation();
			const service = createSubjectRevocationService(keeping({ subjectRevocation: revocation }));

			await expect(
				service.revokeAllForSubject({
					subject: "u-1",
					federationGrants: "keep",
					revokeGrantsConsentedSince: new Date("not a date"),
				}),
			).rejects.toThrow(/revokeGrantsConsentedSince/);
			expect(await revocation.revokedBefore("u-1")).toBeNull();
		});
	});
});
