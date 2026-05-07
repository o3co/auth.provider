import type {
	FederationTokenStoreBase,
	RefreshTokenFamilyRevocation,
	SessionFamilyIndex,
	SessionFederationIndex,
	SessionRPRegistry,
	UserSessionStore,
} from "@o3co/auth-provider-core";
import { describe, expect, it, vi } from "vitest";
import { createMockLogger } from "../../__tests__/_helpers/mockLogger.mjs";
import { cascadeLogout } from "../cascadeLogout.mjs";

// ---------------------------------------------------------------------------
// Mock factories
// ---------------------------------------------------------------------------

function makeFamilyRevocation(
	override?: Partial<RefreshTokenFamilyRevocation>,
): RefreshTokenFamilyRevocation {
	return {
		isFamilyRevoked: vi.fn().mockResolvedValue(false),
		revokeFamily: vi.fn().mockResolvedValue(undefined),
		...override,
	};
}

function makeFedStore(override?: Partial<FederationTokenStoreBase>): FederationTokenStoreBase {
	return {
		kind: "memory",
		attach: vi.fn(),
		get: vi.fn().mockResolvedValue(null),
		update: vi.fn(),
		deleteBySession: vi.fn().mockResolvedValue(undefined),
		delete: vi.fn(),
		...override,
	} as unknown as FederationTokenStoreBase;
}

function makeUserSessionStore(override?: Partial<UserSessionStore>): UserSessionStore {
	return {
		kind: "memory",
		create: vi.fn(),
		get: vi.fn().mockResolvedValue(null),
		delete: vi.fn().mockResolvedValue(undefined),
		...override,
	} as unknown as UserSessionStore;
}

function makeSessionRPRegistry(override?: Partial<SessionRPRegistry>): SessionRPRegistry {
	return {
		kind: "memory",
		registerRP: vi.fn(async () => {}),
		listRPs: vi.fn(async () => []),
		removeBySid: vi.fn(async () => {}),
		...override,
	} as SessionRPRegistry;
}

function makeSessionFamilyIndex(override?: Partial<SessionFamilyIndex>): SessionFamilyIndex {
	return {
		kind: "memory",
		addFamilyId: vi.fn(async () => {}),
		listFamilyIds: vi.fn(async () => []),
		removeBySid: vi.fn(async () => {}),
		...override,
	} as SessionFamilyIndex;
}

function makeSessionFederationIndex(
	override?: Partial<SessionFederationIndex>,
): SessionFederationIndex {
	return {
		kind: "memory",
		addFederation: vi.fn(async () => {}),
		listFederations: vi.fn(async () => []),
		removeFederation: vi.fn(async () => {}),
		removeBySid: vi.fn(async () => {}),
		...override,
	} as SessionFederationIndex;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("cascadeLogout (A4 §6.2)", () => {
	it("executes in §6.2 order: listFamilyIds → revokeFamily (each) → deleteBySession → removeBySid (×3) → delete → post-step-4 sessionFamilyIndex.removeBySid (CR-4)", async () => {
		const sessionFamilyIndex = makeSessionFamilyIndex({
			listFamilyIds: vi.fn(async () => ["fam-1", "fam-2"]),
		});
		const rts = makeFamilyRevocation();
		const fts = makeFedStore();
		const uss = makeUserSessionStore();
		const sessionRPRegistry = makeSessionRPRegistry();
		const sessionFederationIndex = makeSessionFederationIndex();

		const result = await cascadeLogout({
			sid: "sid-1",
			refreshTokenFamilyRevocation: rts,
			federationTokenStore: fts,
			userSessionStore: uss,
			sessionRPRegistry,
			sessionFamilyIndex,
			sessionFederationIndex,
		});

		expect(result.outcome).toBe("done");
		// Step 1: listFamilyIds called
		expect(sessionFamilyIndex.listFamilyIds).toHaveBeenCalledWith("sid-1");
		// Step 2: revokeFamily called for each family
		expect(rts.revokeFamily).toHaveBeenCalledTimes(2);
		expect(rts.revokeFamily).toHaveBeenNthCalledWith(1, "fam-1");
		expect(rts.revokeFamily).toHaveBeenNthCalledWith(2, "fam-2");
		// Step 2: federation tokens deleted
		expect(fts.deleteBySession).toHaveBeenCalledWith("sid-1");
		// Step 3: all three reverse-index removeBySid called.
		expect(sessionRPRegistry.removeBySid).toHaveBeenCalledWith("sid-1");
		expect(sessionFederationIndex.removeBySid).toHaveBeenCalledWith("sid-1");
		// CR-4: sessionFamilyIndex.removeBySid is now called twice — once at Step 3
		// and again as defense-in-depth after Step 4 (see CR-4 invocation-order test
		// below). Both calls receive the same sid argument.
		expect(sessionFamilyIndex.removeBySid).toHaveBeenCalledWith("sid-1");
		// Step 4: primary invalidation must succeed.
		expect(uss.delete).toHaveBeenCalledWith("sid-1");
	});

	it("empty familyIds skips revokeFamily loop and still runs Steps 2–4", async () => {
		const sessionFamilyIndex = makeSessionFamilyIndex({
			listFamilyIds: vi.fn(async () => []),
		});
		const rts = makeFamilyRevocation();
		const fts = makeFedStore();
		const uss = makeUserSessionStore();

		await cascadeLogout({
			sid: "s",
			refreshTokenFamilyRevocation: rts,
			federationTokenStore: fts,
			userSessionStore: uss,
			sessionRPRegistry: makeSessionRPRegistry(),
			sessionFamilyIndex,
			sessionFederationIndex: makeSessionFederationIndex(),
		});

		expect(rts.revokeFamily).not.toHaveBeenCalled();
		expect(fts.deleteBySession).toHaveBeenCalled();
		expect(uss.delete).toHaveBeenCalled();
	});

	// -------------------------------------------------------------------------
	// Step 1 failures
	// -------------------------------------------------------------------------

	it("Step 1 (sessionFamilyIndex.listFamilyIds) failure → step:1, errors:[err]", async () => {
		const result = await cascadeLogout({
			sid: "s1",
			refreshTokenFamilyRevocation: makeFamilyRevocation(),
			federationTokenStore: makeFedStore(),
			userSessionStore: makeUserSessionStore(),
			sessionRPRegistry: makeSessionRPRegistry(),
			sessionFamilyIndex: makeSessionFamilyIndex({
				listFamilyIds: vi.fn(async () => {
					throw new Error("read fail");
				}),
			}),
			sessionFederationIndex: makeSessionFederationIndex(),
		});

		expect(result.outcome).toBe("failed");
		if (result.outcome === "failed") {
			expect(result.step).toBe(1);
			expect(result.errors).toHaveLength(1);
			expect(result.errors[0]).toBeInstanceOf(Error);
		}
	});

	it("Step 1 failure → Steps 2/3/4 NOT executed", async () => {
		const rts = makeFamilyRevocation();
		const fts = makeFedStore();
		const uss = makeUserSessionStore();
		const sessionRPRegistry = makeSessionRPRegistry();
		const sessionFamilyIndex = makeSessionFamilyIndex({
			listFamilyIds: vi.fn(async () => {
				throw new Error("redis down");
			}),
		});
		const sessionFederationIndex = makeSessionFederationIndex();

		await cascadeLogout({
			sid: "s",
			refreshTokenFamilyRevocation: rts,
			federationTokenStore: fts,
			userSessionStore: uss,
			sessionRPRegistry,
			sessionFamilyIndex,
			sessionFederationIndex,
		});

		expect(rts.revokeFamily).not.toHaveBeenCalled();
		expect(fts.deleteBySession).not.toHaveBeenCalled();
		expect(sessionRPRegistry.removeBySid).not.toHaveBeenCalled();
		expect(sessionFamilyIndex.removeBySid).not.toHaveBeenCalled();
		expect(sessionFederationIndex.removeBySid).not.toHaveBeenCalled();
		expect(uss.delete).not.toHaveBeenCalled();
	});

	// -------------------------------------------------------------------------
	// Step 2 failures (collect-and-tally + HALT)
	// -------------------------------------------------------------------------

	it("Step 2 revokeFamily failure → outcome: failed, step:2, errors with that error", async () => {
		const rts = makeFamilyRevocation({
			revokeFamily: vi.fn().mockRejectedValue(new Error("redis down")),
		});
		const result = await cascadeLogout({
			sid: "s",
			refreshTokenFamilyRevocation: rts,
			federationTokenStore: makeFedStore(),
			userSessionStore: makeUserSessionStore(),
			sessionRPRegistry: makeSessionRPRegistry(),
			sessionFamilyIndex: makeSessionFamilyIndex({
				listFamilyIds: vi.fn(async () => ["f"]),
			}),
			sessionFederationIndex: makeSessionFederationIndex(),
		});

		expect(result.outcome).toBe("failed");
		if (result.outcome === "failed") {
			expect(result.step).toBe(2);
			expect(result.errors).toHaveLength(1);
			expect(result.errors[0]).toBeInstanceOf(Error);
		}
	});

	it("Step 2 partial failure HALTS — Step 3 reverse-index cleanup NOT called, Step 4 NOT called", async () => {
		const sessionRPRegistry = makeSessionRPRegistry();
		const sessionFamilyIndex = makeSessionFamilyIndex({
			listFamilyIds: vi.fn(async () => ["fam-1", "fam-2"]),
		});
		const sessionFederationIndex = makeSessionFederationIndex();
		const uss = makeUserSessionStore();
		const rts = makeFamilyRevocation({
			revokeFamily: vi.fn(async (id: string) => {
				if (id === "fam-2") throw new Error("revoke fail");
			}),
		});

		const result = await cascadeLogout({
			sid: "s1",
			refreshTokenFamilyRevocation: rts,
			federationTokenStore: makeFedStore(),
			userSessionStore: uss,
			sessionRPRegistry,
			sessionFamilyIndex,
			sessionFederationIndex,
		});

		expect(result.outcome).toBe("failed");
		if (result.outcome === "failed") expect(result.step).toBe(2);

		// CRITICAL: §6.2 invariant — reverse-index cleanup MUST NOT have run
		expect(sessionRPRegistry.removeBySid).not.toHaveBeenCalled();
		expect(sessionFamilyIndex.removeBySid).not.toHaveBeenCalled();
		expect(sessionFederationIndex.removeBySid).not.toHaveBeenCalled();
		// Step 4 MUST NOT have run
		expect(uss.delete).not.toHaveBeenCalled();
	});

	it("Step 2 collect-and-tally: all revokeFamily failures collected before HALT", async () => {
		const rts = makeFamilyRevocation({
			revokeFamily: vi.fn().mockRejectedValue(new Error("fail")),
		});
		const result = await cascadeLogout({
			sid: "s",
			refreshTokenFamilyRevocation: rts,
			federationTokenStore: makeFedStore({
				deleteBySession: vi.fn().mockRejectedValue(new Error("fed fail")),
			}),
			userSessionStore: makeUserSessionStore(),
			sessionRPRegistry: makeSessionRPRegistry(),
			sessionFamilyIndex: makeSessionFamilyIndex({
				listFamilyIds: vi.fn(async () => ["fam-1", "fam-2"]),
			}),
			sessionFederationIndex: makeSessionFederationIndex(),
		});

		expect(result.outcome).toBe("failed");
		if (result.outcome === "failed") {
			expect(result.step).toBe(2);
			// 2 revokeFamily failures + 1 deleteBySession failure = 3 errors
			expect(result.errors).toHaveLength(3);
		}
	});

	it("Step 2 federationTokenStore.deleteBySession failure → outcome: failed, step:2 (no longer best-effort standalone)", async () => {
		const fts = makeFedStore({
			deleteBySession: vi.fn().mockRejectedValue(new Error("net")),
		});
		const uss = makeUserSessionStore();
		const result = await cascadeLogout({
			sid: "s",
			refreshTokenFamilyRevocation: makeFamilyRevocation(),
			federationTokenStore: fts,
			userSessionStore: uss,
			sessionRPRegistry: makeSessionRPRegistry(),
			sessionFamilyIndex: makeSessionFamilyIndex({
				listFamilyIds: vi.fn(async () => []),
			}),
			sessionFederationIndex: makeSessionFederationIndex(),
		});

		expect(result.outcome).toBe("failed");
		if (result.outcome === "failed") {
			expect(result.step).toBe(2);
			expect(result.errors).toHaveLength(1);
		}
		// HALT: Step 4 must NOT have run
		expect(uss.delete).not.toHaveBeenCalled();
	});

	it("routes step-2 warning to opts.logger when provided (not console.warn)", async () => {
		const rts = makeFamilyRevocation({
			revokeFamily: vi.fn().mockRejectedValue(new Error("redis down")),
		});
		const loggerWarn = vi.fn();
		const consoleWarnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
		try {
			await cascadeLogout({
				sid: "s",
				refreshTokenFamilyRevocation: rts,
				federationTokenStore: makeFedStore(),
				userSessionStore: makeUserSessionStore(),
				sessionRPRegistry: makeSessionRPRegistry(),
				sessionFamilyIndex: makeSessionFamilyIndex({
					listFamilyIds: vi.fn(async () => ["f"]),
				}),
				sessionFederationIndex: makeSessionFederationIndex(),
				logger: Object.assign(createMockLogger(), { warn: loggerWarn }),
			});
			expect(loggerWarn).toHaveBeenCalledTimes(1);
			expect(loggerWarn.mock.calls[0]?.[0]).toMatch(/cascadeLogout/);
			expect(consoleWarnSpy).not.toHaveBeenCalled();
		} finally {
			consoleWarnSpy.mockRestore();
		}
	});

	// -------------------------------------------------------------------------
	// Step 3 (best-effort — never halts)
	// -------------------------------------------------------------------------

	it("Step 3 reverse-index removeBySid failure does NOT halt Step 4", async () => {
		const sessionFamilyIndex = makeSessionFamilyIndex({
			listFamilyIds: vi.fn(async () => []),
		});
		const uss = makeUserSessionStore();
		const sessionRPRegistry = makeSessionRPRegistry({
			removeBySid: vi.fn(async () => {
				throw new Error("transient blip");
			}),
		});

		const result = await cascadeLogout({
			sid: "s1",
			refreshTokenFamilyRevocation: makeFamilyRevocation(),
			federationTokenStore: makeFedStore(),
			userSessionStore: uss,
			sessionRPRegistry,
			sessionFamilyIndex,
			sessionFederationIndex: makeSessionFederationIndex(),
		});

		expect(result.outcome).toBe("done");
		// Step 4 still ran — orphan rp-registry entry is naturally bounded by TTL
		expect(uss.delete).toHaveBeenCalledWith("s1");
	});

	it("Step 3 all removeBySid failures do NOT halt Step 4", async () => {
		const throwFn = vi.fn(async () => {
			throw new Error("blip");
		});
		const uss = makeUserSessionStore();

		const result = await cascadeLogout({
			sid: "s1",
			refreshTokenFamilyRevocation: makeFamilyRevocation(),
			federationTokenStore: makeFedStore(),
			userSessionStore: uss,
			sessionRPRegistry: makeSessionRPRegistry({ removeBySid: throwFn }),
			sessionFamilyIndex: makeSessionFamilyIndex({
				listFamilyIds: vi.fn(async () => []),
				removeBySid: throwFn,
			}),
			sessionFederationIndex: makeSessionFederationIndex({ removeBySid: throwFn }),
		});

		expect(result.outcome).toBe("done");
		expect(uss.delete).toHaveBeenCalledWith("s1");
	});

	// -------------------------------------------------------------------------
	// Step 4 failures
	// -------------------------------------------------------------------------

	it("Step 4 (userSessionStore.delete) failure → step:4, errors:[err]", async () => {
		const uss = makeUserSessionStore({
			delete: vi.fn(async () => {
				throw new Error("persistence failure");
			}),
		});

		const result = await cascadeLogout({
			sid: "s1",
			refreshTokenFamilyRevocation: makeFamilyRevocation(),
			federationTokenStore: makeFedStore(),
			userSessionStore: uss,
			sessionRPRegistry: makeSessionRPRegistry(),
			sessionFamilyIndex: makeSessionFamilyIndex({
				listFamilyIds: vi.fn(async () => []),
			}),
			sessionFederationIndex: makeSessionFederationIndex(),
		});

		expect(result.outcome).toBe("failed");
		if (result.outcome === "failed") {
			expect(result.step).toBe(4);
			expect(result.errors).toHaveLength(1);
			expect(result.errors[0]).toBeInstanceOf(Error);
		}
	});

	// -------------------------------------------------------------------------
	// CR-4 — post-step-4 sessionFamilyIndex cleanup
	//
	// Defense-in-depth: any addFamilyId call that raced into the family index
	// between Step 3 and Step 4 (the TOCTOU window the authorization grant's
	// second-check fix narrows but does not fully close) leaves an orphan entry.
	// A second removeBySid AFTER the session delete clears that orphan. The
	// invocation order MUST be: Step 3 removeBySid → Step 4 delete → post-step-4
	// removeBySid. Codex Delta 5: pin the order to catch accidental reshuffling.
	// -------------------------------------------------------------------------

	it("CR-4: runs sessionFamilyIndex.removeBySid AFTER userSessionStore.delete (post-step-4 cleanup)", async () => {
		const sessionFamilyIndex = makeSessionFamilyIndex({
			listFamilyIds: vi.fn(async () => []),
		});
		const uss = makeUserSessionStore();

		const result = await cascadeLogout({
			sid: "sid-cr4",
			refreshTokenFamilyRevocation: makeFamilyRevocation(),
			federationTokenStore: makeFedStore(),
			userSessionStore: uss,
			sessionRPRegistry: makeSessionRPRegistry(),
			sessionFamilyIndex,
			sessionFederationIndex: makeSessionFederationIndex(),
		});

		expect(result.outcome).toBe("done");

		// Step 3 removeBySid + post-step-4 removeBySid → twice total.
		expect(sessionFamilyIndex.removeBySid).toHaveBeenCalledTimes(2);
		expect(sessionFamilyIndex.removeBySid).toHaveBeenNthCalledWith(1, "sid-cr4");
		expect(sessionFamilyIndex.removeBySid).toHaveBeenNthCalledWith(2, "sid-cr4");

		// Codex Delta 5: pin invocation order.
		// removeBySid call 1 (Step 3) MUST precede userSessionStore.delete (Step 4).
		// userSessionStore.delete (Step 4) MUST precede removeBySid call 2 (post-step-4).
		const removeOrders = (sessionFamilyIndex.removeBySid as ReturnType<typeof vi.fn>).mock
			.invocationCallOrder;
		const deleteOrder = (uss.delete as ReturnType<typeof vi.fn>).mock.invocationCallOrder[0];
		expect(removeOrders).toHaveLength(2);
		expect(removeOrders[0]).toBeLessThan(deleteOrder);
		expect(deleteOrder).toBeLessThan(removeOrders[1]);
	});

	it("CR-4: post-step-4 removeBySid failure does NOT change cascade outcome (best-effort)", async () => {
		// First removeBySid (Step 3) succeeds, second (post-step-4) throws — must be
		// swallowed and logged so the cascade still reports done.
		let calls = 0;
		const sessionFamilyIndex = makeSessionFamilyIndex({
			listFamilyIds: vi.fn(async () => []),
			removeBySid: vi.fn(async () => {
				calls++;
				if (calls === 2) {
					throw new Error("post-delete cleanup failed");
				}
			}),
		});
		const logger = createMockLogger();

		const result = await cascadeLogout({
			sid: "sid-besteffort",
			refreshTokenFamilyRevocation: makeFamilyRevocation(),
			federationTokenStore: makeFedStore(),
			userSessionStore: makeUserSessionStore(),
			sessionRPRegistry: makeSessionRPRegistry(),
			sessionFamilyIndex,
			sessionFederationIndex: makeSessionFederationIndex(),
			logger,
		});

		expect(result.outcome).toBe("done");
		expect(calls).toBe(2);
		// Failure surfaces via the structured logger.
		expect(logger.warn).toHaveBeenCalled();
	});
});
