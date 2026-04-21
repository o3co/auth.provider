import { describe, expect, it, vi } from "vitest";
import type {
	FederationTokenStoreBase,
	RefreshTokenStoreBase,
	UserSessionStoreBase,
} from "@o3co/auth-provider-core";
import { cascadeLogout } from "../cascadeLogout.mjs";

const okRefresh = () =>
	({ revokeFamily: vi.fn().mockResolvedValue(undefined) }) as unknown as RefreshTokenStoreBase;
const okFederation = () =>
	({ deleteBySession: vi.fn().mockResolvedValue(undefined) }) as unknown as FederationTokenStoreBase;
const okSession = () =>
	({ delete: vi.fn().mockResolvedValue(undefined) }) as unknown as UserSessionStoreBase;

describe("cascadeLogout (spec Section 14.2)", () => {
	it("executes in fixed order: revokeFamily (each) → deleteBySession → delete", async () => {
		const rts = okRefresh();
		const fts = okFederation();
		const uss = okSession();
		const result = await cascadeLogout({
			sid: "sid-1",
			familyIds: ["fam-1", "fam-2"],
			refreshTokenStore: rts,
			federationTokenStore: fts,
			userSessionStore: uss,
		});
		expect(result.outcome).toBe("done");
		expect((rts as unknown as { revokeFamily: typeof vi.fn }).revokeFamily).toHaveBeenCalledTimes(2);
		expect((rts as unknown as { revokeFamily: typeof vi.fn }).revokeFamily).toHaveBeenNthCalledWith(1, "fam-1");
		expect((rts as unknown as { revokeFamily: typeof vi.fn }).revokeFamily).toHaveBeenNthCalledWith(2, "fam-2");
		expect((fts as unknown as { deleteBySession: typeof vi.fn }).deleteBySession).toHaveBeenCalledWith("sid-1");
		expect((uss as unknown as { delete: typeof vi.fn }).delete).toHaveBeenCalledWith("sid-1");
	});

	it("step-1 throw → outcome: failed, step: 1; steps 2/3 NOT executed", async () => {
		const rts = { revokeFamily: vi.fn().mockRejectedValue(new Error("redis down")) };
		const fts = okFederation();
		const uss = okSession();
		const result = await cascadeLogout({
			sid: "s",
			familyIds: ["f"],
			refreshTokenStore: rts as unknown as RefreshTokenStoreBase,
			federationTokenStore: fts,
			userSessionStore: uss,
		});
		expect(result.outcome).toBe("failed");
		if (result.outcome === "failed") {
			expect(result.step).toBe(1);
			expect(result.error).toBeInstanceOf(Error);
		}
		expect((fts as unknown as { deleteBySession: typeof vi.fn }).deleteBySession).not.toHaveBeenCalled();
		expect((uss as unknown as { delete: typeof vi.fn }).delete).not.toHaveBeenCalled();
	});

	it("step-2 throw → outcome: done, continues to step 3 (best-effort)", async () => {
		const rts = okRefresh();
		const fts = { deleteBySession: vi.fn().mockRejectedValue(new Error("net")) };
		const uss = okSession();
		const warnings: unknown[] = [];
		const originalWarn = console.warn;
		console.warn = (...args: unknown[]) => {
			warnings.push(args);
		};
		try {
			const result = await cascadeLogout({
				sid: "s",
				familyIds: ["f"],
				refreshTokenStore: rts,
				federationTokenStore: fts as unknown as FederationTokenStoreBase,
				userSessionStore: uss,
			});
			expect(result.outcome).toBe("done");
			expect((uss as unknown as { delete: typeof vi.fn }).delete).toHaveBeenCalled();
			expect(warnings.length).toBeGreaterThan(0);
		} finally {
			console.warn = originalWarn;
		}
	});

	it("routes step-2 warning to opts.logger when provided (not console.warn)", async () => {
		const rts = okRefresh();
		const fts = { deleteBySession: vi.fn().mockRejectedValue(new Error("net")) };
		const uss = okSession();
		const loggerWarn = vi.fn();
		const consoleWarnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
		try {
			const result = await cascadeLogout({
				sid: "s",
				familyIds: ["f"],
				refreshTokenStore: rts,
				federationTokenStore: fts as unknown as FederationTokenStoreBase,
				userSessionStore: uss,
				logger: { warn: loggerWarn },
			});
			expect(result.outcome).toBe("done");
			expect(loggerWarn).toHaveBeenCalledTimes(1);
			expect(loggerWarn.mock.calls[0]?.[0]).toMatch(/cascadeLogout/);
			expect(consoleWarnSpy).not.toHaveBeenCalled();
		} finally {
			consoleWarnSpy.mockRestore();
		}
	});

	it("step-3 throw → outcome: failed, step: 3", async () => {
		const rts = okRefresh();
		const fts = okFederation();
		const uss = { delete: vi.fn().mockRejectedValue(new Error("redis down")) };
		const result = await cascadeLogout({
			sid: "s",
			familyIds: ["f"],
			refreshTokenStore: rts,
			federationTokenStore: fts,
			userSessionStore: uss as unknown as UserSessionStoreBase,
		});
		expect(result.outcome).toBe("failed");
		if (result.outcome === "failed") {
			expect(result.step).toBe(3);
		}
	});

	it("empty familyIds array skips step 1 and still runs 2+3", async () => {
		const rts = okRefresh();
		const fts = okFederation();
		const uss = okSession();
		await cascadeLogout({
			sid: "s",
			familyIds: [],
			refreshTokenStore: rts,
			federationTokenStore: fts,
			userSessionStore: uss,
		});
		expect((rts as unknown as { revokeFamily: typeof vi.fn }).revokeFamily).not.toHaveBeenCalled();
		expect((fts as unknown as { deleteBySession: typeof vi.fn }).deleteBySession).toHaveBeenCalled();
		expect((uss as unknown as { delete: typeof vi.fn }).delete).toHaveBeenCalled();
	});
});
