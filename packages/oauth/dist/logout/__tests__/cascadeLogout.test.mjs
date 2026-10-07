import { describe, expect, it, vi } from "vitest";
import { cascadeLogout } from "../cascadeLogout.mjs";
const okRefresh = () => ({ revokeFamily: vi.fn().mockResolvedValue(undefined) });
const okFederation = () => ({
    deleteBySession: vi.fn().mockResolvedValue(undefined),
});
const okSession = () => ({ delete: vi.fn().mockResolvedValue(undefined) });
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
        expect(rts.revokeFamily).toHaveBeenCalledTimes(2);
        expect(rts.revokeFamily).toHaveBeenNthCalledWith(1, "fam-1");
        expect(rts.revokeFamily).toHaveBeenNthCalledWith(2, "fam-2");
        expect(fts.deleteBySession).toHaveBeenCalledWith("sid-1");
        expect(uss.delete).toHaveBeenCalledWith("sid-1");
    });
    it("step-1 throw → outcome: failed, step: 1; steps 2/3 NOT executed", async () => {
        const rts = { revokeFamily: vi.fn().mockRejectedValue(new Error("redis down")) };
        const fts = okFederation();
        const uss = okSession();
        const result = await cascadeLogout({
            sid: "s",
            familyIds: ["f"],
            refreshTokenStore: rts,
            federationTokenStore: fts,
            userSessionStore: uss,
        });
        expect(result.outcome).toBe("failed");
        if (result.outcome === "failed") {
            expect(result.step).toBe(1);
            expect(result.error).toBeInstanceOf(Error);
        }
        expect(fts.deleteBySession).not.toHaveBeenCalled();
        expect(uss.delete).not.toHaveBeenCalled();
    });
    it("step-2 throw → outcome: done, continues to step 3 (best-effort)", async () => {
        const rts = okRefresh();
        const fts = { deleteBySession: vi.fn().mockRejectedValue(new Error("net")) };
        const uss = okSession();
        const warnings = [];
        const originalWarn = console.warn;
        console.warn = (...args) => {
            warnings.push(args);
        };
        try {
            const result = await cascadeLogout({
                sid: "s",
                familyIds: ["f"],
                refreshTokenStore: rts,
                federationTokenStore: fts,
                userSessionStore: uss,
            });
            expect(result.outcome).toBe("done");
            expect(uss.delete).toHaveBeenCalled();
            expect(warnings.length).toBeGreaterThan(0);
        }
        finally {
            console.warn = originalWarn;
        }
    });
    it("routes step-2 warning to opts.logger when provided (not console.warn)", async () => {
        const rts = okRefresh();
        const fts = { deleteBySession: vi.fn().mockRejectedValue(new Error("net")) };
        const uss = okSession();
        const loggerWarn = vi.fn();
        const consoleWarnSpy = vi.spyOn(console, "warn").mockImplementation(() => { });
        try {
            const result = await cascadeLogout({
                sid: "s",
                familyIds: ["f"],
                refreshTokenStore: rts,
                federationTokenStore: fts,
                userSessionStore: uss,
                logger: { warn: loggerWarn },
            });
            expect(result.outcome).toBe("done");
            expect(loggerWarn).toHaveBeenCalledTimes(1);
            expect(loggerWarn.mock.calls[0]?.[0]).toMatch(/cascadeLogout/);
            expect(consoleWarnSpy).not.toHaveBeenCalled();
        }
        finally {
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
            userSessionStore: uss,
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
        expect(rts.revokeFamily).not.toHaveBeenCalled();
        expect(fts.deleteBySession).toHaveBeenCalled();
        expect(uss.delete).toHaveBeenCalled();
    });
});
