import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
// D-2 v2: ioredis Redis constructor capture. The module under test imports
// `Redis` from "ioredis"; vi.mock replaces that import so the test never
// opens a real socket. Captured arguments verify that the validated config
// reaches the constructor (BLOCKER 1: schema strip closure).
const redisCtorCalls = [];
const quitSpies = [];
const onSpies = [];
vi.mock("ioredis", () => {
    class MockRedis {
        duplicate() {
            return new MockRedis("redis://duplicate.local");
        }
        on = vi.fn();
        quit = vi.fn(async () => "OK");
        // Minimal command surface — `makeIoredisClients` only invokes these
        // during construction in some paths; tests never exercise the wrapped
        // client itself, so most stubs are unused.
        set = vi.fn();
        get = vi.fn();
        pttl = vi.fn();
        watch = vi.fn();
        unwatch = vi.fn();
        multi = vi.fn(() => ({
            set: vi.fn().mockReturnThis(),
            exec: vi.fn(async () => []),
        }));
        constructor(url, options) {
            redisCtorCalls.push({ url, options });
            onSpies.push(this.on);
            quitSpies.push(this.quit);
        }
    }
    return { Redis: MockRedis, default: MockRedis };
});
// Imported AFTER vi.mock so the mocked ioredis is in scope.
const importModule = async () => (await import("../modules.mjs"));
// D-1 / D-5 are already merged on develop, so importing `standaloneRedisClientsModule`
// from `../modules.mjs` is the natural integration point. Pre-fix the export does not
// exist — TS error → RED.
const baseConfig = {
    refreshTokenFamilyStore: {
        redis: { url: "redis://example.com:6379", password: "test-pw" },
    },
};
describe("D-2 / standaloneRedisClientsModule", () => {
    beforeEach(() => {
        redisCtorCalls.length = 0;
        quitSpies.length = 0;
        onSpies.length = 0;
    });
    afterEach(() => {
        vi.restoreAllMocks();
    });
    it("passes operator-supplied Redis URL + password from config to the ioredis constructor (BLOCKER 1 closure)", async () => {
        const { standaloneRedisClientsModule } = await importModule();
        const provides = standaloneRedisClientsModule.provides;
        await provides.refreshTokenFamilyClient({ config: { ...baseConfig } });
        expect(redisCtorCalls).toHaveLength(1);
        expect(redisCtorCalls[0]?.url).toBe("redis://example.com:6379");
        expect(redisCtorCalls[0]?.options?.password).toBe("test-pw");
    });
    it("registers io.quit() with lifecycleRegistrar when provided; drain calls quit exactly once", async () => {
        const registered = [];
        const lifecycleRegistrar = {
            register: (cleanup) => {
                registered.push(cleanup);
            },
        };
        const { standaloneRedisClientsModule } = await importModule();
        const provides = standaloneRedisClientsModule.provides;
        await provides.refreshTokenFamilyClient({ config: { ...baseConfig }, lifecycleRegistrar });
        expect(registered).toHaveLength(1);
        // Pre-drain: quit not yet called.
        expect(quitSpies[0]).not.toHaveBeenCalled();
        // Drain (simulate handle.dispose()).
        await registered[0]?.();
        expect(quitSpies[0]).toHaveBeenCalledTimes(1);
    });
    it("does not crash when lifecycleRegistrar is absent (graceful no-op, no quit registered)", async () => {
        const { standaloneRedisClientsModule } = await importModule();
        const provides = standaloneRedisClientsModule.provides;
        // No lifecycleRegistrar key in deps — must not throw and must NOT
        // register a cleanup (verified by the absence of any quit invocation
        // after the factory resolves; the registrar branch is the only place
        // `quit()` would be wired up in the no-real-shutdown unit-test path).
        await expect(provides.refreshTokenFamilyClient({ config: { ...baseConfig } })).resolves.toBeDefined();
        expect(quitSpies[0]).not.toHaveBeenCalled();
    });
    it("fails fast when refreshTokenFamilyStore.redis.url is missing (no silent localhost fallback)", async () => {
        const { standaloneRedisClientsModule } = await importModule();
        const provides = standaloneRedisClientsModule.provides;
        // Operator deliberately removed the section — must throw instead of
        // silently falling back to redis://localhost:6379 (which would re-
        // introduce the OR-1 multi-replica failure mode in production).
        await expect(provides.refreshTokenFamilyClient({ config: {} })).rejects.toThrow(/refreshTokenFamilyStore\.redis\.url/);
        // And no ioredis instance was constructed because we threw before
        // `new Redis(...)`.
        expect(redisCtorCalls).toHaveLength(0);
    });
    it("attaches an error event handler to the ioredis client (prevents unhandled-error crash)", async () => {
        const { standaloneRedisClientsModule } = await importModule();
        const provides = standaloneRedisClientsModule.provides;
        await provides.refreshTokenFamilyClient({ config: { ...baseConfig } });
        expect(onSpies[0]).toHaveBeenCalledWith("error", expect.any(Function));
    });
    it("declares 'config' as required and 'lifecycleRegistrar' as optional", async () => {
        const { standaloneRedisClientsModule } = await importModule();
        const m = standaloneRedisClientsModule;
        expect(m.requires).toContain("config");
        expect(m.optional).toContain("lifecycleRegistrar");
    });
});
