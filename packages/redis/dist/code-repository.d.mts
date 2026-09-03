import type { AdapterBuilder, Code, CodeRepository, PathResolver } from "@o3co/auth-provider-core";
interface RedisClient {
    connect(): Promise<void>;
    get(key: string): Promise<string | null>;
    set(key: string, value: string, options?: {
        EX?: number;
    }): Promise<unknown>;
    getDel(key: string): Promise<string | null>;
    del(key: string): Promise<number>;
}
export declare class RedisCodeRepository implements CodeRepository {
    private redis;
    private defaultExpiresIn;
    constructor(redis: RedisClient, defaultExpiresIn?: number);
    static create(config: Record<string, unknown>, pathResolver?: PathResolver): Promise<RedisCodeRepository>;
    initialize(): Promise<void>;
    createCode({ code_challenge, code_challenge_method, expiresIn, }: {
        code_challenge?: string;
        code_challenge_method?: string;
        expiresIn?: number;
    }): Promise<Code>;
    getByCode(code: string): Promise<Code | null>;
    consumeByCode(code: string): Promise<Code | null>;
    removeByCode(code: string): Promise<void>;
    private parseCodeValue;
}
/**
 * AdapterFactory builder. Consumer wires:
 *   factory.register("redis", redisCodeRepositoryBuilder);
 *
 * `config` shape: `{ endpointUri: string; password?: string; defaultExpiresIn?: number }`.
 *
 * The repository is constructed and connected lazily on first call to
 * `factory.create(...)`. The redis client lifetime is owned by the repo
 * instance — for clean disposal across restarts, consumers should track
 * the resulting CodeRepository and orchestrate closure in their composition
 * root (no `dispose()` hook on the CodeRepository interface as of v0.5.0).
 *
 * Module pattern wrapper for `codeRepository` slot is intentionally NOT
 * provided in v0.5.0 — see Phase 10 plan §1 / Q4 (deferred to a separate
 * "legacy-slot module-parity" PR).
 */
export declare const redisCodeRepositoryBuilder: AdapterBuilder<CodeRepository>;
export {};
//# sourceMappingURL=code-repository.d.mts.map