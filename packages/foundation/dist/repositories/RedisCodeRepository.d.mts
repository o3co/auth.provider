import type { Code, CodeRepository, PathResolver } from "@o3co/auth-provider-core";
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
export {};
//# sourceMappingURL=RedisCodeRepository.d.mts.map