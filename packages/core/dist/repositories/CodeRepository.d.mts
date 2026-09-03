import type { Code } from "./types.mjs";
export interface CodeRepository {
    createCode(params: {
        code_challenge?: string;
        code_challenge_method?: string;
        redirect_uri?: string;
        expiresIn?: number;
        grantedScope?: readonly string[];
        grantedAudience?: readonly string[];
        nonce?: string;
        sid?: string;
    }): Promise<Code>;
    getByCode(code: string): Promise<Code | null>;
    consumeByCode(code: string): Promise<Code | null>;
    removeByCode(code: string): Promise<void>;
}
//# sourceMappingURL=CodeRepository.d.mts.map