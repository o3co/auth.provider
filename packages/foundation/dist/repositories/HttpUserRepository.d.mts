import type { User, UserRepository } from "@o3co/auth-provider-core";
export declare class HttpUserRepository implements UserRepository {
    private authenticateUrl;
    private authenticateByTokenUrl;
    private timeout;
    constructor({ authenticateUrl, authenticateByTokenUrl, timeout, }: {
        authenticateUrl: string;
        authenticateByTokenUrl: string;
        timeout: number;
    });
    authenticate(username: string, password: string): Promise<User | null>;
    authenticateByToken(token: string): Promise<User | null>;
    private post;
}
//# sourceMappingURL=HttpUserRepository.d.mts.map