import type { User } from "./types.mjs";
export interface UserRepository {
    authenticate(username: string, password: string): Promise<User | null>;
    authenticateByToken(token: string): Promise<User | null>;
}
//# sourceMappingURL=UserRepository.d.mts.map