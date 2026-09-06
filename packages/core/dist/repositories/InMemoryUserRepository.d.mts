import { z } from "zod";
import type { User } from "./types.mjs";
import type { UserRepository } from "./UserRepository.mjs";
export declare const UserEntrySchema: z.ZodObject<{
    password: z.ZodString;
    id: z.ZodOptional<z.ZodString>;
}, z.core.$catchall<z.ZodUnknown>>;
export type UserEntry = z.infer<typeof UserEntrySchema>;
export declare class InMemoryUserRepository implements UserRepository {
    private users;
    constructor(users: Map<string, UserEntry>);
    private toUser;
    authenticate(username: string, password: string): Promise<User | null>;
    authenticateByToken(token: string): Promise<User | null>;
}
//# sourceMappingURL=InMemoryUserRepository.d.mts.map