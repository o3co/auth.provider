/**
 * A `UserRepository` double for the consumers of the subject lookup
 * (`findBySubject`): it holds users by `id`, records every subject it is
 * asked for, and can leave the capability out or stand for a Store that
 * cannot answer. It authenticates nobody. Published on
 * `@o3co/auth-provider-core/testing`.
 */
import type { User } from "../repositories/types.mjs";
import type { UserRepository } from "../repositories/UserRepository.mjs";
export interface TestUserRepositoryOptions {
    /** The users `findBySubject` answers, keyed by their `id`; two with one `id` are refused. */
    readonly users?: readonly User[];
    /** `false` leaves `findBySubject` out, a repository without the capability. Default `true`. */
    readonly subjectLookup?: boolean;
    /** Thrown by `findBySubject`: a Store that cannot answer. */
    readonly unavailable?: unknown;
}
export interface TestUserRepository extends UserRepository {
    /** Every subject `findBySubject` was asked for, in order. */
    readonly lookups: readonly string[];
}
/** A `UserRepository` double for tests of the subject lookup's consumers. */
export declare function createTestUserRepository(options?: TestUserRepositoryOptions): TestUserRepository;
//# sourceMappingURL=userRepository.d.mts.map