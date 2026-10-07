import type { SessionEnrollmentFacts } from "../user-sessions/types.mjs";
import type { CompletedRequirement, PrimaryAdditions, PrimaryAdditionsDto, PrimaryAuthentication, PrimaryAuthenticationDto, PrimaryContinuation, RegisteredRequirement } from "./requirement.mjs";
/**
 * What a session records of its login's `user` for a first binding: the
 * witness as `readMfaEnrollmentWitness` reads it, and what its `email` is
 * (`mailAddressFactOf`) — never the address. Frozen.
 */
export declare function enrollmentFactsOf(user: Readonly<Record<string, unknown>>): SessionEnrollmentFacts;
/**
 * `value` as a `PrimaryAuthentication` core's builders make: `recorded` has
 * a non-empty `amr`, no `mfaAt`, and no second-factor value beside a
 * password primary; `user` is read into its snapshot (`userSnapshot`) and
 * `claims` read by `readLoginClaims` (`copyClaims`). A frozen deep copy, its `enrollmentFacts`
 * derived from the snapshot.
 */
export declare function checkPrimaryAuthentication(value: unknown): PrimaryAuthentication;
/** A primary rehydrated from its DTO: `authTime` a `Date` at `authTimeMs`, `enrollmentFacts` derived from its `user`. Frozen. */
export declare function primaryFromDto(dto: PrimaryAuthenticationDto): PrimaryAuthentication;
/**
 * The enrollment facts of the login `continuation` carries, derived from its
 * `user` exactly as its rehydration derives them: for the requirement that
 * holds it and decides a first binding before resuming the login. Facts the
 * continuation carries are not read. A continuation `checkPrimaryContinuation`
 * cannot read is a `RangeError`, as it is for `resumePrimary`.
 */
export declare function enrollmentFactsOfContinuation(continuation: PrimaryContinuation): SessionEnrollmentFacts;
/** The completing requirement as registered: its name and its declaration, read once. */
export type CompletingRequirement = Pick<RegisteredRequirement, "name" | "secondFactorAuthority">;
/**
 * What `requirement` may add as it completes: an `amr` of non-empty strings,
 * none a primary's marker, `mfa` never alone; `mfaAt` never beside an empty
 * `amr`. A second factor from the second-factor authority alone, and from it
 * a verified one (`checkSecondFactor`). A frozen copy.
 */
export declare function checkPrimaryAdditions(requirement: CompletingRequirement, value: unknown): PrimaryAdditions;
/** Additions rehydrated from their DTO: `mfaAt` a `Date` at `mfaAtMs`. Frozen. */
export declare function additionsFromDto(dto: PrimaryAdditionsDto): PrimaryAdditions;
/**
 * `value` as a `PrimaryContinuation`: a primary DTO and `done`, the
 * completed requirements with what each added — a second factor a verified
 * one, added by one entry at most — no name twice, every instant epoch
 * milliseconds. A frozen deep copy: what a requirement's record holds and
 * what `resumePrimary` reads back. Which requirement declares the
 * second-factor authority it does not know: `resumePrimary` checks that.
 */
export declare function checkPrimaryContinuation(value: unknown): PrimaryContinuation;
/**
 * The continuation admission answers an interruption with: the primary as
 * the route built it — without its `enrollmentFacts`, which a rehydration
 * derives again — and every completed requirement's additions, as the
 * serialisable DTO. Frozen.
 */
export declare function continuationOf(primary: PrimaryAuthentication, done: readonly CompletedRequirement[], interruptedBy: string): PrimaryContinuation;
//# sourceMappingURL=primary.d.mts.map