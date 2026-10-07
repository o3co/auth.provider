/** The longest `kid` this server issues or looks up. */
export declare const MAX_KID_LENGTH = 256;
/**
 * Whether `kid` is a well-formed key id: a non-empty string of at most
 * {@link MAX_KID_LENGTH} characters with no control character.
 */
export declare const isWellFormedKid: (kid: unknown) => kid is string;
/**
 * Refuses, when a keystore is built, a configured kid `verifyJwt` would
 * refuse. `kids` names each by where it was configured (`kid`,
 * `previousKeys[0].kid`); the message names that place and what is wrong,
 * never the kid itself.
 */
export declare function assertWellFormedKids(owner: string, kids: ReadonlyArray<readonly [where: string, kid: unknown]>): void;
//# sourceMappingURL=kid.d.mts.map