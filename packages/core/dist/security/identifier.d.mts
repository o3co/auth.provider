/**
 * What an identifier this server looks something up by must look like: a
 * `client_id`, a JWT `kid`, an assertion's `iss`.
 *
 * Each arrives in a request before anything vouches for it, and each is
 * handed to a store or a keystore a deployment may have written itself — one
 * that throws on input it cannot handle, which this server answers as that
 * store's outage (`503`). So the value is screened first, and one that fails
 * is refused as naming nothing, without a lookup. The same rule is held at
 * the other end — where a kid is configured or a client registered — so a
 * value this server hands out is always one it will look up again.
 *
 * - A string, not empty.
 * - At most {@link MAX_IDENTIFIER_LENGTH} characters.
 * - No control character: C0 (`U+0000`–`U+001F`), DEL (`U+007F`), C1
 *   (`U+0080`–`U+009F`). RFC 6749 Appendix A.1 makes `client_id` `*VSCHAR`,
 *   and none of these identifiers is text a person reads; the rule stops
 *   short of refusing all non-ASCII, which a registry may already hold.
 */
/**
 * The longest identifier this server looks up. No specification bounds a
 * `client_id`, a `kid` or an issuer; the ones this server meets are
 * operator-chosen names and `https` URLs, far shorter in practice. 256 is
 * past all of them, and small enough that a store is never handed an
 * unbounded, attacker-chosen value.
 */
export declare const MAX_IDENTIFIER_LENGTH = 256;
/** Whether `value` is a well-formed identifier (see the module comment). */
export declare function isWellFormedIdentifier(value: unknown): value is string;
/**
 * What is wrong with an identifier {@link isWellFormedIdentifier} refuses,
 * for a configuration error. Never the value itself: it may carry control
 * characters, which a terminal or a log viewer would act on.
 */
export declare function describeMalformedIdentifier(value: unknown): string;
//# sourceMappingURL=identifier.d.mts.map