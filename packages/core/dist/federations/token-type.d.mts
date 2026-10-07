/**
 * The one type an upstream access token may be handed on as, spelled as RFC
 * 6750 §2.1 spells the scheme. RFC 6749 §5.1 makes the comparison
 * case-insensitive ("Value is case insensitive", said there and in §4.2.2;
 * §7.1 is what defines the types themselves), so this is the spelling to
 * WRITE, never the one to test against — {@link isBearerTokenType} is that.
 */
export declare const BEARER_TOKEN_TYPE = "Bearer";
/**
 * The stored form of an upstream `token_type`: the name the upstream gave, or
 * `undefined` when what it gave is not a token type at all (RFC 6749 §A.13,
 * {@link isTokenType}).
 *
 * This is what separates an adapter answering something BROKEN from an
 * upstream answering a real type this provider may not hand on — the two
 * refusals `POST /oauth/federation/:name/token` gives on a refresh. It has to
 * be the grammar and not a looser bound, or garbage such as `"Bearer^"` is
 * read as a type name and answered as if the upstream had meant it.
 *
 * Nothing is trimmed or re-cased. The spelling is the upstream's, and
 * {@link isBearerTokenType} is what reads it.
 */
export declare function canonicalTokenType(value: unknown): string | undefined;
/**
 * Whether a named token type is `Bearer`, however the upstream spelled it
 * (RFC 6749 §5.1; oauth4webapi lower-cases what it was sent).
 *
 * This is the question a route asks before handing an upstream's access token
 * to somebody else, and the answer is no for every other name in IANA's Access
 * Token Types registry. `PoP` (RFC 9200) and `DPoP` (RFC 9449) are
 * sender-constrained: presenting one takes a proof of possession of a key, and
 * the recipient of a token delegated by value does not hold that key — the
 * provider cannot present it on their behalf either, so there is no reading
 * under which such a token is usable once it has been handed on. `N_A` (RFC
 * 8693 §2.2.1) is not sender-constrained but is not an access token type at
 * all: it is Token Exchange's marker for "no type applies", and there is
 * nothing to present. Answering any of them as `Bearer` would be worse than
 * refusing: it drops a constraint the upstream imposed, or invents one that
 * was never issued, and hands out a credential that only looks usable.
 *
 * A type nobody named is not judged here. RFC 6749 §5.1 makes `token_type`
 * REQUIRED, so an answer that omits it comes from an adapter written before
 * the field rather than from an upstream meaning "not bearer" — but that
 * reading belongs to the caller that knows which of the two it is holding, and
 * is stated where it is made rather than hidden in this predicate.
 */
export declare function isBearerTokenType(named: unknown): named is string;
//# sourceMappingURL=token-type.d.mts.map