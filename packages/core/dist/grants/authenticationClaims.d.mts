/**
 * The authentication claims a token may carry (#481): `amr` (RFC 8176) and
 * `acr` (OIDC Core §2), read in one shape by every grant that stamps them.
 *
 * They reach a token from a recorded `UserSession` (a password login, a
 * federation login recording the upstream IdP's `amr` as it arrived), from the
 * code record, or from a refresh token a previous grant minted. A refresh does
 * not repeat the authentication, so the claims are copied forward — and a claim
 * copied forward is a claim vouched for again. One predicate is what keeps a
 * grant from stamping an `amr: []` that the next grant drops, so a resource
 * server gating on `amr` sees one answer for one authentication.
 */
/** `amr` as a token may carry it — a non-empty array of non-empty strings, copied — else undefined. */
export declare function wellFormedAmr(value: unknown): readonly string[] | undefined;
/** `acr` as a token may carry it — a non-empty string — else undefined. */
export declare function wellFormedAcr(value: unknown): string | undefined;
//# sourceMappingURL=authenticationClaims.d.mts.map