/**
 * The refresh-token binding rule, as the grants that mint a refresh token
 * read it: `bindConfidentialClientRefreshTokens` from core's
 * `tokenBindingSettings` slot, which core fills frozen from
 * `core.tokenBinding`. Read once, when a grant is built.
 *
 * Held here until core's token-binding settings carry a check of their own,
 * as `checkOAuthTokenSettings` does for the token settings; the grants then
 * call that and this file goes.
 */
/**
 * Whether a confidential client's refresh token is bound to the key or
 * certificate its request was bound with. Throws a `TypeError` naming the
 * slot and `grant` when the slot is not filled with a boolean rule: a deps
 * built without it, or with a value whose rule is not a boolean, fails at
 * composition, before any request.
 */
export declare function bindConfidentialClientRefreshTokensFrom(tokenBindingSettings: unknown, grant: string): boolean;
//# sourceMappingURL=tokenBindingRule.d.mts.map