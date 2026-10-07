/**
 * Whether a user's Store-published state says their email is verified (#297).
 *
 * `oauth.requireEmailVerified` turns this into a gate on token issuance for an
 * end-user subject. The verification *flow* stays where it belongs — the Store
 * issues the token, delivers it, and flips the state; this library only reads
 * the result and decides whether to issue.
 *
 * Accepts **exactly** `true`. Absence is not verification: a Store that does
 * not model the field has not verified anything, and a deployment that turned
 * the gate on is asking for a positive signal, not the absence of a negative
 * one. A truthy non-boolean is rejected for the same reason the claim filter
 * drops it — a Store is reached across an untyped boundary, and the string
 * `"false"` is truthy.
 */
export declare const isEmailVerified: (user: unknown) => boolean;
//# sourceMappingURL=emailVerifiedGate.d.mts.map