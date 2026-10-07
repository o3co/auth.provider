/**
 * What the grant answers: `400 invalid_request` for a malformed request and for
 * every refused token, told apart by `error_description`, and the issued token's
 * response, which names its `issued_token_type`.
 */
import { type GrantHandlerResult, type Token } from "@o3co/auth-provider-core";
/**
 * `400 invalid_request`: RFC 8693 §2.2.2 makes it the code for a request that is
 * not valid and for a `subject_token` or `actor_token` that is invalid or
 * unacceptable for any reason. That covers malformed or repeated parameters,
 * mismatched `actor_token`/`actor_token_type`, a body `client_id` that is not the
 * authenticated client, a malformed `expires_in`, an unsupported token type (RFC
 * 6749 §5.2; `unsupported_token_type` is RFC 7009's, for revocation), and every
 * refused token: validator `null`, a subject token that does not name the
 * client, sender constraint, family, session, `may_act`, actor-chain depth,
 * expiry. `invalid_grant` is not open to this grant.
 *
 * One code covers all of these, so `error_description` tells a client which check
 * refused it and is part of the wire contract (the README names each). Quote
 * values with `'`: RFC 6749 §5.2 allows neither `"` nor `\`.
 *
 * Other answers keep their RFC codes: `invalid_target` for audience and resource
 * (including values of the wrong type, since both may repeat), `invalid_scope`,
 * `invalid_client`, `unauthorized_client`; a policy past a ceiling is core's
 * `policyOutOfBounds`, and an unavailable store is `503 temporarily_unavailable`.
 */
export declare function invalidRequest(errorDescription: string): GrantHandlerResult;
/**
 * Whether a stage refused the request, rather than answering its own output.
 * A stage's own output never carries `result`, which the type parameter holds.
 */
export declare const isRefusal: <T extends object & {
    readonly result?: never;
}>(outcome: T | GrantHandlerResult) => outcome is GrantHandlerResult;
/**
 * The issued token, as RFC 8693 §2.2.1 answers it, with `expires_in` the
 * seconds left of its lifetime when it is answered.
 */
export declare function tokenAnswer(accessToken: Token, expiresIn: number): GrantHandlerResult;
//# sourceMappingURL=answers.d.mts.map