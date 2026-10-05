/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * What the grant answers: `400 invalid_request` for a malformed request and for
 * every refused token, told apart by `error_description`, and the issued token's
 * response, which names its `issued_token_type`.
 */

import {
	type GrantHandlerResult,
	generateTokenResponse,
	type Token,
} from "@o3co/auth-provider-core";
import { ACCESS_TOKEN_TYPE } from "./validator/selfIssuedAccessToken.mjs";

/**
 * `400 invalid_request`: RFC 8693 §2.2.2 makes it the code for a request that is
 * not valid and for a `subject_token` or `actor_token` that is invalid or
 * unacceptable for any reason. That covers malformed or repeated parameters,
 * mismatched `actor_token`/`actor_token_type`, a body `client_id` that is not the
 * authenticated client, a malformed `expires_in`, an unsupported token type (RFC
 * 6749 §5.2; `unsupported_token_type` is RFC 7009's, for revocation), and every
 * refused token: validator `null`, sender constraint, family, session,
 * `may_act`, actor-chain depth, expiry. `invalid_grant` is not open to this grant.
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
export function invalidRequest(errorDescription: string): GrantHandlerResult {
	return { result: { status: 400, error: "invalid_request", errorDescription } };
}

/**
 * Whether a stage refused the request, rather than answering its own output.
 * A stage's own output never carries `result`, which the type parameter holds.
 */
export const isRefusal = <T extends object & { readonly result?: never }>(
	outcome: T | GrantHandlerResult,
): outcome is GrantHandlerResult => "result" in outcome;

/**
 * The issued token, as RFC 8693 §2.2.1 answers it, with `expires_in` the
 * seconds left of its lifetime when it is answered.
 */
export function tokenAnswer(accessToken: Token, expiresIn: number): GrantHandlerResult {
	// RFC 9449 §5: a DPoP-bound token is `token_type: "DPoP"`; mTLS keeps "Bearer"
	// (RFC 8705 §3). Read off the stamped confirmation, so the two cannot disagree.
	const tokens = generateTokenResponse({ accessToken: { ...accessToken, expiresIn } });
	const tokensWithIssuedType: typeof tokens & { issued_token_type: string } = {
		...tokens,
		issued_token_type: ACCESS_TOKEN_TYPE,
	};

	return {
		result: {
			status: 200,
			tokens: tokensWithIssuedType,
		},
	};
}
