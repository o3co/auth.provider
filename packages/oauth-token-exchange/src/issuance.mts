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
 * The token mint: the issued access token's `act`, scope, audience and binding, and
 * its lifetime, the requested or the default one clamped to the maximum and never
 * past the subject token's own expiry. A subject token that has already expired is
 * refused, never minted from.
 */

import {
	type AccessTokenLifetime,
	type Confirmation,
	consoleLogger,
	formatObject,
	type GrantContext,
	type GrantDependencies,
	type GrantHandlerResult,
	generateToken,
	LIVENESS_SID_CLAIM,
	type PublicClient,
	type Token,
	type ValidatedToken,
} from "@o3co/auth-provider-core";
import { buildActClaim } from "./act.mjs";
import { invalidRequest } from "./answers.mjs";
import type { ReportedBindings } from "./tokenValidation.mjs";

/** What the issued token is minted from. */
export interface Issuance {
	/** The issuance instant, epoch seconds: the minted `iat`, and what `exp` is measured from. */
	readonly issuedAt: number;
	readonly client: PublicClient;
	readonly subjectValidated: ValidatedToken;
	/** The subject's family and session, as read once at validation. */
	readonly subjectBindings: ReportedBindings;
	readonly actorValidated: ValidatedToken | null;
	readonly grantedScope: readonly string[] | undefined;
	readonly audienceForToken: string;
	readonly requestedExpiresIn: number | undefined;
	readonly issuedConfirmation: Confirmation | undefined;
}

export async function issueAccessToken(
	deps: Pick<GrantDependencies, "keyStore" | "logger">,
	ctx: GrantContext,
	{ defaultExpiresIn, maxExpiresIn }: AccessTokenLifetime,
	{
		issuedAt,
		client,
		subjectValidated,
		subjectBindings,
		actorValidated,
		grantedScope,
		audienceForToken,
		requestedExpiresIn,
		issuedConfirmation,
	}: Issuance,
): Promise<{ readonly accessToken: Token } | GrantHandlerResult> {
	const act = buildActClaim({
		subject: subjectValidated,
		actor: actorValidated ?? undefined,
	});
	const scopeClaim = grantedScope && grantedScope.length > 0 ? grantedScope.join(" ") : null;

	// The issued lifetime: the requested `expires_in` or
	// `oauth.accessToken.defaultExpiresIn`, clamped (not refused) to `maxExpiresIn`,
	// then capped at the subject token's remaining lifetime below. An unset max
	// equals the default. The max also bounds how long a resource server validating
	// offline keeps accepting this token after its family is revoked.
	let expiresIn = Math.min(requestedExpiresIn ?? defaultExpiresIn, maxExpiresIn);

	// RFC 8693 §2.2.1: the issued token SHOULD NOT outlive the subject token, or a
	// chain of exchanges outlives its origin indefinitely. The built-in validator
	// already rejects an expired subject, so this is the fail-closed backstop for
	// contributed validators, placed here so the refusal order of a doubly invalid
	// request is unchanged. The cap is measured from the issuance instant the minted
	// `iat`/`exp` carry, so `exp` cannot pass the subject's; the expiry is judged
	// at the minting clock, so a subject that expired while the exchange ran is
	// refused.
	const mintedAt = Math.floor(Date.now() / 1000);
	const subjectExpiry = subjectValidated.claims.exp;
	if (typeof subjectExpiry === "number" && Number.isFinite(subjectExpiry)) {
		// `<= 0` includes a token expiring within this second: capping would mint a dead
		// token, so refuse instead.
		if (Math.floor(subjectExpiry - mintedAt) <= 0) {
			return invalidRequest("subject_token has expired");
		}
		expiresIn = Math.min(expiresIn, Math.floor(subjectExpiry - issuedAt));
	}
	// The lifetime runs from the issuance instant: one the exchange itself has
	// used up would be minted already expired, so it is refused, and retryable.
	if (issuedAt + expiresIn <= mintedAt) {
		(deps.logger ?? consoleLogger).warn(
			{ clientId: client.clientId, expiresIn, elapsed: mintedAt - issuedAt },
			"token_exchange_lifetime_elapsed",
		);
		return {
			result: {
				status: 503,
				error: "temporarily_unavailable",
				errorDescription: "issued token lifetime elapsed during the exchange",
			},
		};
	}
	// A subject token without `exp` leaves the lifetime above standing: `exp` is a
	// property of the presented credential, and a validator returning none asserts a
	// credential with no expiry. The built-in validator never takes this path.

	const accessToken = await generateToken(
		formatObject({
			family_id: subjectBindings.familyId,
			// The subject's session as a liveness link only (core's
			// `grants/sessionClaims.mts`): the logout that ends the subject token ends this
			// one at introspection and userinfo, and nothing a `sid` authorises is reachable
			// with it. The actor's session is not carried.
			[LIVENESS_SID_CLAIM]: subjectBindings.sid,
			act,
		}),
		{
			expiresIn,
			issuedAt,
			keyStore: deps.keyStore,
			issuer: ctx.issuer,
			audience: audienceForToken,
			subject: subjectValidated.sub,
			authorizedParty: client.clientId,
			scope: scopeClaim,
			tokenType: "at+jwt",
			...(issuedConfirmation ? { confirmation: issuedConfirmation } : {}),
		},
	);
	return { accessToken };
}
