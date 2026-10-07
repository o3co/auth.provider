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
 * refused, never minted from. The subject's `acr`, `amr` and `auth_time` are carried
 * only from a token this provider's own validator verified for the issuer minting;
 * the actor's never are.
 */
import { consoleLogger, formatObject, generateToken, LIVENESS_SID_CLAIM, } from "@o3co/auth-provider-core";
import { buildActClaim } from "./act.mjs";
import { invalidRequest } from "./answers.mjs";
import { snapshotAuthentication } from "./validatedSnapshot.mjs";
export async function issueAccessToken(deps, ctx, { defaultExpiresIn, maxExpiresIn }, { issuedAt, client, subjectValidated, subjectBindings, actorValidated, grantedScope, audienceForToken, requestedExpiresIn, issuedConfirmation, }) {
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
    const subjectExpiry = subjectValidated.claims.exp;
    if (typeof subjectExpiry === "number" && Number.isFinite(subjectExpiry)) {
        // `<= 0` includes a token expiring within this second: capping would mint a dead
        // token, so refuse instead.
        if (Math.floor(subjectExpiry - Math.floor(Date.now() / 1000)) <= 0) {
            return invalidRequest("subject_token has expired");
        }
        expiresIn = Math.min(expiresIn, Math.floor(subjectExpiry - issuedAt));
    }
    // A subject token without `exp` leaves the lifetime above standing: `exp` is a
    // property of the presented credential, and a validator returning none asserts a
    // credential with no expiry. The built-in validator never takes this path.
    const accessToken = await generateToken(formatObject({
        family_id: subjectBindings.familyId,
        // The subject's session as a liveness link only (core's
        // `grants/sessionClaims.mts`): the logout that ends the subject token ends this
        // one at introspection and userinfo, and nothing a `sid` authorises is reachable
        // with it. The actor's session is not carried.
        [LIVENESS_SID_CLAIM]: subjectBindings.sid,
        act,
        ...carriedAuthentication(subjectValidated, ctx.issuer, issuedAt),
    }), {
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
    });
    // The lifetime runs from the issuance instant, so what is left of it once the
    // token is signed is the answer's `expires_in` (RFC 6749 §5.1). One the
    // exchange used up is refused, and retryable, rather than answered expired.
    const answeredAt = Math.floor(Date.now() / 1000);
    const remaining = issuedAt + expiresIn - answeredAt;
    if (remaining <= 0) {
        (deps.logger ?? consoleLogger).warn({ clientId: client.clientId, expiresIn, elapsed: answeredAt - issuedAt }, "token_exchange_lifetime_elapsed");
        return {
            result: {
                status: 503,
                error: "temporarily_unavailable",
                errorDescription: "issued token lifetime elapsed during the exchange",
            },
        };
    }
    return { accessToken, expiresIn: remaining };
}
/**
 * The subject's `acr`, `amr` and `auth_time` the issued token carries: only
 * from an answer the built-in validator gave for a token verified against the
 * issuer minting, else none. `auth_time` is never later than the subject's own
 * `iat` nor than this issuance.
 */
function carriedAuthentication(subjectValidated, issuer, issuedAt) {
    const verified = snapshotAuthentication(subjectValidated);
    if (verified === undefined || issuer === undefined || verified.issuer !== issuer)
        return {};
    const { acr, amr, authTime, issuedAt: subjectIssuedAt } = verified;
    return {
        ...(acr !== undefined ? { acr } : {}),
        ...(amr !== undefined ? { amr: [...amr] } : {}),
        ...(authTime !== undefined
            ? { auth_time: Math.min(authTime, subjectIssuedAt ?? issuedAt, issuedAt) }
            : {}),
    };
}
