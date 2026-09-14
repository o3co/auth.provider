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
 */
import { decodeJwt } from "jose";
import { parseAccessTokenAuthorization } from "../accessTokenHeader.mjs";
import { errorEnvelope } from "../errors/envelope.mjs";
import { BINDING_PROFILES, matchConfirmation } from "../grants/confirmationMatch.mjs";
import "./express.mjs"; // ensure ambient Express.Request augmentation is loaded
export const protectedResourceBindingMw = ({ mechanisms, logger, }) => {
    return async (req, res, next) => {
        // Anything that is not an access-token scheme belongs to another
        // authentication surface — `Basic` client auth on the introspection
        // endpoint is the case that actually occurs — and is not ours to judge.
        const authorization = parseAccessTokenAuthorization(req.headers.authorization);
        if (authorization === null) {
            next();
            return;
        }
        const { scheme, token: accessToken } = authorization;
        // Claims are read WITHOUT verifying the signature; the endpoint
        // downstream still runs the full `verifyJwt`. That is sound because the
        // two reads cannot disagree — `decodeJwt` is the same primitive
        // `jwt/verify.mts` uses, over the same bytes — so a token whose `cnf`
        // is enforced here is the same token whose signature is checked there.
        // A token that fails to decode is left to the endpoint to reject, which
        // keeps the "invalid token" response in one place.
        let claims;
        try {
            claims = decodeJwt(accessToken);
        }
        catch {
            next();
            return;
        }
        // Classify the token's `cnf` before any mechanism runs: `binding` is
        // still unresolved here, so the match can only be `unbound`,
        // `compound`, or `no-proof` — the latter meaning "bound by `member`,
        // proof still to be collected below".
        const match = matchConfirmation(claims.cnf, null);
        if (match.status === "unbound") {
            // Unbound token (or a junk `cnf` that names no binding). Nothing to
            // enforce — an unbound token was never sender-constrained, and the
            // endpoint's own authorization checks still apply.
            next();
            return;
        }
        const reject = (reason, challenge, description) => {
            logger?.warn({ reason, scheme, site: "protected_resource_binding" }, "sender_constraint_rejected");
            res.setHeader("WWW-Authenticate", `${challenge} error="invalid_token"`);
            // RFC 6750 §3.1 gives one code for every token-level failure. The
            // granular reason goes to the audit log above and never to the
            // caller: telling an attacker holding a stolen bound token whether
            // they got the scheme, the proof, or the key wrong hands them a
            // tuning oracle.
            res.status(401).json(errorEnvelope("invalid_token", description));
        };
        if (match.status === "compound") {
            // This AS mints exactly one mechanism's confirmation per token, so a
            // compound `cnf` means a forged token or an AS bug. Refuse rather
            // than pick a winner — the same call `grants/refreshToken.mts` and
            // the introspection handler already make.
            reject("compound_cnf", "Bearer", "access token carries an ambiguous compound cnf binding");
            return;
        }
        const { member } = match;
        const profile = BINDING_PROFILES[member];
        if (scheme !== profile.scheme) {
            // The #264 replay: a DPoP-bound token handed over as `Bearer`.
            reject("scheme_mismatch", profile.challenge, `a token bound by ${member} must be presented using the ${profile.challenge} scheme`);
            return;
        }
        const owning = mechanisms.filter((mechanism) => mechanism.kind === profile.kind);
        let binding = null;
        for (const mechanism of owning) {
            let candidate;
            try {
                candidate = await mechanism.extract(req, { boundAccessToken: accessToken });
            }
            catch (err) {
                logger?.warn({ mechanism: mechanism.kind, err }, "protected_resource_binding_proof_invalid");
                reject("proof_invalid", profile.challenge, "presented proof-of-possession is invalid");
                return;
            }
            if (candidate !== null && matchConfirmation(claims.cnf, candidate).status === "satisfied") {
                binding = candidate;
                break;
            }
        }
        if (binding === null) {
            // Covers all three ways the proof can fail to arrive: the mechanism
            // is not installed (a deployment that dropped the module while bound
            // tokens are still live), no material was presented, or the material
            // proved possession of a different key or certificate. Each is a
            // stolen-token replay from the resource's point of view. (For why
            // the thumbprint comparison is a plain `!==`, see
            // `grants/confirmationMatch.mts`.)
            reject("no_matching_binding", profile.challenge, "access token is sender-constrained and no matching proof-of-possession was presented");
            return;
        }
        req.tokenBinding = binding;
        next();
    };
};
