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
 * For a route whose caller is the client an access token was issued to: the
 * token must be one that client obtained for itself.
 */
import { decodeJwt } from "jose";
/**
 * The pins for an access token presented by the client it was issued to: its
 * `aud` must contain that client's id, and its `azp` must be that id.
 *
 * Nothing else on such a request names the client, so its id is read from the
 * token's own `azp` before verification. Core's verifier then checks both
 * pins against the signed payload, so the audience check runs and an `azp`
 * the signature does not cover never passes.
 *
 * An `azp` claim that is present but not a non-empty string names no client
 * the token can be bound to: it is pinned to an audience nothing matches, so
 * the verifier refuses it. `null` for a token with no `azp` claim, or one
 * that cannot be decoded: no client to pin to, which each route answers.
 */
export const ownAccessTokenPins = (token) => {
    let claims;
    try {
        claims = decodeJwt(token);
    }
    catch {
        // Not a decodable JWT: the verifier refuses it.
        return null;
    }
    if (!Object.hasOwn(claims, "azp"))
        return null;
    const { azp } = claims;
    return typeof azp === "string" && azp.length > 0
        ? { expectedAudience: azp, expectedAzp: azp }
        : { expectedAudience: [] };
};
