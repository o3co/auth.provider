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
import { randomUUID } from "node:crypto";
export const formatObject = (data) => {
    return Object.fromEntries(Object.entries(data).filter(([, v]) => v !== undefined && v !== null));
};
export const generateTokenResponse = ({ accessToken, refreshToken = undefined, idToken = undefined, }) => {
    return {
        access_token: accessToken.token,
        token_type: "Bearer",
        ...formatObject({
            scope: accessToken.scope,
            refresh_token: refreshToken ? refreshToken.token : null,
            expires_in: accessToken.expiresIn,
            id_token: idToken ? idToken.token : undefined,
        }),
    };
};
export const generateToken = async (data, { expiresIn = undefined, keyStore, issuer = null, audience = null, subject = null, authorizedParty = null, scope = null, tokenType = undefined, }) => {
    const now = Math.floor(Date.now() / 1000);
    const claims = {
        ...data,
        ...(authorizedParty ? { azp: authorizedParty } : {}),
        ...(scope ? { scope } : {}),
        iat: now,
        jti: randomUUID(),
        ...(expiresIn !== undefined ? { exp: now + expiresIn } : {}),
        ...(issuer != null ? { iss: issuer } : {}),
        ...(audience != null ? { aud: audience } : {}),
        ...(subject != null ? { sub: subject } : {}),
    };
    const token = await keyStore.sign({
        claims,
        ...(tokenType ? { header: { typ: tokenType } } : {}),
    });
    const result = { token };
    if (expiresIn !== undefined)
        result.expiresIn = expiresIn;
    if (audience !== null && audience !== undefined)
        result.audience = audience;
    if (issuer !== null && issuer !== undefined)
        result.issuer = issuer;
    if (subject !== null && subject !== undefined)
        result.subject = subject;
    if (scope !== null && scope !== undefined)
        result.scope = scope;
    if (tokenType !== undefined)
        result.tokenType = tokenType;
    return result;
};
