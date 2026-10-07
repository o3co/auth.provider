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
 * What every `/authorize` stage reads: the handler's options, the request's
 * parameters and its GET URL on the issuer's origin, and the per-request
 * context, which exists only once `redirect_uri` is validated.
 */
import { buildCanonicalRequestUrl, readSpaceDelimitedParameter, } from "@o3co/auth-provider-core";
export const toStr = (v) => (typeof v === "string" ? v : undefined);
/**
 * The authorization request's parameters: a POST's form body or a GET's
 * query (OIDC Core §3.1.2.1 requires both methods). Read in one place so no
 * check silently applies to GET alone.
 */
export const authorizeParams = (req) => req.method === "POST"
    ? (req.body ?? {})
    : req.query;
/**
 * This authorization request as a GET URL on the issuer's origin, with a
 * POST's form parameters written as the query: what the consent, login and
 * step-up pages return to, and what an ask is bound to. Not
 * `req.originalUrl`: a POST's URL alone names no client, `redirect_uri` or
 * PKCE.
 */
export const authorizeRequestUrl = (issuerOrigin, req) => {
    const url = new URL(buildCanonicalRequestUrl(issuerOrigin, req.originalUrl));
    url.search = "";
    for (const [name, value] of Object.entries(authorizeParams(req))) {
        if (typeof value === "string") {
            url.searchParams.append(name, value);
        }
        else if (Array.isArray(value)) {
            for (const item of value) {
                if (typeof item === "string")
                    url.searchParams.append(name, item);
            }
        }
    }
    return url;
};
/**
 * `url` less `prompt=consent`, which the consent round trip answers — carried
 * back, it would park the request again forever. Other prompt values stay,
 * read as `resolvePrompt` reads them; a malformed `prompt` was refused there
 * and is left as it is. The request the consent step resumes, and the one a
 * re-authentication ask is bound to, so the two agree.
 */
export const withoutConsentPrompt = (url) => {
    const out = new URL(url);
    const prompt = out.searchParams.get("prompt");
    const prompts = prompt === null ? null : readSpaceDelimitedParameter(prompt);
    if (prompts === null)
        return out;
    const remaining = prompts.filter((value) => value !== "consent");
    if (remaining.length === 0) {
        out.searchParams.delete("prompt");
    }
    else {
        out.searchParams.set("prompt", remaining.join(" "));
    }
    return out;
};
