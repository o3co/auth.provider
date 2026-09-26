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
 * The response headers a token-binding outcome asks for (#530): a refusal
 * (an error carrying `responseHeaders`) or an accepted binding
 * (`TokenBinding.responseHeaders`). Only string-valued entries count — a
 * mechanism cannot smuggle a non-header through.
 */
export const responseHeadersOf = (source) => {
    if (typeof source !== "object" || source === null || !("responseHeaders" in source))
        return {};
    const headers = source.responseHeaders;
    if (typeof headers !== "object" || headers === null)
        return {};
    return Object.fromEntries(Object.entries(headers).filter((entry) => typeof entry[1] === "string"));
};
/** Set every header {@link responseHeadersOf} finds on `source`. */
export const applyResponseHeaders = (res, source) => {
    for (const [name, value] of Object.entries(responseHeadersOf(source))) {
        res.setHeader(name, value);
    }
};
/** An OAuth error code: snake_case, so an infrastructure code (`ECONNREFUSED`) never reaches the wire. */
const OAUTH_ERROR_CODE_PATTERN = /^[a-z][a-z0-9_]*$/;
/** The OAuth error `code` a thrown refusal carries, or `undefined`. */
export const oauthErrorCodeOf = (err) => {
    const code = typeof err === "object" && err !== null ? err.code : undefined;
    return typeof code === "string" && OAUTH_ERROR_CODE_PATTERN.test(code) ? code : undefined;
};
/**
 * The retry instruction a refusal states (`TokenBindingRefusal.retryInstruction`),
 * or `undefined` for a verdict. Only a non-empty string beside an OAuth code
 * counts: an instruction with no code to answer under is not one.
 */
export const retryInstructionOf = (err) => {
    if (oauthErrorCodeOf(err) === undefined)
        return undefined;
    const instruction = err.retryInstruction;
    return typeof instruction === "string" && instruction.length > 0 ? instruction : undefined;
};
