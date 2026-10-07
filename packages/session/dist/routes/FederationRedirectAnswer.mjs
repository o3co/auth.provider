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
import { refusalEnvelope } from "../internal/refusalEnvelope.mjs";
import { logMisconfigured } from "./FederationLog.mjs";
/**
 * A provider with no redirect policy: a composition fault, `500
 * internal_error`, logged once as `federation_misconfigured` with `context`.
 */
export const answerNoRedirectPolicy = (res, log, context = {}) => {
    logMisconfigured(log, "no_redirect_policy", context);
    res.status(500).json({
        error: "internal_error",
        error_description: "redirect policy not registered for provider",
    });
};
/**
 * Answer with the provider's policy's redirect. A provider with no policy is
 * a composition fault, `500`; a policy's refusal is answered in its words,
 * held to RFC 6749's characters (`refusalEnvelope`).
 */
export const redirectAfterCallback = (ctx, provider, redirectTo, res, log) => {
    const policy = ctx.federationRedirectPolicyResolver.get(provider.name);
    if (!policy) {
        answerNoRedirectPolicy(res, log);
        return;
    }
    const redirect = policy.resolveCallbackRedirect({ redirectTo });
    if (!redirect.ok) {
        res.status(redirect.status).json(refusalEnvelope(redirect, log));
        return;
    }
    res.redirect(redirect.value);
};
