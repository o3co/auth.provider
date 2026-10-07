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
import { resolveCallbackRedirect, validateRedirect } from "./helpers.mjs";
/**
 * Default `FederationRedirectPolicy` factory that preserves v0.4.x
 * `validateRedirect` / `resolveCallbackRedirect` behavior bit-identically
 * by delegating to the same underlying helpers in `helpers.mts`.
 *
 * Provider configs (`GoogleProviderConfig`, `GithubProviderConfig`) include
 * the three required fields, so passing the full provider config is valid
 * via structural assignability.
 *
 * Per A5 §9.
 */
export function createFederationRedirectPolicy(config) {
    // Defensive snapshot: detach from caller's reference so post-construction
    // mutation of the supplied config (e.g. `config.sessionDomain = "evil.com"`
    // later) cannot retroactively change validateRedirect/resolveCallbackRedirect
    // behavior. Shallow freeze + spread suffices because the picked
    // RedirectConfig fields are primitive strings (no nested mutability).
    const frozenConfig = Object.freeze({ ...config });
    return Object.freeze({
        validateRedirect(url) {
            return validateRedirect(url, frozenConfig);
        },
        resolveCallbackRedirect(session) {
            return resolveCallbackRedirect(session, frozenConfig);
        },
    });
}
