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
import { resolvePkceOptions } from "./grants/pkce.mjs";
/**
 * Resolves every `oauth.*` knob the OAuth routers and grants consume into one
 * plain typed options object, at composition time.
 *
 * Replaces the per-site `config as { oauth?: ... }` casts that had spread
 * through `routes.mts` and `grants/session.mts`: each new knob re-implemented
 * the "tolerate a hand-built config that bypassed the schema" defensive read,
 * at inconsistent altitude (router construction vs per request). Values pass
 * through untouched — no coercion, no validation — so a config that lies about
 * its types behaves exactly as it did against the inline casts. Defaults:
 *
 * - boolean opt-ins (`requireEmailVerified`, `resourceIndicator.enabled`)
 *   enable only on literal `true` — the safe reading of an absent value is
 *   `false` (enforce/off);
 * - `oidcMode` falls back to `"oidc-required"`;
 * - `nonce.maxLength` falls back to `256`;
 * - `legacyTypAccept` stays `undefined` when absent (consumers default it);
 * - `pkce` is fixed policy, not a knob (#273): `resolvePkceOptions` returns
 *   required + S256-only whatever the config says, and warns about the keys
 *   that no longer do anything.
 *
 * The optional `logger` receives the `resolvePkceOptions` inert-config
 * warning. Resolution runs once at composition, so an operator sees one
 * boot-time warning instead of one per `/authorize` request.
 */
export const resolveOAuthOptions = (config, logger) => {
    const oauth = config?.oauth;
    // #273: read the pkce block only to report what is now inert in it.
    // `oauth.grants` is `z.object({}).passthrough()` in the schema, so even a
    // schema-validated tree is untyped from here down.
    const authorizationConfig = oauth?.grants?.authorization_code;
    const pkceConfig = authorizationConfig?.pkce;
    return {
        issuer: oauth?.jwt?.issuer,
        legacyTypAccept: oauth?.jwt?.legacyTypAccept,
        oidcMode: oauth?.oidcMode ?? "oidc-required",
        requireEmailVerified: oauth?.requireEmailVerified === true,
        pkce: resolvePkceOptions(pkceConfig, logger),
        nonceMaxLength: oauth?.nonce?.maxLength ?? 256,
        resourceIndicatorEnabled: oauth?.resourceIndicator?.enabled === true,
    };
};
