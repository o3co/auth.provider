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
import { createAdapterFactory } from "@o3co/auth-provider-core";
import { createGithubProvider } from "./github.mjs";
import { createGoogleProvider } from "./google.mjs";
export function createFederationProviderFactory() {
    return createAdapterFactory("FederationProvider");
}
/**
 * Narrows a raw Record<string, unknown> builder config to the typed fields
 * required by all built-in federation providers. Throws with a provider-specific
 * label if any required field is absent or has the wrong type.
 *
 * Not exported — internal to this module only.
 */
function narrowFederationConfig(config, providerLabel) {
    const name = typeof config.name === "string" ? config.name : undefined;
    const clientId = typeof config.clientId === "string" ? config.clientId : undefined;
    const clientSecret = typeof config.clientSecret === "string" ? config.clientSecret : undefined;
    const callbackURL = typeof config.callbackURL === "string" ? config.callbackURL : undefined;
    if (!name || !clientId || !clientSecret || !callbackURL) {
        throw new Error(`${providerLabel} federation requires name, clientId, clientSecret, and callbackURL`);
    }
    const sessionDomain = typeof config.sessionDomain === "string" ? config.sessionDomain : undefined;
    const authCallbackUrl = typeof config.authCallbackUrl === "string" ? config.authCallbackUrl : undefined;
    const clientUrl = typeof config.clientUrl === "string" ? config.clientUrl : undefined;
    const endSessionEndpoint = typeof config.endSessionEndpoint === "string" ? config.endSessionEndpoint : undefined;
    return {
        name,
        clientId,
        clientSecret,
        callbackURL,
        sessionDomain,
        authCallbackUrl,
        clientUrl,
        endSessionEndpoint,
    };
}
export function registerBuiltinFederations(factory) {
    factory.register("google", async (config) => {
        const narrowed = narrowFederationConfig(config, "Google");
        return createGoogleProvider(narrowed);
    });
    factory.register("github", async (config) => {
        const narrowed = narrowFederationConfig(config, "GitHub");
        return createGithubProvider(narrowed);
    });
}
