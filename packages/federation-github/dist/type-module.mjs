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
 * The module that handles every `core.federations` entry of type `github`: it
 * contributes the type, and core dispatches each enabled entry of it here —
 * the provider and its redirect policy built from the entry, under the
 * entry's name.
 */
import { defineFederationType, defineModule, } from "@o3co/auth-provider-core";
import { createFederationRedirectPolicy } from "@o3co/auth-provider-session";
import { githubEntrySchema } from "./entry.mjs";
import { createNamedGithubProvider } from "./github.mjs";
/** The `type` a `core.federations.<name>` entry names to select this provider. */
export const GITHUB_FEDERATION_TYPE = "github";
/**
 * Contributes `federationTypes.github`. For each enabled entry of type
 * `github` core parses the entry's own keys with the type's strict, flat
 * schema (`entry.mts`) and calls the two factories with the entry's name, its
 * `callbackURL` and the parsed keys: the provider and its redirect policy.
 * The name is the `:name` route segment and the prefix of the identity handed
 * to the Store (`<name>:<id>`), so two entries are two GitHub clients. It
 * requires no dependency.
 */
export function githubFederationTypeModule(options = {}) {
    const upstreamFetch = options.fetch;
    return defineModule({
        name: "federation-github-type",
        contributes: {
            federationTypes: {
                [GITHUB_FEDERATION_TYPE]: defineFederationType()({
                    entrySchema: githubEntrySchema,
                    factory: (_deps, { name, callbackURL, entry }) => createNamedGithubProvider(name, {
                        ...entry,
                        callbackURL,
                        ...(upstreamFetch !== undefined ? { fetch: upstreamFetch } : {}),
                    }),
                    redirectPolicy: (_deps, { entry }) => createFederationRedirectPolicy(entry),
                }),
            },
        },
    });
}
