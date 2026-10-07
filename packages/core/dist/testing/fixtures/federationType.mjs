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
 * A module that registers one federation type, so that a test boots the
 * `core.federations` entries of that type as a federation package's module
 * would, without the package: each enabled entry gets a provider named after
 * it and a redirect policy beside it.
 */
import { z } from "zod";
import { defineFederationType, defineModule, } from "../../modules/manifest/index.mjs";
/** Any entry: the keys a test writes beside core's are handed on as written. */
const AnyEntry = z.looseObject({});
/** The default provider for the entry `name`. */
function providerNamed(name) {
    return {
        name,
        scope: ["openid"],
        buildAuthorizationUrl: () => new URL(`https://${name}.idp.test/authorize`),
        exchangeCode: async () => ({
            issuer: `https://${name}.idp.test`,
            sub: "user-1",
            expiresAt: null,
        }),
    };
}
/**
 * The default redirect policy: it accepts every redirect and resolves the
 * callback to `/`. Core does not declare the policy's type, the package that
 * declares the `federationRedirectPolicies` kind does, so the shape is checked
 * against it only in a program that holds that package.
 */
const acceptingRedirectPolicy = () => ({
    validateRedirect: () => ({ ok: true, value: undefined }),
    resolveCallbackRedirect: () => ({ ok: true, value: "/" }),
});
/**
 * A module named `test-federation-type-<type>` that registers `type` under
 * `federationTypes`, with an entry schema that accepts any entry. For each
 * enabled `core.federations` entry naming `type`, boot registers the provider
 * `options.provider` answers and the redirect policy `options.redirectPolicy`
 * answers under the entry's name. By default the provider is named after the
 * entry, with scope `openid`, an authorization URL on
 * `https://<name>.idp.test` and a code exchange that answers one fixed
 * subject; the policy accepts every redirect and resolves the callback to `/`.
 * `type` is one kebab-case word.
 */
export function federationTypeForTests(type, options = {}) {
    const provider = options.provider ?? ((instance) => providerNamed(instance.name));
    const redirectPolicy = options.redirectPolicy ?? acceptingRedirectPolicy;
    return defineModule({
        name: `test-federation-type-${type}`,
        contributes: {
            federationTypes: {
                [type]: defineFederationType()({
                    entrySchema: AnyEntry,
                    factory: (_deps, instance) => provider(instance),
                    redirectPolicy: (_deps, instance) => redirectPolicy(instance),
                }),
            },
        },
    });
}
