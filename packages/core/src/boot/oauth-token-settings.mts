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
 * What boot's own machinery reads of the oauth module's settings: the issuer
 * the discovery document, the CORS table and a session requirement's page are
 * built on. The token-binding dispatch policy is core's; boot reads it from
 * the configuration with `resolveTokenBindingSettings`.
 *
 * The issuer is the `oauthTokenSettings` slot's when the composition holds it
 * — the key is present, whatever a provider answered — otherwise the
 * configuration's, since core runs in compositions without the oauth module. The stage-1
 * checks read the configuration alone because no provider has run by then
 * (`validate-manifests.mts`, the `grantPolicy` issuer check).
 */

import { checkOAuthTokenSettings } from "../token-settings/check.mjs";

/** The component map as boot holds it. */
type Components = Readonly<Record<string, unknown>>;

/**
 * The issuer: the slot's when the composition holds it — read whole, held
 * first to what its readers read (`checkOAuthTokenSettings`), so a slot
 * without a canonical issuer refuses rather than the configuration's being
 * read beside it — else `oauth.jwt.issuer` as the configuration carries it,
 * unvalidated, for each reader to hold to its own rule. The slot is held
 * to the lifetimes core resolves from the configuration as well: this is
 * where boot bounds a module's slot by them, so a reader holding the slot
 * alone need not.
 */
export function compositionIssuer(components: Components): unknown {
	if (Object.hasOwn(components, "oauthTokenSettings")) {
		return checkOAuthTokenSettings(components.oauthTokenSettings, components.config).issuer;
	}
	return (components.config as { oauth?: { jwt?: { issuer?: unknown } } } | undefined)?.oauth?.jwt
		?.issuer;
}
