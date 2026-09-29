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
 * What boot's own machinery reads of the oauth module's settings (#728): the
 * issuer the discovery document, the CORS table and a session requirement's
 * page are built on. The token-binding dispatch policy is not among them: it
 * is core's, and boot reads it from the configuration with
 * `resolveTokenBindingDispatchPolicy`, whatever the composition holds.
 *
 * The issuer is the `oauthTokenSettings` slot's when the composition holds
 * it — the oauth module provides the slot eagerly, so it is there whenever
 * that module is installed — and otherwise read from the configuration core's
 * schema parsed, as before: core runs in compositions without the oauth
 * module. The stage-1 checks read the configuration alone, since no provider
 * has run by then (`validate-manifests.mts`, the `grantPolicy` issuer check).
 */

import type { OAuthTokenSettings } from "../token-settings/types.mjs";

/** The component map as boot holds it. */
type Components = Readonly<Record<string, unknown>>;

const tokenSettingsOf = (components: Components): OAuthTokenSettings | undefined =>
	components.oauthTokenSettings as OAuthTokenSettings | undefined;

/**
 * The issuer: the slot's — canonical, as its contract holds it — else
 * `oauth.jwt.issuer` as the configuration carries it, unvalidated, for each
 * reader to hold to its own rule as it always has.
 */
export function compositionIssuer(components: Components): unknown {
	const fromSlot = tokenSettingsOf(components)?.issuer;
	if (fromSlot !== undefined) return fromSlot;
	return (components.config as { oauth?: { jwt?: { issuer?: unknown } } } | undefined)?.oauth?.jwt
		?.issuer;
}
