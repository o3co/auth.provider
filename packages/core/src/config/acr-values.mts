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
 * What an `oauth.authorize.acrValues` key may be: an acr value a request can
 * name. `/authorize` reads `acr_values` as space-delimited RFC 6749 §3.3
 * scope-tokens (`readSpaceDelimitedParameter`), so a key is one only when it
 * is a scope-token (`isScopeToken`); any other key would be advertised in
 * `acr_values_supported` and never be asked for. A schema that declares the
 * table refuses a key with `checkAcrValueName`, so each says the same.
 */

import { isScopeToken } from "../federations/scope.mjs";

/**
 * Why an `oauth.authorize.acrValues` key can never be requested, naming the
 * path and the key as JSON, or `null` when it can.
 */
export function checkAcrValueName(name: string): string | null {
	if (isScopeToken(name)) return null;
	return `oauth.authorize.acrValues key ${JSON.stringify(name)} can never be requested: /authorize reads acr_values as space-delimited RFC 6749 §3.3 scope-tokens, so a key is one or more printable ASCII characters other than the space, " and \\`;
}
