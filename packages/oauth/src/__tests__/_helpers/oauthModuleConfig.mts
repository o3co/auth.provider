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
 * Core's application fixture for a composition that loads the oauth module:
 * core's fixture carries only the keys of `oauth {}` core reads, and refuses
 * any other where the module is not loaded, so the module's own required key,
 * `oidcMode`, is added here, at `config/reference.conf`'s default.
 */

import { makeValidAppConfig } from "@o3co/auth-provider-core/testing";

export function appConfigWithOAuthModule() {
	const config = makeValidAppConfig();
	return { ...config, oauth: { ...config.oauth, oidcMode: "oidc-required" as const } };
}
