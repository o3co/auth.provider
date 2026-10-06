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
 * The module that keeps a subject's MFA factors in the Store:
 * `foundation-mfa-factor-store` provides `mfaFactorStore` as an
 * `HttpMfaFactorStore`, built at boot whether or not anything requires it.
 *
 * Guarantees: the section's four URLs are read first, so a composition that
 * installs the module with any of them unset refuses the boot; the Store's
 * credential, deadline and response cap are the Store transport settings the
 * composition root must hand it — the user repository's HTTP settings, read
 * as that repository's builder reads them — so one token goes to every Store
 * endpoint, and settings absent or not a section of keys refuse the boot
 * rather than send no credential. It requires no slot.
 */

import { defineModule, type Module } from "@o3co/auth-provider-core";
import { readStoreTransportConfig } from "../storeTransport.mjs";
import { HttpMfaFactorStore } from "./HttpMfaFactorStore.mjs";
import {
	foundationMfaFactorStoreLifecycle,
	foundationMfaFactorStoreSection,
	readFoundationMfaFactorStoreUrls,
} from "./section.mjs";

export interface FoundationMfaFactorStoreModuleOptions {
	/**
	 * The Store transport settings: the user repository's HTTP settings as the
	 * configuration holds them (`repositories.user.http` in the standalone
	 * template, which hands them here), whose `bearerToken`,
	 * `timeout` and `maxResponseBytes` are the Store's, text read as numbers.
	 * `{}` states none: no credential is sent, and the defaults apply.
	 */
	readonly storeTransport: unknown;
}

/** The settings as a section of keys, or a refusal for anything else, absent included. */
function settingsOf(value: unknown): Readonly<Record<string, unknown>> {
	if (typeof value !== "object" || value === null || Array.isArray(value)) {
		throw new RangeError(
			"foundation-mfa-factor-store: storeTransport, the Store transport settings, must be a section of keys ({} for none)",
		);
	}
	return value as Readonly<Record<string, unknown>>;
}

/** The module, over the Store transport settings `options` hands it. */
export function foundationMfaFactorStoreModule(
	options: FoundationMfaFactorStoreModuleOptions,
): Module {
	return defineModule({
		name: "foundation-mfa-factor-store",
		section: foundationMfaFactorStoreSection,
		provides: {
			mfaFactorStore: ({ section }) => {
				const urls = readFoundationMfaFactorStoreUrls(section);
				return new HttpMfaFactorStore({
					...urls,
					...readStoreTransportConfig(settingsOf(options?.storeTransport)),
				});
			},
		},
		lifecycle: foundationMfaFactorStoreLifecycle,
	});
}
