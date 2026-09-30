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
 * credential, deadline and response cap are the user repository's, handed
 * in by the composition root as it hands that repository its settings, and
 * read as the repository's builder reads them, so one token goes to every
 * Store endpoint; the version floor is kept in the `replaySeenSet` slot,
 * which every replica shares.
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
	 * The user repository's HTTP settings as the configuration holds them
	 * (`repositories.user.http`): its `bearerToken`, `timeout` and
	 * `maxResponseBytes` are the Store's, text read as numbers. Absent, no
	 * credential is sent and the defaults apply.
	 */
	readonly userRepositoryHttp?: unknown;
}

/** The settings as a section of keys, or a refusal for anything else. */
function settingsOf(value: unknown): Readonly<Record<string, unknown>> {
	if (value === undefined) return {};
	if (typeof value !== "object" || value === null || Array.isArray(value)) {
		throw new RangeError(
			"foundation-mfa-factor-store: the user repository's HTTP settings must be a section of keys",
		);
	}
	return value as Readonly<Record<string, unknown>>;
}

/** The module, over the user repository's HTTP settings `options` hands it. */
export function foundationMfaFactorStoreModule(
	options: FoundationMfaFactorStoreModuleOptions = {},
): Module {
	return defineModule({
		name: "foundation-mfa-factor-store",
		section: foundationMfaFactorStoreSection,
		requires: ["replaySeenSet"] as const,
		provides: {
			mfaFactorStore: ({ section, replaySeenSet }) => {
				const urls = readFoundationMfaFactorStoreUrls(section);
				return new HttpMfaFactorStore({
					...urls,
					...readStoreTransportConfig(settingsOf(options.userRepositoryHttp)),
					replaySeenSet,
				});
			},
		},
		lifecycle: foundationMfaFactorStoreLifecycle,
	});
}
