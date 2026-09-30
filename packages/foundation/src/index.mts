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

import type { AdapterFactory, UserRepository } from "@o3co/auth-provider-core";
import {
	DEFAULT_MAX_RESPONSE_BYTES,
	type FederatedIdentityLookupCoverage,
	HttpUserRepository,
} from "./repositories/HttpUserRepository.mjs";

/** Default request deadline, in milliseconds, when the config names none. */
const DEFAULT_TIMEOUT_MS = 5000;

/**
 * Coerces a numeric config value that may arrive as a string (HOCON
 * environment substitution yields strings). Only an *absent* key takes
 * `fallback`. Anything present but unreadable becomes `NaN` for the
 * constructor to reject, and a **blank** environment variable, which HOCON
 * substitutes as `""`, becomes `0`: a boot failure too, not a silent default.
 */
const toNumber = (value: unknown, fallback: number): number => {
	if (value === undefined || value === null) return fallback;
	if (typeof value === "number") return value;
	if (typeof value === "string") return Number(value.trim());
	return Number.NaN;
};

export const registerBuiltinAdapters = (factories: {
	userFactory: AdapterFactory<UserRepository>;
}): void => {
	factories.userFactory.register("http", (config) => {
		if (typeof config.authenticateUrl !== "string") {
			throw new Error('HttpUserRepository requires "authenticateUrl" in config');
		}
		if (typeof config.authenticateByTokenUrl !== "string") {
			throw new Error('HttpUserRepository requires "authenticateByTokenUrl" in config');
		}
		// Every remaining check — https-or-loopback, positive-integer timeout,
		// positive-integer cap — lives in the constructor, so a repository built
		// by hand is validated exactly as one built from config.
		return new HttpUserRepository({
			authenticateUrl: config.authenticateUrl,
			authenticateByTokenUrl: config.authenticateByTokenUrl,
			// Optional. Present → the repository can link a federated identity.
			...(typeof config.linkFederatedIdentityUrl === "string"
				? { linkFederatedIdentityUrl: config.linkFederatedIdentityUrl }
				: {}),
			// Optional. Forwarded whenever SET, not only when well-typed —
			// the link URL above vanishes when misspelt, and for the lookup a value
			// that vanishes is a deployment that believes itself covered and is
			// not. The constructor refuses what is not a URL, or not a list.
			...(config.findSubjectByFederatedIdentityUrl !== undefined
				? {
						findSubjectByFederatedIdentityUrl: config.findSubjectByFederatedIdentityUrl as string,
					}
				: {}),
			...(config.federatedIdentityLookupCoverage !== undefined
				? {
						federatedIdentityLookupCoverage:
							config.federatedIdentityLookupCoverage as readonly FederatedIdentityLookupCoverage[],
					}
				: {}),
			// Optional, and forwarded whenever SET for the lookup URL's reason: a
			// token that vanished would be a deployment that believes its Store
			// calls authenticated and sends them bare. The constructor refuses
			// what is not a string, and what is blank, malformed or too weak.
			...(config.bearerToken !== undefined ? { bearerToken: config.bearerToken as string } : {}),
			timeout: toNumber(config.timeout, DEFAULT_TIMEOUT_MS),
			maxResponseBytes: toNumber(config.maxResponseBytes, DEFAULT_MAX_RESPONSE_BYTES),
		});
	});
};

export {
	FOUNDATION_MFA_FACTOR_STORE_SECTION,
	type FoundationMfaFactorStoreSection,
	type FoundationMfaFactorStoreUrls,
	foundationMfaFactorStoreSection,
	readFoundationMfaFactorStoreUrls,
} from "./mfa/section.mjs";
export {
	MfaStoreError,
	type MfaStoreFailure,
	type MfaStoreOperation,
	mfaStoreMalformedAnswer,
	mfaStoreStatusError,
	mfaStoreUnreadableRecord,
	mfaStoreVersionSkipped,
} from "./mfa/storeFailure.mjs";
export {
	DEFAULT_MAX_RESPONSE_BYTES,
	type FederatedIdentityLookupCoverage,
	HttpUserRepository,
} from "./repositories/HttpUserRepository.mjs";
export {
	StoreCredentialRefusedError,
	StoreTransportError,
	type StoreTransportFailure,
} from "./repositories/storeErrors.mjs";
