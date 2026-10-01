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
	type FederatedIdentityLookupCoverage,
	HttpUserRepository,
} from "./repositories/HttpUserRepository.mjs";
import { readStoreTransportConfig } from "./storeTransport.mjs";

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
			// Optional, forwarded whenever SET for the same reason: a witness URL
			// that vanished leaves the MFA enrollment witness unwritten.
			...(config.markMfaEnrolledUrl !== undefined
				? { markMfaEnrolledUrl: config.markMfaEnrolledUrl as string }
				: {}),
			...(config.federatedIdentityLookupCoverage !== undefined
				? {
						federatedIdentityLookupCoverage:
							config.federatedIdentityLookupCoverage as readonly FederatedIdentityLookupCoverage[],
					}
				: {}),
			// The bearer token, the deadline and the response cap. The constructor
			// refuses a token that is not a string, or is blank, malformed or too
			// weak, and a deadline or cap that is not a positive integer.
			...readStoreTransportConfig(config),
		});
	});
};

export {
	HttpMfaFactorStore,
	type HttpMfaFactorStoreOptions,
} from "./mfa/HttpMfaFactorStore.mjs";
export {
	type FoundationMfaFactorStoreModuleOptions,
	foundationMfaFactorStoreModule,
} from "./mfa/module.mjs";
export {
	MfaStoreError,
	type MfaStoreFailure,
	type MfaStoreOperation,
} from "./mfa/storeFailure.mjs";
export {
	type FederatedIdentityLookupCoverage,
	HttpUserRepository,
} from "./repositories/HttpUserRepository.mjs";
export {
	StoreCredentialRefusedError,
	StoreTransportError,
	type StoreTransportFailure,
} from "./repositories/storeErrors.mjs";
export { DEFAULT_MAX_RESPONSE_BYTES } from "./storeTransport.mjs";
