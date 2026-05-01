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

export { extractFederationSection } from "./federations/extract-federation-section.mjs";
export type { RedirectConfig } from "./federations/helpers.mjs";
export { resolveCallbackRedirect, validateRedirect } from "./federations/helpers.mjs";
export { codeChallenge } from "./federations/pkce.mjs";
// A5 redirect-policy split (per A5 §5.2/§5.3/§9)
export type {
	DefaultFederationRedirectPolicyConfig,
	FederationRedirectPolicy,
	FederationRedirectPolicyFactory,
} from "./federations/redirect-policy.mjs";
export { createDefaultFederationRedirectPolicy } from "./federations/redirect-policy.mjs";
export type {
	EndSessionRequest,
	EndSessionResult,
	FederationProfile,
	FederationProvider,
	FederationResult,
	MappedClaims,
	RefreshedTokens,
	SupportsClaimMapping,
	SupportsLogout,
	SupportsRefresh,
} from "./federations/types.mjs";
export {
	supportsClaimMapping,
	supportsLogout,
	supportsRefresh,
} from "./federations/types.mjs";
export { sessionModule } from "./module.mjs";
export type { SessionStoreFactory } from "./store/factory.mjs";
export {
	createSessionStoreFactory,
	registerBuiltinSessionStores,
} from "./store/factory.mjs";

// Side-effect: loads ContributesMap + ComponentMap declaration-merges for A5.
import "./federations/contributes.mjs";
