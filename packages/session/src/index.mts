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

// #272 — CSRF protection for the state-changing session routes. Exported so a
// composition root can issue tokens from its own login page, or mount the same
// guard on routes this package does not own.
export type {
	CsrfCookieAttributes,
	CsrfGuardOptions,
	CsrfOriginVerdict,
	CsrfProtection,
	CsrfProtectionOptions,
	CsrfTokenVerdict,
	SessionCsrfConfigSlice,
} from "./csrf.mjs";
export {
	checkRequestOrigin,
	createCsrfGuard,
	createCsrfIssueHandler,
	createCsrfProtection,
	createCsrfProtectionFromConfig,
	DEFAULT_CSRF_BODY_FIELD,
	DEFAULT_CSRF_COOKIE_NAME,
	DEFAULT_CSRF_HEADER_NAME,
	DEFAULT_CSRF_TTL_SECONDS,
	MAX_CSRF_TTL_SECONDS,
} from "./csrf.mjs";
// #279 — federated claims never outrank local ones; see claim-precedence.mts.
export type { FederatedClaimsNamespace } from "./federations/claim-precedence.mjs";
export {
	FEDERATED_CLAIMS_KEY,
	mergeFederatedClaims,
	PROMOTABLE_FEDERATED_CLAIMS,
} from "./federations/claim-precedence.mjs";
// #479 — a federation may compute its `client_secret` per token exchange
// (Apple's ES256 JWT) instead of holding a fixed string.
export type { FederationClientSecret } from "./federations/client-secret.mjs";
export { resolveClientSecret } from "./federations/client-secret.mjs";
export { extractFederationSection } from "./federations/extract-federation-section.mjs";
export type { RedirectConfig } from "./federations/helpers.mjs";
export { resolveCallbackRedirect } from "./federations/helpers.mjs";
export { codeChallenge } from "./federations/pkce.mjs";
// A5 redirect-policy split (per A5 §5.2/§5.3/§9)
export type {
	FederationRedirectPolicy,
	FederationRedirectPolicyConfig,
	FederationRedirectPolicyFactory,
	RedirectAllowlistOptions,
	RedirectAllowlistValidator,
	RedirectRejection,
} from "./federations/redirect-policy.mjs";
// `validateRedirect` is deliberately NOT exported: the standalone helper
// derived its answer from `sessionDomain` alone and accepted every http(s) URL
// when that was unset (#278). Redirect validation now exists only as a policy
// built from an allowlist. The pieces below are exported so a custom policy can
// reuse the same rules and rejection vocabulary instead of inventing its own.
export {
	checkRedirectShape,
	createFederationRedirectPolicy,
	createRedirectAllowlistValidator,
	describeRedirectRejection,
	isLoopbackHostname,
	MAX_REDIRECT_URL_LENGTH,
} from "./federations/redirect-policy.mjs";
// #479 — `response_mode=form_post` federations (Sign in with Apple).
export type { FederationResponseMode } from "./federations/response-mode.mjs";
export {
	applyCrossSiteStateCookie,
	DEFAULT_FEDERATION_RESPONSE_MODE,
	FEDERATION_RESPONSE_MODES,
	resolveFederationResponseMode,
} from "./federations/response-mode.mjs";
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
export {
	type SessionStoreModuleConfig,
	sessionStoreModule,
	sessionStoreModuleFor,
} from "./modules/sessionStoreModule.mjs";
export type { SessionStoreFactory } from "./store/factory.mjs";
export {
	createSessionStoreFactory,
	registerBuiltinSessionStores,
} from "./store/factory.mjs";

// Side-effect: loads ContributesMap + ComponentMap declaration-merges for A5.
import "./federations/contributes.mjs";
