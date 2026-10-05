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

// The `amr` value a federated login records (beside the upstream IdP's only
// for a federation that trusts it, the MFA ADR's D13). Core's; re-exported so
// an import from here keeps working.
export { FEDERATED_AMR } from "@o3co/auth-provider-core";
// The session-admission ADR's D5 — the answer to a login a session requirement
// interrupted: the login route's, and a requirement's completion's when
// `resumePrimary` answers another requirement's interruption.
export {
	type AnswerInterruptionDeps,
	type AnswerInterruptionResult,
	answerInterruption,
	type InterruptionReporter,
	type InterruptionStep,
} from "./answer-interruption.mjs";
// CSRF protection for the state-changing session routes. Exported so a
// composition root can issue tokens from its own login page, or mount the same
// guard on routes this package does not own. Another package reaches the guard
// through the `csrfGuard` slot the session module provides;
// `createSessionCsrfGuard` builds that slot's value, for a composition that
// provides it without the module. `createCsrfProtection` and
// `createCsrfProtectionFromConfig` sign through the `CsrfTokenSigner` they are
// given.
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
	createSessionCsrfGuard,
	DEFAULT_CSRF_BODY_FIELD,
	DEFAULT_CSRF_COOKIE_NAME,
	DEFAULT_CSRF_HEADER_NAME,
	DEFAULT_CSRF_TTL_SECONDS,
	MAX_CSRF_TTL_SECONDS,
} from "./csrf.mjs";
// The `csrfTokenSigner` slot the session store's module provides from
// `session-store.secret`; exported so a composition that mounts its own cookie
// session provides the slot the same way, and its tokens keep verifying.
export { createSessionCsrfTokenSigner } from "./csrf-token-signer.mjs";
// The session-admission ADR's D5 — the tail of a login: the session written
// from the `Establishment` core's admission built, and nothing beside it. Both
// login routes call it, and a requirement's completion (the MFA package's,
// after `resumePrimary`) finishes a login with it.
export {
	type EstablishedRecord,
	type EstablishSessionDeps,
	type EstablishSessionReporter,
	type EstablishSessionResult,
	type EstablishSessionStep,
	establishSession,
} from "./establish-session.mjs";
// Federated claims never outrank local ones; see claim-precedence.mts.
export type { FederatedClaimsNamespace } from "./federations/claim-precedence.mjs";
export {
	FEDERATED_CLAIMS_KEY,
	mergeFederatedClaims,
	PROMOTABLE_FEDERATED_CLAIMS,
} from "./federations/claim-precedence.mjs";
export type { RedirectConfig } from "./federations/helpers.mjs";
export { resolveCallbackRedirect } from "./federations/helpers.mjs";
// The federation redirect policy.
export type {
	FederationRedirectPolicy,
	FederationRedirectPolicyConfig,
	FederationRedirectPolicyFactory,
	RedirectAllowlistOptions,
	RedirectAllowlistValidator,
	RedirectRejection,
} from "./federations/redirect-policy.mjs";
// A standalone `validateRedirect` is deliberately NOT exported: redirect
// validation exists only as a policy built from an allowlist, which fails
// closed without one. The pieces below are exported so a custom policy can
// reuse the same rules and rejection vocabulary instead of inventing its own.
export {
	checkRedirectShape,
	createFederationRedirectPolicy,
	createRedirectAllowlistValidator,
	describeRedirectRejection,
	isLoopbackHostname,
	MAX_REDIRECT_URL_LENGTH,
} from "./federations/redirect-policy.mjs";
// `response_mode=form_post` federations (Sign in with Apple). A form_post
// federation's ephemeral state lives in a transaction of its own, addressed by
// a dedicated cookie, so the application session cookie is never relaxed.
export type {
	FederationTransactionEnvelope,
	FederationTransactionSessionStore,
	FederationTransactionStore,
} from "./federations/transaction.mjs";
export {
	createFederationTransactionStore,
	DEFAULT_FEDERATION_TRANSACTION_TTL_MS,
	deriveFederationTransactionCookieName,
	FEDERATION_TRANSACTION_COOKIE_SUFFIX,
	FEDERATION_TRANSACTION_KEY_PREFIX,
	mintFederationTransactionId,
} from "./federations/transaction.mjs";
export type { FederationResult } from "./federations/types.mjs";
// The login page and its `redirect_to` protocol, the `loginEntry` slot
// `sessionModule` provides; exported so a composition that provides the slot
// without the module builds it the same way.
export { createLoginEntry, loginEntryFromConfig } from "./login-entry.mjs";
// The federation adapter port — `FederationProvider`, `FederationProfile`,
// the capability interfaces and their guards, and the response-mode
// helpers — is exported by `@o3co/auth-provider-core` and is
// deliberately not re-exported here: one type, one path. So is the adapter
// toolkit (`codeChallenge`, `callbackUrlForExchange`, `resolveClientSecret`).
// `FederationResult` above stays because only this router answers with one.
export { sessionModule } from "./module.mjs";
// The `loginCompletion` slot, over the deployment's `csrfGuard`: its own
// module, loaded beside `sessionModule` where a requirement completes a login.
export { loginCompletionModule } from "./modules/loginCompletionModule.mjs";
export { sessionStoreModule } from "./modules/sessionStoreModule.mjs";
export type { SessionStoreFactory } from "./store/factory.mjs";
export {
	createSessionStoreFactory,
	registerBuiltinSessionStores,
} from "./store/factory.mjs";

// Side-effect: loads the ContributesMap + ComponentMap declaration merges.
import "./federations/contributes.mjs";
