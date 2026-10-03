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
import type { ProviderDeps } from "../modules/manifest/provider.mjs";
import type { TokenEndpointAuthMethod } from "../repositories/types.mjs";
import type { SenderConstraint } from "./senderConstraint.mjs";
import type { TokenBinding } from "./tokenBinding.mjs";

/**
 * The client identity established by RFC 6749 §2.3 token-endpoint
 * authentication (`clientAuthMw`) before a grant handler runs. Grants that
 * gate on client identity MUST use it, never the raw body: body parameters
 * are attacker-controlled and may differ from the authenticated identity.
 */
export interface AuthenticatedClient {
	readonly clientId: string;
	readonly tokenEndpointAuthMethod: TokenEndpointAuthMethod;
	/**
	 * Per-client allowed scope ceiling. Grant handlers that issue tokens
	 * directly from the client record (e.g., `client_credentials`, which has
	 * no upstream RT/code carrying a scope claim) compare requested scopes
	 * against this list and emit `invalid_scope` on disjoint sets.
	 */
	readonly allowedScopes?: readonly string[];
	/**
	 * What an omitted `scope` grants, mirrored from the client registration.
	 * Absent with a non-empty `allowedScopes`, a scope-omitting request answers
	 * `invalid_scope` instead of receiving the whole ceiling.
	 */
	readonly defaultScopes?: readonly string[];
	/**
	 * Per-client grant-type gate, mirrored from the client registration by
	 * `clientAuthMw`. Enforced centrally by `isGrantTypeAllowed` at grant
	 * dispatch and at `/authorize`; `client_credentials` and the WebAuthn grant
	 * add a stricter deny-by-absence rule. Semantics are documented on
	 * `Client.allowedGrantTypes` in `../repositories/types.mts`.
	 */
	readonly allowedGrantTypes?: readonly string[];
	/**
	 * Audience values this client may receive tokens for. Grants take the first
	 * entry as the default `aud` and let a `grantPolicy` narrow within the
	 * list. An absent list falls back by whom the token is for:
	 *
	 * - User-bound tokens (`authorization_code`, `session`, the device, WebAuthn
	 *   and jwt-bearer grants): the client id. The token is for a resource, so
	 *   the issuer would be wrong; never null, since an audience-less token
	 *   passes any loose `aud` check.
	 * - Client-only tokens (`client_credentials`): the issuer. There is no end
	 *   user, and the registration is the party the token speaks for.
	 * - No authenticated client (WebAuthn and jwt-bearer client-less mode): the
	 *   issuer, the one audience every deployment has (RFC 9068 §2.2 requires
	 *   `aud`). A policy audience is refused: with no list there is no ceiling,
	 *   and policy may narrow, never originate.
	 *
	 * `session.mts`, `jwtBearer.mts` and the WebAuthn grant cite this as their
	 * authority; keep it true when adding a grant.
	 */
	readonly allowedAudiences?: readonly string[];
	/**
	 * Per-client sender-constraint requirement, propagated by `/token` from
	 * `req.oauthClient` and enforced by the shared grant dispatch before the
	 * grant handler runs.
	 */
	readonly senderConstrained?: SenderConstraint;
	/**
	 * Per-client opt-in for the RFC 7636 `plain` PKCE method, propagated by
	 * `/token` from `req.oauthClient` so the authorization-code grant applies
	 * the method list `/authorize` applied when minting the code. Semantics are
	 * documented on `Client.allowPlainPkce` in `../repositories/types.mts`.
	 */
	readonly allowPlainPkce?: boolean;
}

/**
 * Session data exposed to grant handlers. Authorization-code identity binding
 * lives on the code record (`Code.client_id` / `Code.redirect_uri`), not
 * here. `code` remains so the authorization grant can clear it from older
 * sessions (`sessionMutation.clear`).
 */
export interface SessionData {
	user?: Record<string, unknown>;
	client?: Record<string, unknown>;
	code?: string;
	isAuthenticated?: boolean;
	/**
	 * The `UserSession` id of this browser session, written by local login or
	 * the federation callback and kept across session regeneration. A token
	 * minted from the browser session carries it as `sid`, which every
	 * liveness check (`/userinfo`, `/introspect`, the refresh grant) keys on;
	 * without it, logout cannot reach the token.
	 *
	 * Absent when the login wiring does not write it, or on a back-channel
	 * `/token` call with no cookie; grants treat absence as "no session to
	 * bind to", never as an error.
	 */
	sid?: string;
}

export interface GrantContext {
	readonly body: Readonly<Record<string, unknown>>;
	/**
	 * Readonly property — wholesale `ctx.session = {…}` replacement is rejected
	 * at compile time. Field-level mutation (`ctx.session.isAuthenticated = …`)
	 * is intentionally still allowed because handlers write through Express's
	 * `req.session` object; `SessionData` mirrors that mutable surface.
	 */
	readonly session: SessionData;
	readonly issuer?: string;
	readonly metadata: Readonly<Record<string, unknown>>;
	readonly ip?: string;
	readonly userAgent?: string;
	/**
	 * The client authenticated by `clientAuthMw` before `/token` dispatch.
	 * Grants that bind tokens to client identity MUST use it, not
	 * `body.client_id`, which is attacker-controlled and bypasses RFC 6749
	 * §2.3 authentication. `null` outside the standard `/token` route (custom
	 * wiring, direct invocation); handlers that need a client identity SHOULD
	 * reject `null` with `invalid_client` 401.
	 */
	readonly authenticatedClient: AuthenticatedClient | null;
	/**
	 * Sender binding established by `tokenBindingMw` before grant dispatch;
	 * `undefined` when no mechanism is enabled, the request carried no proof /
	 * cert, or the grant runs outside the standard `/token` route. Grants that
	 * issue tokens stamp `ownedConfirmation(tokenBinding)` (the member the
	 * binding's kind owns, never the confirmation verbatim) as
	 * `GenerateTokenOptions.confirmation`.
	 */
	readonly tokenBinding?: TokenBinding;
}

export interface GrantSuccess {
	status: number;
	tokens: import("./token.mjs").TokenResponse;
}

export interface GrantError {
	status: number;
	error: string;
	errorDescription?: string;
	/**
	 * Present when the refusal is a grant policy's deny: the policy's own
	 * code, sanitised and capped, which the token endpoint's audit records
	 * beside the code it answered. Never sent to the client.
	 */
	readonly policyDenial?: { readonly error: string };
}

export type GrantResult = GrantSuccess | GrantError;

export interface SessionMutation {
	clear?: string[];
	set?: Record<string, unknown>;
}

export interface GrantHandlerResult {
	result: GrantResult;
	sessionMutation?: SessionMutation;
}

/**
 * What `/oauth/token` dispatches a `grant_type` to. It has no teardown hook:
 * a module that holds a resource on a handler's behalf releases it through
 * its own `lifecycle[K].cleanup`, which `AppHandle.dispose()` runs.
 */
export interface GrantHandler {
	handle(ctx: GrantContext): Promise<GrantHandlerResult>;
	/**
	 * Declares that this grant must never be acquired by omission.
	 *
	 * `/token` dispatch always enforces `isGrantTypeAllowed`, under which an
	 * absent `allowedGrantTypes` admits every grant. With this flag, an absent
	 * allowlist on the authenticated client is refused `400
	 * unauthorized_client` before the handler runs. Declare it on grants that
	 * are a standing capability rather than a per-user ceremony
	 * (`client_credentials`, the WebAuthn grant), so a registration without
	 * `allowedGrantTypes` cannot silently acquire them.
	 *
	 * Applies only when `ctx.authenticatedClient` is non-null (WebAuthn's
	 * client-less mode has no allowlist to consult); handlers that require a
	 * client reject `null` themselves with `invalid_client`.
	 */
	readonly requiresExplicitGrantAllowlist?: boolean;
}

/**
 * The slots a grant may depend on, as `ComponentMap` slots: `config` and
 * `keyStore` required, the rest optional. A grant factory takes
 * `Pick<GrantDependencies, …>` of the slots it reads (plus `ProviderDeps<…>`
 * for a slot no other grant shares), and its module's `ProviderDeps<R, O>`
 * must satisfy that pick at the wiring, so an undeclared slot is a compile
 * error rather than a runtime `undefined`.
 *
 * Why each is optional:
 * - `refreshTokenFamilyRotation` / `refreshTokenFamilyRevocation`: rotation
 *   persistence and replay revocation (RFC 6819 §5.2.2); without rotation
 *   there is no replay path.
 * - `grantPolicy`: absent means no policy declared.
 * - `userSessionStore` / `sessionRPRegistry` / `sessionFamilyIndex` /
 *   `sessionFederationIndex`: session liveness and the four-store cascade; a
 *   back-channel deployment with no browser sessions wires none.
 * - `subjectRevocation`: the subject-revocation watermark, checked by the
 *   refresh grant at RT redemption as the backstop for a partial cascade
 *   failure, so a family the cascade could not revoke stops minting access
 *   tokens for a subject whose credential changed. A rotated RT has a fresh
 *   `iat`, so only RTs minted before the change are caught.
 * - `logger`: security audit events (RT replay, unknown-family decisions,
 *   legacy-token acceptance); silent when absent, for minimal test harnesses.
 * - `oauthTokenSettings`: the issuer, lifetimes and switches a grant reads of
 *   the oauth module's settings, held whole with `checkOAuthTokenSettings`
 *   rather than read from `config`; absent in a composition without the
 *   oauth module. `config` stays required while grants still read it.
 */
export type GrantDependencies = ProviderDeps<
	"config" | "keyStore",
	| "refreshTokenFamilyRotation"
	| "refreshTokenFamilyRevocation"
	| "grantPolicy"
	| "userSessionStore"
	| "sessionRPRegistry"
	| "sessionFamilyIndex"
	| "sessionFederationIndex"
	| "subjectRevocation"
	| "logger"
	| "oauthTokenSettings"
>;

/**
 * Factory function type for creating grant handlers.
 * Used by OSS consumers to implement custom grant types.
 */
export type GrantFactory = (deps: GrantDependencies) => GrantHandler;
