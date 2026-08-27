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
import type { z } from "zod";
import type { CoreConfig } from "../config/application.schema.mjs";
import type { KeyStore } from "../keys/KeyStore.mjs";
import type { PathResolver } from "../modules/types.mjs";
import type { GrantPolicyHook } from "../policy/types.mjs";
import type {
	RefreshTokenFamilyRevocation,
	RefreshTokenFamilyRotation,
} from "../refresh-token-family/types.mjs";
import type { TokenEndpointAuthMethod } from "../repositories/types.mjs";
import type {
	SessionFamilyIndex,
	SessionFederationIndex,
	SessionRPRegistry,
	UserSessionStore,
} from "../user-sessions/types.mjs";
import type { SenderConstraint } from "./senderConstraint.mjs";
import type { TokenBinding } from "./tokenBinding.mjs";

/**
 * The client identity established by RFC 6749 §2.3 token-endpoint
 * authentication middleware (`clientAuthMw`) before a grant handler is
 * invoked.
 *
 * Every grant handler that gates on client identity (refresh, authorization
 * code, token-exchange) MUST consult this slot rather than the raw request
 * body — body parameters are attacker-controlled and may differ from the
 * authenticated identity. `null` indicates the request did not pass through
 * `clientAuthMw` (e.g., a custom route, or a unit test invoking the handler
 * directly with a hand-built `GrantContext`).
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
	 * Per-client grant-type gate, mirrored from the client registration by
	 * `clientAuthMw`. Enforced **centrally** by `isGrantTypeAllowed` at grant
	 * dispatch and at `/authorize`, so every grant inherits the check (#268);
	 * `client_credentials` and the WebAuthn grant layer a stricter
	 * deny-by-absence rule on top. The absent / empty / non-empty semantics
	 * are documented once, on `Client.allowedGrantTypes` in
	 * `../repositories/types.mts`.
	 */
	readonly allowedGrantTypes?: readonly string[];
	/**
	 * Audience values this client may receive tokens for. Grants that issue
	 * tokens directly from the client record select the first entry as the
	 * default `aud`; absence falls back to the issuer.
	 */
	readonly allowedAudiences?: readonly string[];
	/**
	 * Per-client sender-constraint requirement. The `/token` route
	 * propagates this from `req.oauthClient`; the shared grant-dispatch
	 * path enforces the binding-method rules in spec §4.8 step 2 before
	 * invoking the concrete grant handler.
	 */
	readonly senderConstrained?: SenderConstraint;
}

/**
 * Session data exposed to grant handlers.
 *
 * D-1 (v0.5.1): identity binding for the authorization code grant moved out
 * of this session bag and into the code record (`Code.client_id` /
 * `Code.redirect_uri`). The previously exposed `code_client_id`,
 * `code_redirect_uri`, and `granted_scopes` fields have been removed because
 * `/authorize` no longer writes them and `/token` no longer reads them.
 *
 * `code` is retained because the authorization grant still clears it from
 * sessions issued before v0.5.1 ships (see `sessionMutation.clear`).
 */
export interface SessionData {
	user?: Record<string, unknown>;
	client?: Record<string, unknown>;
	code?: string;
	isAuthenticated?: boolean;
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
	 * The authenticated client established by `clientAuthMw` before grant
	 * dispatch on `/token`. Grant handlers that bind tokens to client identity
	 * (authorization code, refresh, token-exchange) MUST use this field rather
	 * than `body.client_id` — the body is attacker-controlled and bypasses
	 * RFC 6749 §2.3 authentication.
	 *
	 * `null` when the grant is invoked outside the standard `/token` route
	 * (custom wiring, direct unit-test invocation). Handlers that rely on a
	 * client identity SHOULD reject `null` with `invalid_client` 401.
	 */
	readonly authenticatedClient: AuthenticatedClient | null;
	/**
	 * Sender-binding established by `tokenBindingMw` before grant dispatch.
	 * `undefined` when no binding mechanism is enabled, when the request
	 * did not carry the required proof / cert, or when the grant is
	 * invoked outside the standard `/token` route. Grant handlers that
	 * issue tokens propagate `tokenBinding.confirmation` into
	 * `GenerateTokenOptions.confirmation`. See Wave 2 Token-binding Cluster
	 * spec §4.1.
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

export interface GrantHandler {
	handle(ctx: GrantContext): Promise<GrantHandlerResult>;
	cleanup?(): void;
	/**
	 * Declares that this grant must never be acquired by omission (#326).
	 *
	 * The shared `/token` dispatch always enforces the base
	 * `allowedGrantTypes` rule (`isGrantTypeAllowed`), under which an
	 * **absent** allowlist means "no policy declared" and admits every
	 * grant. A handler that sets this flag opts into the stricter
	 * deny-by-absence composition: when the authenticated client's
	 * `allowedGrantTypes` is absent, dispatch refuses the request with
	 * `400 unauthorized_client` before the handler runs.
	 *
	 * Declare it on grants where access is a standing capability rather
	 * than a per-user ceremony — machine-to-machine grants like
	 * `client_credentials` and the WebAuthn grant do — so that a
	 * registration written before `allowedGrantTypes` existed cannot
	 * silently acquire them. Enforcement used to be hand-rolled inside
	 * those two handlers; the flag replaces that folklore with a
	 * declaration the dispatch enforces for every current and future
	 * strict grant.
	 *
	 * The check only applies when an authenticated client is present.
	 * `ctx.authenticatedClient === null` (custom wiring, direct handler
	 * invocation, or a grant that deliberately serves unauthenticated
	 * callers, e.g. WebAuthn's passkey-is-the-auth-event mode) has no
	 * allowlist to consult; handlers that require a client identity keep
	 * rejecting `null` themselves with `invalid_client`.
	 */
	readonly requiresExplicitGrantAllowlist?: boolean;
}

export interface GrantDependencies {
	config: CoreConfig & Record<string, unknown>;
	keyStore: KeyStore;
	pathResolver?: PathResolver;
	refreshTokenFamilyRotation?: RefreshTokenFamilyRotation;
	refreshTokenFamilyRevocation?: RefreshTokenFamilyRevocation;
	grantPolicy?: GrantPolicyHook;
	userSessionStore?: UserSessionStore;
	sessionRPRegistry?: SessionRPRegistry;
	sessionFamilyIndex?: SessionFamilyIndex;
	sessionFederationIndex?: SessionFederationIndex;
	/**
	 * Optional structured logger for security-relevant grant audit events
	 * (RT replay detection, unknown-family policy decisions, legacy-token
	 * acceptance). Falls back silently when absent so the grant factory
	 * remains usable from minimal test harnesses; production wires the
	 * `logger` slot per `ComponentMap.logger` declaration merge.
	 */
	logger?: import("../logging/Logger.mjs").Logger;
}

/**
 * Factory function type for creating grant handlers.
 * Used by OSS consumers to implement custom grant types.
 */
export type GrantFactory = (deps: GrantDependencies) => GrantHandler;

/**
 * A module that bundles one or more grant factories together.
 * Used with GrantRegistry.addModule() for plugin-style registration.
 */
export interface GrantModule {
	grants: Record<string, GrantFactory>;
	configSchema?: z.ZodType;
}
