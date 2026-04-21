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

import type { User } from "@o3co/auth-provider-core";
import type { PassportStatic } from "passport";

export type FederationResult<T> =
	| { ok: true; value: T }
	| { ok: false; status: number; error: string; errorDescription: string };

export interface SetupPassportContext {
	readonly verifyUser: (externalId: string) => Promise<User | null>;
	/**
	 * Optional module resolver used for dynamic imports of passport strategies.
	 * Deployments with non-standard module layouts (Yarn PnP, custom require hooks)
	 * can pass a resolver; standard Node/npm deployments omit it.
	 */
	readonly pathResolver?: (spec: string) => string;
	/**
	 * Optional hook called by federation provider passport strategies after
	 * successful OAuth code exchange. Built-in implementations (in session
	 * module) orchestrate UserSessionStore + FederationTokenStore; custom
	 * deployments can wire their own. When absent, providers fall back to
	 * the legacy single-parameter `verifyUser(externalId)` flow.
	 */
	readonly onFederationCallback?: (params: {
		readonly federationName: string;
		readonly profile: FederationProfile;
		readonly req: import("express").Request;
		readonly done: (err: Error | null, user: User | false) => void;
	}) => Promise<void>;
}

/**
 * Minimum contract implemented by every federation provider.
 * Provider-specific optional features are layered via `SupportsX` capability interfaces.
 */
export interface FederationProviderBase {
	readonly name: string;
	readonly scope: readonly string[];
	validateRedirect(url: string): FederationResult<void>;
	resolveCallbackRedirect(session: { redirectTo?: string }): FederationResult<string>;
	setupPassportStrategy(passport: PassportStatic, ctx: SetupPassportContext): Promise<void>;
}

/**
 * Arguments for an OIDC RP-Initiated Logout (end-session) request.
 *
 * All fields are optional per the OIDC spec. Consumers should generate a `state`
 * value and verify it on the post-logout redirect to mitigate CSRF.
 */
export interface EndSessionRequest {
	/** ID token previously issued by the IdP, used to identify the session to terminate. */
	idTokenHint?: string;
	/** URL the IdP redirects the user agent to after logout completes. */
	postLogoutRedirectUri?: string;
	/** Opaque value round-tripped by the IdP for CSRF protection. */
	state?: string;
}

/**
 * Outcome of building an end-session redirect.
 *
 * `method` is currently always `"GET"` (OIDC RP-Initiated Logout 1.0). Future extensions
 * (e.g. POST logout for SAML interop) can widen the union additively.
 */
export interface EndSessionResult {
	/** Fully-qualified end-session URL with all parameters encoded. */
	url: URL;
	/** HTTP method the consumer should use when driving the redirect. */
	method: "GET";
}

/**
 * Optional capability: OIDC RP-Initiated Logout (end-session).
 *
 * Providers whose IdP exposes an end_session endpoint implement this capability by
 * returning a redirect URL. Consumers detect the capability with {@link supportsLogout}.
 */
export interface SupportsLogout {
	endSession(req: EndSessionRequest): Promise<EndSessionResult>;
}

/**
 * Type guard: does `provider` implement the {@link SupportsLogout} capability?
 *
 * Returns `false` for `null` / `undefined` so consumers can call this directly on
 * `Map.get(name)` results without an explicit existence check. When `provider` is
 * non-null, returns `true` when `provider.endSession` is a function. Inside a `true`
 * branch, TypeScript narrows `provider` to `FederationProviderBase & SupportsLogout`,
 * so `provider.endSession(...)` is callable without a cast.
 */
export function supportsLogout(
	provider: FederationProviderBase | undefined | null,
): provider is FederationProviderBase & SupportsLogout {
	if (provider == null) return false;
	return typeof (provider as { endSession?: unknown }).endSession === "function";
}

/**
 * OIDC-standard claims mapped from a federation profile. `[key: string]: unknown`
 * allows providers to add non-standard claims (e.g. Google's `hd` hosted domain).
 */
export interface MappedClaims {
	readonly email?: string;
	readonly emailVerified?: boolean;
	readonly name?: string;
	readonly picture?: string;
	readonly groups?: ReadonlyArray<string>;
	readonly [key: string]: unknown;
}

/**
 * Snapshot of a successful federation callback: provider-internal id + the raw
 * passport profile payload + the tokens the IdP returned. Consumed by the
 * `onFederationCallback` hook (see {@link SetupPassportContext}).
 */
export interface FederationProfile {
	readonly id: string;
	readonly raw: Readonly<Record<string, unknown>>;
	readonly accessToken?: string;
	readonly refreshToken?: string;
	readonly idToken?: string;
	readonly expiresIn?: number;
}

export interface SupportsClaimMapping {
	mapClaims(profile: FederationProfile): MappedClaims;
}

export function supportsClaimMapping(
	p: FederationProviderBase | undefined | null,
): p is FederationProviderBase & SupportsClaimMapping {
	if (p == null) return false;
	return typeof (p as { mapClaims?: unknown }).mapClaims === "function";
}

export interface RefreshedTokens {
	readonly accessToken: string;
	readonly refreshToken?: string;
	readonly idToken?: string;
	readonly expiresAt: Date;
}

export interface SupportsRefresh {
	refreshFederationToken(refreshToken: string): Promise<RefreshedTokens>;
}

export function supportsRefresh(
	p: FederationProviderBase | undefined | null,
): p is FederationProviderBase & SupportsRefresh {
	if (p == null) return false;
	return typeof (p as { refreshFederationToken?: unknown }).refreshFederationToken === "function";
}
