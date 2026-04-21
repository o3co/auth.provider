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

import { resolveCallbackRedirect, validateRedirect } from "./helpers.mjs";
import type {
	EndSessionRequest,
	EndSessionResult,
	FederationProfile,
	FederationProviderBase,
	MappedClaims,
	RefreshedTokens,
	SetupPassportContext,
	SupportsClaimMapping,
	SupportsLogout,
	SupportsRefresh,
} from "./types.mjs";

export interface GoogleProviderConfig {
	/** Passport strategy identifier — use a unique name per tenant for multi-tenant setups. */
	name: string;
	clientId: string;
	clientSecret: string;
	callbackURL: string;
	/** Cookie / session domain used to validate redirect URLs (e.g. ".example.com"). Optional. */
	sessionDomain?: string;
	/** URL of the auth-callback page (used to build the post-login redirect). Optional. */
	authCallbackUrl?: string;
	/** Fallback URL for the client app (used when no redirectTo is present). Optional. */
	clientUrl?: string;
	/** Override Google's OAuth token endpoint (default: https://oauth2.googleapis.com/token). */
	tokenEndpoint?: string;
	/** Override Google's end-session endpoint (default: https://accounts.google.com/o/oauth2/v2/auth/logout). */
	endSessionEndpoint?: string;
	/** Test-only: inject a fetch impl for refreshFederationToken. Not documented publicly. */
	_fetch?: typeof fetch;
}

type GoogleProvider = FederationProviderBase &
	SupportsClaimMapping &
	SupportsRefresh &
	SupportsLogout;

const DEFAULT_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
const DEFAULT_END_SESSION_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth/logout";

export const createGoogleProvider = (config: GoogleProviderConfig): GoogleProvider => {
	if (!config.clientId || !config.clientSecret || !config.callbackURL) {
		throw new Error(
			`Google federation "${config.name}" requires clientId, clientSecret, and callbackURL`,
		);
	}
	const tokenEndpoint = config.tokenEndpoint ?? DEFAULT_TOKEN_ENDPOINT;
	const endSessionEndpoint = config.endSessionEndpoint ?? DEFAULT_END_SESSION_ENDPOINT;
	const fetchImpl: typeof fetch = config._fetch ?? fetch;

	return {
		name: config.name,
		scope: ["openid", "profile", "email"],

		validateRedirect(url: string) {
			return validateRedirect(url, config);
		},

		resolveCallbackRedirect(session: { redirectTo?: string }) {
			// authCallbackUrl and clientUrl are optional (DID-only deployments don't need them).
			// When Google federation is enabled, operators must configure authCallbackUrl
			// if redirect_to flows are used.
			return resolveCallbackRedirect(session, config);
		},

		async setupPassportStrategy(passport, ctx: SetupPassportContext) {
			const modSpec = ctx.pathResolver
				? ctx.pathResolver("passport-google-oauth20")
				: "passport-google-oauth20";
			const { Strategy: GoogleStrategy } = (await import(
				modSpec
			)) as typeof import("passport-google-oauth20");
			passport.use(
				config.name,
				new GoogleStrategy(
					{
						clientID: config.clientId,
						clientSecret: config.clientSecret,
						callbackURL: config.callbackURL,
						passReqToCallback: true,
					},
					async (req, accessToken, refreshToken, profileRaw, done) => {
						const profile = toFederationProfile(profileRaw, accessToken, refreshToken);
						if (ctx.onFederationCallback) {
							try {
								await ctx.onFederationCallback({
									federationName: config.name,
									profile,
									req: req as import("express").Request,
									done: done as (err: Error | null, user: unknown) => void,
								});
							} catch (err) {
								done(err as Error);
							}
							return;
						}
						// Legacy fallback (federation-tokens not wired): emulate prior behavior.
						try {
							const user = await ctx.verifyUser(`google:${profile.id}`);
							return done(null, user ?? false);
						} catch (err) {
							return done(err as Error);
						}
					},
				),
			);
		},

		mapClaims(profile: FederationProfile): MappedClaims {
			const raw = profile.raw as Record<string, unknown>;
			const json = (raw._json ?? {}) as Record<string, unknown>;
			const emails = Array.isArray(raw.emails)
				? (raw.emails as Array<{ value?: unknown; verified?: unknown }>)
				: [];
			const photos = Array.isArray(raw.photos) ? (raw.photos as Array<{ value?: unknown }>) : [];
			const claims: Record<string, unknown> = {};
			if (typeof json.email === "string") claims.email = json.email;
			else if (emails[0]?.value && typeof emails[0].value === "string")
				claims.email = emails[0].value;
			if (typeof json.email_verified === "boolean") claims.emailVerified = json.email_verified;
			else if (typeof emails[0]?.verified === "boolean") claims.emailVerified = emails[0].verified;
			if (typeof raw.displayName === "string") claims.name = raw.displayName;
			if (typeof photos[0]?.value === "string") claims.picture = photos[0].value;
			if (typeof json.hd === "string") claims.hd = json.hd;
			return claims as MappedClaims;
		},

		async refreshFederationToken(refreshToken: string): Promise<RefreshedTokens> {
			const body = new URLSearchParams({
				grant_type: "refresh_token",
				refresh_token: refreshToken,
				client_id: config.clientId,
				client_secret: config.clientSecret,
			});
			const res = await fetchImpl(tokenEndpoint, {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: body.toString(),
			});
			if (!res.ok) {
				let detail = "";
				try {
					const err = (await res.json()) as { error?: string; error_description?: string };
					detail = `${err.error ?? ""} ${err.error_description ?? ""}`.trim();
				} catch {
					// ignore JSON parse error
				}
				if (res.status >= 500) {
					throw new Error(
						`temporarily_unavailable: google refresh failed (${res.status}) ${detail}`,
					);
				}
				if (detail.includes("invalid_grant")) {
					throw new Error(`invalid_grant: google refresh rejected ${detail}`);
				}
				throw new Error(`refresh_failed: google refresh failed (${res.status}) ${detail}`);
			}
			const json = (await res.json()) as {
				access_token?: unknown;
				refresh_token?: unknown;
				id_token?: unknown;
				expires_in?: unknown;
			};
			if (typeof json.access_token !== "string") {
				throw new Error("refresh_failed: google refresh returned no access_token");
			}
			const expiresIn = typeof json.expires_in === "number" ? json.expires_in : 3600;
			return {
				accessToken: json.access_token,
				refreshToken: typeof json.refresh_token === "string" ? json.refresh_token : undefined,
				idToken: typeof json.id_token === "string" ? json.id_token : undefined,
				expiresAt: new Date(Date.now() + expiresIn * 1000),
			};
		},

		async endSession(req: EndSessionRequest): Promise<EndSessionResult> {
			const url = new URL(endSessionEndpoint);
			if (req.idTokenHint) url.searchParams.set("id_token_hint", req.idTokenHint);
			if (req.postLogoutRedirectUri)
				url.searchParams.set("post_logout_redirect_uri", req.postLogoutRedirectUri);
			if (req.state) url.searchParams.set("state", req.state);
			return { url, method: "GET" };
		},
	};
};

function toFederationProfile(
	raw: unknown,
	accessToken: string | undefined,
	refreshToken: string | undefined,
): FederationProfile {
	const rawObj = (raw ?? {}) as Record<string, unknown>;
	const id = typeof rawObj.id === "string" ? rawObj.id : "";
	return {
		id,
		raw: rawObj,
		accessToken,
		refreshToken,
	};
}
