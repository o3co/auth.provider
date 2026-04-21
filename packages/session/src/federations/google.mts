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
	/** Override Google's end-session endpoint. When omitted Google does not publish an OIDC end_session_endpoint; the provider redirects directly to postLogoutRedirectUri instead. */
	endSessionEndpoint?: string;
	/** Test-only: inject a fetch impl for refreshFederationToken. Not documented publicly. */
	_fetch?: typeof fetch;
}

type GoogleProvider = FederationProviderBase &
	SupportsClaimMapping &
	SupportsRefresh &
	SupportsLogout;

const DEFAULT_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";

export const createGoogleProvider = (config: GoogleProviderConfig): GoogleProvider => {
	if (!config.clientId || !config.clientSecret || !config.callbackURL) {
		throw new Error(
			`Google federation "${config.name}" requires clientId, clientSecret, and callbackURL`,
		);
	}
	const tokenEndpoint = config.tokenEndpoint ?? DEFAULT_TOKEN_ENDPOINT;
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
			const strategy = new GoogleStrategy(
				{
					clientID: config.clientId,
					clientSecret: config.clientSecret,
					callbackURL: config.callbackURL,
					passReqToCallback: true,
				},
				// 6-arg verify form: passport-oauth2 dispatches on arity and passes the
				// raw token-endpoint response `params` only when the callback declares 6
				// parameters. We need `params.id_token` + `params.expires_in` for the
				// FederationProfile.
				async (
					req: import("express").Request,
					accessToken: string,
					refreshToken: string,
					params: import("passport-google-oauth20").GoogleCallbackParameters,
					profileRaw: import("passport-google-oauth20").Profile,
					done: import("passport-google-oauth20").VerifyCallback,
				) => {
					const p = params as unknown as Record<string, unknown>;
					const profile = toFederationProfile(profileRaw as unknown as Record<string, unknown>, {
						accessToken,
						refreshToken,
						idToken: typeof p?.id_token === "string" ? p.id_token : undefined,
						expiresIn: typeof p?.expires_in === "number" ? p.expires_in : undefined,
					});
					if (ctx.onFederationCallback) {
						try {
							await ctx.onFederationCallback({
								federationName: config.name,
								profile,
								req,
								done: done as (err: Error | null, user: unknown) => void,
							});
						} catch (err) {
							done(err as Error);
						}
						return;
					}
					try {
						if (!profile.id) {
							return done(null, false);
						}
						const user = await ctx.verifyUser(`${config.name}:${profile.id}`);
						return done(null, user ?? false);
					} catch (err) {
						return done(err as Error);
					}
				},
			);
			// Override authorizationParams to always include access_type=offline so Google
			// returns a refresh_token on the first authorization. This cannot be set via the
			// constructor options because passport-google-oauth20 only reads accessType from
			// the per-request options passed to passport.authenticate(); overriding the method
			// here avoids exposing per-strategy configuration to the route layer.
			const baseAuthorizationParams = (
				strategy as unknown as {
					authorizationParams(opts: Record<string, unknown>): Record<string, unknown>;
				}
			).authorizationParams.bind(strategy);
			(
				strategy as unknown as {
					authorizationParams(opts: Record<string, unknown>): Record<string, unknown>;
				}
			).authorizationParams = (opts: Record<string, unknown>) => {
				return { ...baseAuthorizationParams(opts), access_type: "offline" };
			};
			passport.use(config.name, strategy);
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
			// Google does not publish an OIDC end_session_endpoint in its discovery document;
			// operators MUST pass `endSessionEndpoint` explicitly if they want an upstream logout.
			// Absent that, we redirect directly to the RP's postLogoutRedirectUri with state,
			// mirroring the GitHub provider. The application is responsible for its own session cleanup.
			if (config.endSessionEndpoint) {
				const url = new URL(config.endSessionEndpoint);
				if (req.idTokenHint) url.searchParams.set("id_token_hint", req.idTokenHint);
				if (req.postLogoutRedirectUri)
					url.searchParams.set("post_logout_redirect_uri", req.postLogoutRedirectUri);
				if (req.state) url.searchParams.set("state", req.state);
				return { url, method: "GET" };
			}
			const base = req.postLogoutRedirectUri ?? "https://accounts.google.com/Logout";
			const url = new URL(base);
			if (req.state) url.searchParams.set("state", req.state);
			return { url, method: "GET" };
		},
	};
};

function toFederationProfile(
	raw: unknown,
	tokens: {
		accessToken: string | undefined;
		refreshToken: string | undefined;
		idToken?: string;
		expiresIn?: number;
	},
): FederationProfile {
	const rawObj = (raw ?? {}) as Record<string, unknown>;
	const id = typeof rawObj.id === "string" ? rawObj.id : "";
	return {
		id,
		raw: rawObj,
		...tokens,
	};
}
