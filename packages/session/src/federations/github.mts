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

import type { PassportStatic } from "passport";
import { fetchGithubPrimaryEmail, resolveCallbackRedirect, validateRedirect } from "./helpers.mjs";
import type {
	EndSessionRequest,
	EndSessionResult,
	FederationProfile,
	FederationProviderBase,
	MappedClaims,
	SetupPassportContext,
	SupportsClaimMapping,
	SupportsLogout,
} from "./types.mjs";

export interface GithubProviderConfig {
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
	/** Test-only: inject fetch impl used by fetchGithubPrimaryEmail. */
	_fetch?: typeof fetch;
}

type GithubProvider = FederationProviderBase & SupportsClaimMapping & SupportsLogout;

export function createGithubProvider(config: GithubProviderConfig): GithubProvider {
	if (!config.clientId || !config.clientSecret || !config.callbackURL) {
		throw new Error(
			`GitHub federation "${config.name}" requires clientId, clientSecret, and callbackURL`,
		);
	}

	const scope = ["read:user", "user:email"] as const;
	const fetchImpl: typeof fetch = config._fetch ?? fetch;

	return {
		name: config.name,
		scope,

		validateRedirect(url: string) {
			return validateRedirect(url, config);
		},

		resolveCallbackRedirect(session: { redirectTo?: string }) {
			return resolveCallbackRedirect(session, config);
		},

		async setupPassportStrategy(
			passport: PassportStatic,
			ctx: SetupPassportContext,
		): Promise<void> {
			let GithubStrategy: typeof import("passport-github2").Strategy;
			try {
				const modSpec = ctx.pathResolver
					? ctx.pathResolver("passport-github2")
					: "passport-github2";
				({ Strategy: GithubStrategy } = (await import(
					modSpec
				)) as typeof import("passport-github2"));
			} catch (err) {
				throw new Error(
					"GitHub federation requires passport-github2. Run: pnpm add passport-github2 @types/passport-github2",
					{ cause: err },
				);
			}
			passport.use(
				config.name,
				new GithubStrategy(
					{
						clientID: config.clientId,
						clientSecret: config.clientSecret,
						callbackURL: config.callbackURL,
						scope: [...scope],
						passReqToCallback: true,
					},
					async (
						req: import("express").Request,
						accessToken: string,
						refreshToken: string | undefined,
						profileRaw: { id: string } & Record<string, unknown>,
						done: (err: Error | null, user?: unknown) => void,
					) => {
						let enrichedRaw: Record<string, unknown> = {
							...(profileRaw as Record<string, unknown>),
						};
						if (!hasEmail(enrichedRaw)) {
							const fetched = await fetchGithubPrimaryEmail(accessToken, fetchImpl);
							if (fetched) {
								enrichedRaw = {
									...enrichedRaw,
									emails: [{ value: fetched.email, verified: fetched.verified }],
								};
							}
						}
						const profile: FederationProfile = {
							id:
								typeof enrichedRaw.id === "string" ? enrichedRaw.id : String(enrichedRaw.id ?? ""),
							raw: enrichedRaw,
							accessToken,
							refreshToken,
						};
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
							const user = await ctx.verifyUser(`github:${profile.id}`);
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
			const emails = Array.isArray(raw.emails)
				? (raw.emails as Array<{ value?: unknown; verified?: unknown }>)
				: [];
			const photos = Array.isArray(raw.photos) ? (raw.photos as Array<{ value?: unknown }>) : [];
			const claims: Record<string, unknown> = {};
			if (typeof emails[0]?.value === "string") claims.email = emails[0].value;
			if (typeof emails[0]?.verified === "boolean") claims.emailVerified = emails[0].verified;
			if (typeof raw.displayName === "string") claims.name = raw.displayName;
			if (typeof photos[0]?.value === "string") claims.picture = photos[0].value;
			return claims as MappedClaims;
		},

		async endSession(req: EndSessionRequest): Promise<EndSessionResult> {
			// GitHub has no RP-Initiated Logout endpoint. Return a redirect directly to
			// the post_logout_redirect_uri with round-tripped state. If no redirect is
			// given, fall back to GitHub's top-level logout page.
			const base = req.postLogoutRedirectUri ?? "https://github.com/logout";
			const url = new URL(base);
			if (req.state) url.searchParams.set("state", req.state);
			return { url, method: "GET" };
		},
	};
}

function hasEmail(raw: Record<string, unknown>): boolean {
	return (
		Array.isArray(raw.emails) &&
		raw.emails.some((e) => typeof (e as { value?: unknown }).value === "string")
	);
}
