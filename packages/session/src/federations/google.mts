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
import type { FederationProvider, SetupPassportContext } from "./types.mjs";

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
}

export const createGoogleProvider = (config: GoogleProviderConfig): FederationProvider => {
	if (!config.clientId || !config.clientSecret || !config.callbackURL) {
		throw new Error(
			`Google federation "${config.name}" requires clientId, clientSecret, and callbackURL`,
		);
	}

	return {
		name: config.name,
		scope: ["profile", "email"],

		validateRedirect(url: string) {
			return validateRedirect(url, config);
		},

		resolveCallbackRedirect(session: { redirectTo?: string }) {
			// authCallbackUrl and clientUrl are optional (DID-only deployments don't need them).
			// When Google federation is enabled, operators must configure authCallbackUrl
			// if redirect_to flows are used.
			return resolveCallbackRedirect(session, config);
		},

		async setupPassportStrategy(passport, { verifyUser, pathResolver }: SetupPassportContext) {
			const modSpec = pathResolver
				? pathResolver("passport-google-oauth20")
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
					},
					async (_at, _rt, profile, done) => {
						try {
							const user = await verifyUser(`google:${profile.id}`);
							return done(null, user ?? false);
						} catch (err) {
							return done(err as Error);
						}
					},
				),
			);
		},
	};
};
