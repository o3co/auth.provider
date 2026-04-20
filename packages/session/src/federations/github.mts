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
import { resolveCallbackRedirect, validateRedirect } from "./helpers.mjs";
import type { FederationProvider, VerifyUserContext } from "./types.mjs";

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
}

export function createGithubProvider(config: GithubProviderConfig): FederationProvider {
	if (!config.clientId || !config.clientSecret || !config.callbackURL) {
		throw new Error(
			`GitHub federation "${config.name}" requires clientId, clientSecret, and callbackURL`,
		);
	}

	const scope = ["read:user", "user:email"] as const;

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
			{ verifyUser }: VerifyUserContext,
		): Promise<void> {
			let GithubStrategy: typeof import("passport-github2").Strategy;
			try {
				({ Strategy: GithubStrategy } = await import("passport-github2"));
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
					},
					async (
						_at: string,
						_rt: string,
						profile: { id: string },
						done: (err: Error | null, user?: unknown) => void,
					) => {
						try {
							const user = await verifyUser(`github:${profile.id}`);
							return done(null, user ?? false);
						} catch (err) {
							return done(err as Error);
						}
					},
				),
			);
		},
	};
}
