/*
 * Copyright 2026 1o1 Inc.
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
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as ClientCredentialStrategy } from "passport-oauth2-client-password";

import type { AppConfig } from "../config/application.schema.mjs";
import type { AppClient } from "./clients/Client.mjs";
import type { ClientFactory } from "./clients/ClientFactory.mjs";
import type { UserClient } from "./clients/User.mjs";

declare global {
	namespace Express {
		interface User extends Record<string, unknown> {}
	}
}

export const createPassport = async ({
	clients,
	config,
}: {
	clients: ClientFactory;
	config: AppConfig;
}): Promise<typeof passport> => {
	passport.serializeUser((user: Express.User, done) => {
		done(null, JSON.stringify(user));
	});

	passport.deserializeUser(async (data: string, done) => {
		try {
			done(null, JSON.parse(data) as Express.User);
		} catch (cause) {
			done(cause as Error);
		}
	});

	passport
		.use(
			new LocalStrategy(
				{
					usernameField: "username",
					passwordField: "password",
				},
				async (un, ps, done) => {
					try {
						const user = await (clients.get("User") as UserClient).authenticate({
							username: un,
							password: ps,
						});

						if (!user) {
							return done(null, false, {
								message: "Incorrect username or password.",
							});
						}

						return done(null, user as Express.User);
					} catch (cause) {
						done(cause as Error);
					}
				},
			),
		)
		.use(
			new ClientCredentialStrategy(async (clientId, clientSecret, done) => {
				try {
					const client = await (clients.get("Client") as AppClient).authenticate({
						clientId,
						password: clientSecret,
					});

					if (!client) {
						return done(null, false);
					}
					return done(null, client as Express.User);
				} catch (cause) {
					return done(cause as Error);
				}
			}),
		);

	if (config.federations.google.enabled) {
		passport.use(
			new GoogleStrategy(
				{
					clientID: config.federations.google.clientId ?? "",
					clientSecret: config.federations.google.clientSecret ?? "",
					callbackURL: config.federations.google.callbackURL ?? "",
				},
				async (_accessToken, _refreshToken, profile, done) => {
					try {
						const user = await (clients.get("User") as UserClient).authenticateByToken(
							`google:${profile.id}`,
						);
						return done(null, user as Express.User);
					} catch (cause) {
						return done(cause as Error);
					}
				},
			),
		);
	}

	return passport;
};
