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
import type { AppConfig, PathResolver, UserRepository } from "@o3co/auth-provider-core";

declare global {
	namespace Express {
		interface User extends Record<string, unknown> {}
	}
}

export const createPassport = async ({
	pathResolver,
	userRepository,
	config,
}: {
	pathResolver: PathResolver;
	userRepository: UserRepository;
	config: AppConfig;
}): Promise<PassportStatic> => {
	const { default: passport } = (await import(
		pathResolver("passport")
	)) as { default: PassportStatic };

	const { Strategy: LocalStrategy } = (await import(
		pathResolver("passport-local")
	)) as { Strategy: new (
		options: { usernameField: string; passwordField: string },
		verify: (username: string, password: string, done: (err: Error | null, user?: unknown, info?: { message: string }) => void) => void,
	) => import("passport").Strategy };

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

	passport.use(
		new LocalStrategy(
			{ usernameField: "username", passwordField: "password" },
			async (un, ps, done) => {
				try {
					const user = await userRepository.authenticate(un, ps);
					if (!user) {
						return done(null, false, { message: "Incorrect username or password." });
					}
					return done(null, user as Express.User);
				} catch (cause) {
					done(cause as Error);
				}
			},
		),
	);

	if (config.federations.google.enabled) {
		const { Strategy: GoogleStrategy } = await import(
			pathResolver("passport-google-oauth20")
		) as { Strategy: new (
			options: { clientID: string; clientSecret: string; callbackURL: string },
			verify: (accessToken: string, refreshToken: string, profile: { id: string }, done: (err: Error | null, user?: unknown) => void) => void,
		) => import("passport").Strategy };

		passport.use(
			new GoogleStrategy(
				{
					clientID: config.federations.google.clientId ?? "",
					clientSecret: config.federations.google.clientSecret ?? "",
					callbackURL: config.federations.google.callbackURL ?? "",
				},
				async (_accessToken, _refreshToken, profile, done) => {
					try {
						const user = await userRepository.authenticateByToken(`google:${profile.id}`);
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
