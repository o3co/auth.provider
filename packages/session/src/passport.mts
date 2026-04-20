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

import type { PathResolver, UserRepository } from "@o3co/auth-provider-core";
import type { PassportStatic } from "passport";
import type { FederationProvider, SetupPassportContext } from "./federations/types.mjs";

declare global {
	namespace Express {
		interface User extends Record<string, unknown> {}
	}
}

export type CreatePassportOptions = {
	pathResolver: PathResolver;
	userRepository: UserRepository;
	federationProviders: ReadonlyMap<string, FederationProvider>;
};

/**
 * Internal implementation — accepts an optional passport override for testing.
 * Not part of the public API; tests import this directly via the `#/` alias.
 */
export const _createPassportImpl = async ({
	pathResolver,
	userRepository,
	federationProviders,
	_passportOverride,
}: CreatePassportOptions & {
	/** For testing only — inject a passport stub to skip dynamic import. */
	_passportOverride?: PassportStatic;
}): Promise<PassportStatic> => {
	const passport: PassportStatic =
		_passportOverride ??
		(
			(await import(pathResolver("passport"))) as {
				default: PassportStatic;
			}
		).default;

	const { Strategy: LocalStrategy } = (await import(pathResolver("passport-local"))) as {
		Strategy: new (
			options: { usernameField: string; passwordField: string },
			verify: (
				username: string,
				password: string,
				done: (err: Error | null, user?: unknown, info?: { message: string }) => void,
			) => void,
		) => import("passport").Strategy;
	};

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

	// Build the setup context once: verifyUser delegates to userRepository so federation
	// providers don't depend on the repo directly; pathResolver is forwarded for
	// non-standard module layouts (Yarn PnP, custom require hooks).
	const ctx: SetupPassportContext = {
		verifyUser: (externalId: string) => userRepository.authenticateByToken(externalId),
		pathResolver,
	};

	// Register each enabled federation provider's passport strategy.
	for (const provider of federationProviders.values()) {
		await provider.setupPassportStrategy(passport, ctx);
	}

	return passport;
};

/**
 * Creates and configures a Passport instance with LocalStrategy and all federation strategies.
 *
 * Public API — does not expose test-only options. Tests should use `_createPassportImpl` directly.
 */
export const createPassport = (opts: CreatePassportOptions): Promise<PassportStatic> =>
	_createPassportImpl(opts);
