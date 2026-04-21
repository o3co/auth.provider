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

import { randomUUID } from "node:crypto";
import {
	extractUserClaims,
	type FederationTokenStoreBase,
	type PathResolver,
	type User,
	type UserRepository,
	type UserSessionStoreBase,
} from "@o3co/auth-provider-core";
import type { PassportStatic } from "passport";
import {
	type FederationProfile,
	type FederationProviderBase,
	type SetupPassportContext,
	supportsClaimMapping,
} from "./federations/types.mjs";

declare global {
	namespace Express {
		interface User extends Record<string, unknown> {}
	}
}

export type CreatePassportOptions = {
	pathResolver: PathResolver;
	userRepository: UserRepository;
	federationProviders: ReadonlyMap<string, FederationProviderBase>;
	userSessionStore?: UserSessionStoreBase;
	federationTokenStore?: FederationTokenStoreBase;
	/** Session TTL in milliseconds. Default: 24h. */
	sessionTtlMs?: number;
};

const DEFAULT_SESSION_TTL_MS = 86400_000;

/**
 * Internal implementation — accepts an optional passport override for testing.
 * Not part of the public API; tests import this directly via the `#/` alias.
 */
export const _createPassportImpl = async ({
	pathResolver,
	userRepository,
	federationProviders,
	userSessionStore,
	federationTokenStore,
	sessionTtlMs = DEFAULT_SESSION_TTL_MS,
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

	// Build the built-in onFederationCallback only when BOTH stores are wired.
	// When either store is absent the hook is left undefined so providers fall
	// back to their legacy single-call verifyUser path.
	const onFederationCallback =
		userSessionStore && federationTokenStore
			? async (params: {
					readonly federationName: string;
					readonly profile: FederationProfile;
					readonly req: import("express").Request;
					readonly done: (err: Error | null, user: User | false) => void;
				}) => {
					try {
						const provider = federationProviders.get(params.federationName);
						const mapped =
							provider && supportsClaimMapping(provider) ? provider.mapClaims(params.profile) : {};
						const user = await userRepository.authenticateByToken(
							`${params.federationName}:${params.profile.id}`,
						);
						if (!user) {
							params.done(null, false);
							return;
						}
						const sid = randomUUID();
						const claims = { ...extractUserClaims(user), ...mapped };
						await userSessionStore.create({
							sid,
							sub: user.id,
							authTime: new Date(),
							expiresAt: new Date(Date.now() + sessionTtlMs),
							federations: [params.federationName],
							claims,
						});
						// Post-create operations: any failure here orphans the UserSession,
						// so we roll back with a best-effort delete before calling done(err).
						let attachedToFederation = false;
						try {
							if (params.profile.accessToken) {
								await federationTokenStore.attach(sid, params.federationName, {
									accessToken: params.profile.accessToken,
									refreshToken: params.profile.refreshToken,
									idToken: params.profile.idToken,
									expiresAt: new Date(Date.now() + (params.profile.expiresIn ?? 3600) * 1000),
								});
								attachedToFederation = true;
							}
							const session = params.req.session as unknown as
								| (Record<string, unknown> & {
										save?: (cb: (err: unknown) => void) => void;
								  })
								| undefined;
							if (session) {
								session.sid = sid;
								if (typeof session.save === "function") {
									await new Promise<void>((resolve, reject) => {
										// session.save is guaranteed by the typeof check above; call it.
										(session.save as (cb: (err: unknown) => void) => void)((err) => {
											if (err) reject(err as Error);
											else resolve();
										});
									});
								}
							}
							params.done(null, user);
						} catch (postCreateErr) {
							// Best-effort rollback: delete in REVERSE order of creation.
							// Token first (only if attach succeeded), then UserSession.
							if (attachedToFederation) {
								try {
									await federationTokenStore.delete(sid, params.federationName);
								} catch {
									// ignore
								}
							}
							try {
								await userSessionStore.delete(sid);
							} catch {
								// ignore
							}
							params.done(postCreateErr as Error, false);
						}
					} catch (err) {
						params.done(err as Error, false);
					}
				}
			: undefined;

	// Build the setup context once: verifyUser delegates to userRepository so federation
	// providers don't depend on the repo directly; pathResolver is forwarded for
	// non-standard module layouts (Yarn PnP, custom require hooks).
	const ctx: SetupPassportContext = {
		verifyUser: (externalId: string) => userRepository.authenticateByToken(externalId),
		pathResolver,
		onFederationCallback,
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
