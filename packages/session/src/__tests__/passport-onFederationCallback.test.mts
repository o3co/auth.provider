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

import type { FederationTokenStoreBase, UserSessionStoreBase } from "@o3co/auth-provider-core";
import { describe, expect, it, vi } from "vitest";
import type { FederationProviderBase, SupportsClaimMapping } from "#/federations/types.mjs";
import { _createPassportImpl } from "#/passport.mjs";

const fakeUser = { id: "u-1", username: "u", email: "existing@x.com" };

function makePassportStub() {
	return {
		use: vi.fn(),
		serializeUser: vi.fn(),
		deserializeUser: vi.fn(),
	} as unknown as import("passport").PassportStatic;
}

function makeUserSessionStore(): UserSessionStoreBase & { _saved: unknown[]; _deleted: string[] } {
	const saved: unknown[] = [];
	const deleted: string[] = [];
	return {
		kind: "memory",
		_saved: saved,
		_deleted: deleted,
		async create(input) {
			saved.push(input);
		},
		async get() {
			return null;
		},
		async registerRP() {},
		async linkFamily() {},
		async updateClaims() {},
		async removeFederation() {},
		async delete(sid: string) {
			deleted.push(sid);
		},
	} as UserSessionStoreBase & { _saved: unknown[]; _deleted: string[] };
}

function makeFederationTokenStore(): FederationTokenStoreBase & {
	_attached: unknown[];
	_deletedPairs: Array<{ sid: string; federationName: string }>;
} {
	const attached: unknown[] = [];
	const deletedPairs: Array<{ sid: string; federationName: string }> = [];
	return {
		kind: "memory",
		_attached: attached,
		_deletedPairs: deletedPairs,
		async attach(sid, name, tokens) {
			attached.push({ sid, name, tokens });
		},
		async get() {
			return null;
		},
		async update() {},
		async deleteBySession() {},
		async delete(sid: string, federationName: string) {
			deletedPairs.push({ sid, federationName });
		},
	} as FederationTokenStoreBase & {
		_attached: unknown[];
		_deletedPairs: Array<{ sid: string; federationName: string }>;
	};
}

type DoneRecord = { err: Error | null; user: unknown; reqSid: unknown };

function makeProvider(
	federationName: string,
	profileOverride: {
		id: string;
		raw?: Record<string, unknown>;
		accessToken?: string;
		refreshToken?: string;
		idToken?: string;
		expiresIn?: number;
	},
	doneResults: DoneRecord[],
	mapClaimsImpl?: (profile: {
		id: string;
		raw: Record<string, unknown>;
	}) => Record<string, unknown>,
): FederationProviderBase & SupportsClaimMapping {
	const reqStub = {
		session: {} as Record<string, unknown>,
	} as unknown as import("express").Request;
	return {
		name: federationName,
		scope: ["openid"],
		validateRedirect: () => ({ ok: true as const, value: undefined }),
		resolveCallbackRedirect: () => ({ ok: true as const, value: "/" }),
		async setupPassportStrategy(_passport, ctx) {
			if (!ctx.onFederationCallback) throw new Error("onFederationCallback hook missing");
			await ctx.onFederationCallback({
				federationName,
				profile: {
					id: profileOverride.id,
					raw: profileOverride.raw ?? {},
					accessToken: profileOverride.accessToken,
					refreshToken: profileOverride.refreshToken,
					idToken: profileOverride.idToken,
					expiresIn: profileOverride.expiresIn,
				},
				req: reqStub,
				done: (err, user) => {
					doneResults.push({
						err,
						user,
						reqSid: (reqStub.session as Record<string, unknown>).sid,
					});
				},
			});
		},
		mapClaims: mapClaimsImpl
			? (profile) => mapClaimsImpl(profile as { id: string; raw: Record<string, unknown> })
			: () => ({}),
	};
}

describe("_createPassportImpl onFederationCallback wiring", () => {
	it("creates UserSession, attaches federation tokens, sets req.session.sid on success", async () => {
		const doneResults: DoneRecord[] = [];
		const us = makeUserSessionStore();
		const ft = makeFederationTokenStore();
		const provider = makeProvider(
			"google",
			{
				id: "gid-1",
				raw: { displayName: "Alice" },
				accessToken: "at",
				refreshToken: "rt",
				idToken: "it",
				expiresIn: 3600,
			},
			doneResults,
			() => ({ name: "Alice", email: "fed@x.com" }),
		);
		const userRepo = {
			authenticate: async () => null,
			authenticateByToken: vi.fn().mockResolvedValue(fakeUser),
		};

		await _createPassportImpl({
			pathResolver: (s) => s,
			userRepository: userRepo as unknown as Parameters<
				typeof _createPassportImpl
			>[0]["userRepository"],
			federationProviders: new Map([["google", provider]]),
			userSessionStore: us,
			federationTokenStore: ft,
			sessionTtlMs: 86400_000,
			_passportOverride: makePassportStub(),
		});

		// UserSession was created
		expect(us._saved).toHaveLength(1);
		const saved = us._saved[0] as {
			sid: string;
			sub: string;
			claims: Record<string, unknown>;
			federations: string[];
		};
		expect(saved.sub).toBe("u-1");
		expect(saved.federations).toEqual(["google"]);
		// federation claims override user claims (spread order: user first, then mapped)
		expect(saved.claims).toMatchObject({ email: "fed@x.com", name: "Alice" });

		// FederationTokens were attached
		expect(ft._attached).toHaveLength(1);
		const at = ft._attached[0] as {
			sid: string;
			name: string;
			tokens: {
				accessToken: string;
				refreshToken: string | undefined;
				idToken: string | undefined;
			};
		};
		expect(at.sid).toBe(saved.sid);
		expect(at.name).toBe("google");
		expect(at.tokens.accessToken).toBe("at");
		expect(at.tokens.refreshToken).toBe("rt");
		expect(at.tokens.idToken).toBe("it");

		// done was called with (null, user)
		expect(doneResults).toHaveLength(1);
		expect(doneResults[0]?.err).toBeNull();
		expect((doneResults[0]?.user as { id: string })?.id).toBe("u-1");

		// req.session.sid was set to the same sid
		expect(doneResults[0]?.reqSid).toBe(saved.sid);
	});

	it("calls done(null, false) and creates no session when verifyUser returns null", async () => {
		const doneResults: DoneRecord[] = [];
		const us = makeUserSessionStore();
		const ft = makeFederationTokenStore();
		const provider = makeProvider("google", { id: "gid-unknown" }, doneResults);
		const userRepo = {
			authenticate: async () => null,
			authenticateByToken: vi.fn().mockResolvedValue(null),
		};

		await _createPassportImpl({
			pathResolver: (s) => s,
			userRepository: userRepo as unknown as Parameters<
				typeof _createPassportImpl
			>[0]["userRepository"],
			federationProviders: new Map([["google", provider]]),
			userSessionStore: us,
			federationTokenStore: ft,
			sessionTtlMs: 86400_000,
			_passportOverride: makePassportStub(),
		});

		expect(doneResults).toHaveLength(1);
		expect(doneResults[0]?.err).toBeNull();
		expect(doneResults[0]?.user).toBe(false);
		expect(us._saved).toHaveLength(0);
		expect(ft._attached).toHaveLength(0);
	});

	it("rejects empty profile.id without calling authenticateByToken or touching stores", async () => {
		const doneResults: DoneRecord[] = [];
		const us = makeUserSessionStore();
		const ft = makeFederationTokenStore();
		const provider = makeProvider("google", { id: "" }, doneResults);
		const authenticateByToken = vi.fn().mockResolvedValue(fakeUser);
		const userRepo = {
			authenticate: async () => null,
			authenticateByToken,
		};

		await _createPassportImpl({
			pathResolver: (s) => s,
			userRepository: userRepo as unknown as Parameters<
				typeof _createPassportImpl
			>[0]["userRepository"],
			federationProviders: new Map([["google", provider]]),
			userSessionStore: us,
			federationTokenStore: ft,
			_passportOverride: makePassportStub(),
		});

		expect(doneResults).toHaveLength(1);
		expect(doneResults[0]?.err).toBeNull();
		expect(doneResults[0]?.user).toBe(false);
		expect(authenticateByToken).not.toHaveBeenCalled();
		expect(us._saved).toHaveLength(0);
		expect(ft._attached).toHaveLength(0);
	});

	it("skips FederationTokenStore.attach when profile has no accessToken", async () => {
		const doneResults: DoneRecord[] = [];
		const us = makeUserSessionStore();
		const ft = makeFederationTokenStore();
		// No accessToken in profile
		const provider = makeProvider("google", { id: "gid-1" }, doneResults);
		const userRepo = {
			authenticate: async () => null,
			authenticateByToken: vi.fn().mockResolvedValue(fakeUser),
		};

		await _createPassportImpl({
			pathResolver: (s) => s,
			userRepository: userRepo as unknown as Parameters<
				typeof _createPassportImpl
			>[0]["userRepository"],
			federationProviders: new Map([["google", provider]]),
			userSessionStore: us,
			federationTokenStore: ft,
			_passportOverride: makePassportStub(),
		});

		expect(us._saved).toHaveLength(1);
		expect(ft._attached).toHaveLength(0);
	});

	it("leaves onFederationCallback undefined when userSessionStore is absent", async () => {
		let receivedCtx: unknown;
		const provider: FederationProviderBase = {
			name: "google",
			scope: ["openid"],
			validateRedirect: () => ({ ok: true as const, value: undefined }),
			resolveCallbackRedirect: () => ({ ok: true as const, value: "/" }),
			async setupPassportStrategy(_passport, ctx) {
				receivedCtx = ctx;
			},
		};
		const ft = makeFederationTokenStore();
		const userRepo = {
			authenticate: async () => null,
			authenticateByToken: vi.fn().mockResolvedValue(null),
		};

		await _createPassportImpl({
			pathResolver: (s) => s,
			userRepository: userRepo as unknown as Parameters<
				typeof _createPassportImpl
			>[0]["userRepository"],
			federationProviders: new Map([["google", provider]]),
			federationTokenStore: ft,
			_passportOverride: makePassportStub(),
		});

		expect(
			(receivedCtx as { onFederationCallback?: unknown })?.onFederationCallback,
		).toBeUndefined();
	});

	it("leaves onFederationCallback undefined when federationTokenStore is absent", async () => {
		let receivedCtx: unknown;
		const provider: FederationProviderBase = {
			name: "google",
			scope: ["openid"],
			validateRedirect: () => ({ ok: true as const, value: undefined }),
			resolveCallbackRedirect: () => ({ ok: true as const, value: "/" }),
			async setupPassportStrategy(_passport, ctx) {
				receivedCtx = ctx;
			},
		};
		const us = makeUserSessionStore();
		const userRepo = {
			authenticate: async () => null,
			authenticateByToken: vi.fn().mockResolvedValue(null),
		};

		await _createPassportImpl({
			pathResolver: (s) => s,
			userRepository: userRepo as unknown as Parameters<
				typeof _createPassportImpl
			>[0]["userRepository"],
			federationProviders: new Map([["google", provider]]),
			userSessionStore: us,
			_passportOverride: makePassportStub(),
		});

		expect(
			(receivedCtx as { onFederationCallback?: unknown })?.onFederationCallback,
		).toBeUndefined();
	});

	it("calls done(err, false) when an internal error is thrown", async () => {
		const doneResults: DoneRecord[] = [];
		const us = makeUserSessionStore();
		const ft = makeFederationTokenStore();
		const provider = makeProvider("google", { id: "gid-1", accessToken: "at" }, doneResults);
		const boom = new Error("db failure");
		const userRepo = {
			authenticate: async () => null,
			authenticateByToken: vi.fn().mockRejectedValue(boom),
		};

		await _createPassportImpl({
			pathResolver: (s) => s,
			userRepository: userRepo as unknown as Parameters<
				typeof _createPassportImpl
			>[0]["userRepository"],
			federationProviders: new Map([["google", provider]]),
			userSessionStore: us,
			federationTokenStore: ft,
			_passportOverride: makePassportStub(),
		});

		expect(doneResults).toHaveLength(1);
		expect(doneResults[0]?.err).toBe(boom);
		expect(doneResults[0]?.user).toBe(false);
	});

	it("rolls back both FederationTokenStore and UserSession when session.save throws after attach", async () => {
		const doneResults: DoneRecord[] = [];
		const us = makeUserSessionStore();
		const ft = makeFederationTokenStore();
		const saveError = new Error("session save failure");
		const provider = makeProvider(
			"google",
			{ id: "gid-save-fail", accessToken: "at" },
			doneResults,
		);
		// Override the req.session provided by makeProvider to have a save() that throws.
		// We do this by injecting a custom provider that passes a session with a failing save().
		const reqStub = {
			session: {
				save(cb: (err: unknown) => void) {
					cb(saveError);
				},
			} as Record<string, unknown>,
		} as unknown as import("express").Request;
		const providerWithFailingSave: typeof provider = {
			...provider,
			async setupPassportStrategy(_passport, ctx) {
				if (!ctx.onFederationCallback) throw new Error("onFederationCallback hook missing");
				await ctx.onFederationCallback({
					federationName: "google",
					profile: {
						id: "gid-save-fail",
						raw: {},
						accessToken: "at",
					},
					req: reqStub,
					done: (err, user) => {
						doneResults.push({
							err,
							user,
							reqSid: (reqStub.session as Record<string, unknown>).sid,
						});
					},
				});
			},
		};
		const userRepo = {
			authenticate: async () => null,
			authenticateByToken: vi.fn().mockResolvedValue(fakeUser),
		};

		await _createPassportImpl({
			pathResolver: (s) => s,
			userRepository: userRepo as unknown as Parameters<
				typeof _createPassportImpl
			>[0]["userRepository"],
			federationProviders: new Map([["google", providerWithFailingSave]]),
			userSessionStore: us,
			federationTokenStore: ft,
			_passportOverride: makePassportStub(),
		});

		// UserSession was created
		expect(us._saved).toHaveLength(1);
		const saved = us._saved[0] as { sid: string };

		// done was called with the save error
		expect(doneResults).toHaveLength(1);
		expect(doneResults[0]?.err).toBe(saveError);
		expect(doneResults[0]?.user).toBe(false);

		// FederationTokenStore entry was deleted (attach succeeded before save failed)
		expect(ft._deletedPairs).toHaveLength(1);
		expect(ft._deletedPairs[0]?.sid).toBe(saved.sid);
		expect(ft._deletedPairs[0]?.federationName).toBe("google");

		// UserSession was also rolled back
		expect(us._deleted).toHaveLength(1);
		expect(us._deleted[0]).toBe(saved.sid);
	});

	it("rolls back UserSession (delete) when federationTokenStore.attach throws post-create", async () => {
		const doneResults: DoneRecord[] = [];
		const us = makeUserSessionStore();
		const attachError = new Error("attach failure");
		const ft: FederationTokenStoreBase & { _attached: unknown[] } = {
			kind: "memory",
			_attached: [],
			async attach() {
				throw attachError;
			},
			async get() {
				return null;
			},
			async update() {},
			async deleteBySession() {},
			async delete() {},
		} as FederationTokenStoreBase & { _attached: unknown[] };

		const provider = makeProvider("google", { id: "gid-rollback", accessToken: "at" }, doneResults);
		const userRepo = {
			authenticate: async () => null,
			authenticateByToken: vi.fn().mockResolvedValue(fakeUser),
		};

		await _createPassportImpl({
			pathResolver: (s) => s,
			userRepository: userRepo as unknown as Parameters<
				typeof _createPassportImpl
			>[0]["userRepository"],
			federationProviders: new Map([["google", provider]]),
			userSessionStore: us,
			federationTokenStore: ft,
			_passportOverride: makePassportStub(),
		});

		// UserSession was created
		expect(us._saved).toHaveLength(1);
		const saved = us._saved[0] as { sid: string };

		// done was called with the attach error
		expect(doneResults).toHaveLength(1);
		expect(doneResults[0]?.err).toBe(attachError);
		expect(doneResults[0]?.user).toBe(false);

		// UserSession was rolled back (delete called with the generated sid)
		expect(us._deleted).toHaveLength(1);
		expect(us._deleted[0]).toBe(saved.sid);
	});
});
