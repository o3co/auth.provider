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

import type { UserRepository } from "@o3co/auth-provider-core";
import { describe, expect, it, vi } from "vitest";
import type { FederationProvider } from "#/federations/types.mjs";
import { createPassport } from "#/passport.mjs";

/** Minimal passport stub that tracks strategy registrations. */
function makePassportStub() {
	const strategies: Array<{ name: string }> = [];
	const stub = {
		use: vi.fn((_nameOrStrategy: unknown, _strategy?: unknown) => {
			if (typeof _nameOrStrategy === "string" && _strategy) {
				strategies.push({ name: _nameOrStrategy });
			}
			return stub;
		}),
		serializeUser: vi.fn(),
		deserializeUser: vi.fn(),
		_strategies: strategies,
	};
	return stub;
}

function makeFederationProvider(name: string): FederationProvider {
	return {
		name,
		scope: ["profile"],
		validateRedirect: vi.fn().mockReturnValue({ ok: true, value: undefined }),
		resolveCallbackRedirect: vi.fn().mockReturnValue({ ok: true, value: "/" }),
		setupPassportStrategy: vi.fn().mockResolvedValue(undefined),
	};
}

describe("createPassport", () => {
	it("calls setupPassportStrategy on each provider in federationProviders Map", async () => {
		const passportStub = makePassportStub();
		const userRepository: UserRepository = {
			authenticate: vi.fn(),
			authenticateByToken: vi.fn().mockResolvedValue(null),
		} as unknown as UserRepository;

		const providerA = makeFederationProvider("google");
		const providerB = makeFederationProvider("github");
		const federationProviders: ReadonlyMap<string, FederationProvider> = new Map([
			["google", providerA],
			["github", providerB],
		]);

		// pathResolver returns a stub that yields our passportStub
		const pathResolver = vi.fn((name: string) => name);

		await createPassport({
			pathResolver,
			userRepository,
			federationProviders,
			_passportOverride: passportStub as unknown as import("passport").PassportStatic,
		});

		expect(providerA.setupPassportStrategy).toHaveBeenCalledTimes(1);
		expect(providerB.setupPassportStrategy).toHaveBeenCalledTimes(1);
	});

	it("verifyUser delegates to userRepository.authenticateByToken", async () => {
		const passportStub = makePassportStub();
		const authenticateByToken = vi.fn().mockResolvedValue({ id: "u1" });
		const userRepository: UserRepository = {
			authenticate: vi.fn(),
			authenticateByToken,
		} as unknown as UserRepository;

		let capturedVerifyUser: ((id: string) => Promise<unknown>) | undefined;
		const provider = makeFederationProvider("google");
		(provider.setupPassportStrategy as ReturnType<typeof vi.fn>).mockImplementation(
			async (_passport: unknown, ctx: { verifyUser: (id: string) => Promise<unknown> }) => {
				capturedVerifyUser = ctx.verifyUser;
			},
		);

		const federationProviders: ReadonlyMap<string, FederationProvider> = new Map([
			["google", provider],
		]);

		await createPassport({
			pathResolver: vi.fn((name: string) => name),
			userRepository,
			federationProviders,
			_passportOverride: passportStub as unknown as import("passport").PassportStatic,
		});

		expect(capturedVerifyUser).toBeDefined();
		// biome-ignore lint/style/noNonNullAssertion: asserted defined on line above
		await capturedVerifyUser!("google:abc123");
		expect(authenticateByToken).toHaveBeenCalledWith("google:abc123");
	});

	it("propagates pathResolver into each provider's setupPassportStrategy ctx", async () => {
		const passportStub = makePassportStub();
		const userRepository: UserRepository = {
			authenticate: vi.fn(),
			authenticateByToken: vi.fn().mockResolvedValue(null),
		} as unknown as UserRepository;

		let capturedCtx: { pathResolver?: (spec: string) => string } | undefined;
		const provider = makeFederationProvider("google");
		(provider.setupPassportStrategy as ReturnType<typeof vi.fn>).mockImplementation(
			async (_passport: unknown, ctx: { pathResolver?: (spec: string) => string }) => {
				capturedCtx = ctx;
			},
		);

		// Identity resolver: records calls but returns spec unchanged so passport-local
		// and other internal imports resolve normally. We only need to verify the same
		// resolver reference reaches the provider ctx.
		const identityPathResolver = vi.fn((spec: string) => spec);

		await createPassport({
			pathResolver: identityPathResolver,
			userRepository,
			federationProviders: new Map([["google", provider]]),
			_passportOverride: passportStub as unknown as import("passport").PassportStatic,
		});

		expect(capturedCtx).toBeDefined();
		expect(capturedCtx?.pathResolver).toBe(identityPathResolver);
	});

	it("uses an empty Map when no federationProviders are given", async () => {
		const passportStub = makePassportStub();
		const userRepository: UserRepository = {
			authenticate: vi.fn(),
			authenticateByToken: vi.fn().mockResolvedValue(null),
		} as unknown as UserRepository;

		// Should not throw with empty map
		await expect(
			createPassport({
				pathResolver: vi.fn((name: string) => name),
				userRepository,
				federationProviders: new Map(),
				_passportOverride: passportStub as unknown as import("passport").PassportStatic,
			}),
		).resolves.toBeDefined();
	});
});
