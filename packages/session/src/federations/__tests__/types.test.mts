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
import { describe, expect, it } from "vitest";
import type { FederationProviderBase, SetupPassportContext } from "#/federations/types.mjs";

describe("FederationProviderBase interface", () => {
	it("requires name, scope, validateRedirect, resolveCallbackRedirect, setupPassportStrategy — no enabled or strategyName", () => {
		// Type-only structural test: the literal must type-check under the new shape.
		const provider: FederationProviderBase = {
			name: "google",
			scope: ["profile", "email"],
			validateRedirect: () => ({ ok: true, value: undefined }),
			resolveCallbackRedirect: () => ({ ok: true, value: "/" }),
			setupPassportStrategy: async () => {
				// noop — signature check only
			},
		};
		expect(provider.name).toBe("google");
		expect(provider.scope).toEqual(["profile", "email"]);
	});

	it("setupPassportStrategy accepts a PassportStatic and SetupPassportContext", () => {
		// Type-only: annotate a function with the expected signature so tsc would fail
		// if setupPassportStrategy's shape were to drift.
		const setup: FederationProviderBase["setupPassportStrategy"] = async (
			_passport: PassportStatic,
			_ctx: SetupPassportContext,
		) => {};
		expect(typeof setup).toBe("function");
	});

	it("SetupPassportContext has verifyUser(externalId): Promise<User | null>", () => {
		const ctx: SetupPassportContext = {
			verifyUser: async (externalId: string) => {
				expect(externalId).toMatch(/^\w+:/);
				return null;
			},
		};
		expect(typeof ctx.verifyUser).toBe("function");
	});

	it("SetupPassportContext has optional pathResolver(spec: string): string", () => {
		const ctx: SetupPassportContext = {
			verifyUser: async () => null,
			pathResolver: (spec) => `/custom/path/${spec}`,
		};
		expect(typeof ctx.pathResolver).toBe("function");
		// biome-ignore lint/style/noNonNullAssertion: pathResolver set above
		expect(ctx.pathResolver!("passport-google-oauth20")).toBe(
			"/custom/path/passport-google-oauth20",
		);
	});
});
