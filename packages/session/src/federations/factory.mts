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

import { type AdapterFactory, createAdapterFactory } from "@o3co/auth-provider-core";
import { createGithubProvider } from "./github.mjs";
import { createGoogleProvider } from "./google.mjs";
import type { FederationProvider } from "./types.mjs";

export type FederationProviderFactory = AdapterFactory<FederationProvider>;

export function createFederationProviderFactory(): FederationProviderFactory {
	return createAdapterFactory<FederationProvider>("FederationProvider");
}

export function registerBuiltinFederations(factory: FederationProviderFactory): void {
	factory.register("google", async (config) => {
		const name = typeof config.name === "string" ? config.name : undefined;
		const clientId = typeof config.clientId === "string" ? config.clientId : undefined;
		const clientSecret = typeof config.clientSecret === "string" ? config.clientSecret : undefined;
		const callbackURL = typeof config.callbackURL === "string" ? config.callbackURL : undefined;
		if (!name || !clientId || !clientSecret || !callbackURL) {
			throw new Error("Google federation requires name, clientId, clientSecret, and callbackURL");
		}
		const sessionDomain =
			typeof config.sessionDomain === "string" ? config.sessionDomain : undefined;
		const authCallbackUrl =
			typeof config.authCallbackUrl === "string" ? config.authCallbackUrl : undefined;
		const clientUrl = typeof config.clientUrl === "string" ? config.clientUrl : undefined;
		return createGoogleProvider({
			name,
			clientId,
			clientSecret,
			callbackURL,
			sessionDomain,
			authCallbackUrl,
			clientUrl,
		});
	});

	factory.register("github", async (config) => {
		const name = typeof config.name === "string" ? config.name : undefined;
		const clientId = typeof config.clientId === "string" ? config.clientId : undefined;
		const clientSecret = typeof config.clientSecret === "string" ? config.clientSecret : undefined;
		const callbackURL = typeof config.callbackURL === "string" ? config.callbackURL : undefined;
		if (!name || !clientId || !clientSecret || !callbackURL) {
			throw new Error("GitHub federation requires name, clientId, clientSecret, and callbackURL");
		}
		const sessionDomain =
			typeof config.sessionDomain === "string" ? config.sessionDomain : undefined;
		const authCallbackUrl =
			typeof config.authCallbackUrl === "string" ? config.authCallbackUrl : undefined;
		const clientUrl = typeof config.clientUrl === "string" ? config.clientUrl : undefined;
		return createGithubProvider({
			name,
			clientId,
			clientSecret,
			callbackURL,
			sessionDomain,
			authCallbackUrl,
			clientUrl,
		});
	});
}
