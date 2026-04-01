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
import type { AppConfig } from "#/config/application.schema.mjs";
import type { FederationProvider, FederationResult } from "./types.mjs";

export const createGoogleProvider = (config: AppConfig): FederationProvider => ({
	name: "google",
	strategyName: "google",
	scope: ["profile", "email"],
	enabled: config.federations.google.enabled,

	validateRedirect(url: string): FederationResult<void> {
		if (url.length > 2048) {
			return {
				ok: false,
				status: 400,
				error: "invalid_redirect",
				errorDescription: "Invalid redirect_to",
			};
		}

		let parsed: URL;
		try {
			parsed = new URL(url);
		} catch {
			return {
				ok: false,
				status: 400,
				error: "invalid_redirect",
				errorDescription: "Invalid redirect URL",
			};
		}

		if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
			return {
				ok: false,
				status: 400,
				error: "invalid_redirect",
				errorDescription: "Invalid redirect URL scheme",
			};
		}

		const cookieDomain = config.session.domain;
		if (cookieDomain) {
			const normalizedDomain = cookieDomain.replace(/^\./, "");
			if (
				parsed.hostname !== normalizedDomain &&
				!parsed.hostname.endsWith(`.${normalizedDomain}`)
			) {
				return {
					ok: false,
					status: 400,
					error: "invalid_redirect",
					errorDescription: "Redirect domain not allowed",
				};
			}
		}

		return { ok: true, value: undefined };
	},

	resolveCallbackRedirect(session: { redirectTo?: string }): FederationResult<string> {
		const authCallbackUrl = config.endpoints.authCallback.url;
		if (session.redirectTo && authCallbackUrl) {
			return {
				ok: true,
				value: `${authCallbackUrl}?redirect_to=${encodeURIComponent(session.redirectTo)}`,
			};
		}

		const clientUrl = config.endpoints.client.url;
		if (!clientUrl) {
			return {
				ok: false,
				status: 500,
				error: "misconfiguration",
				errorDescription: "client URL not configured",
			};
		}

		return { ok: true, value: clientUrl };
	},
});
