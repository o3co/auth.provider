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

import type { FederationResult } from "./types.mjs";

/**
 * Shared config shape for federation providers that support redirect validation
 * and callback redirect resolution.
 */
export interface RedirectConfig {
	sessionDomain?: string;
	authCallbackUrl?: string;
	clientUrl?: string;
}

/**
 * Validates that the given URL is acceptable as a post-login redirect target.
 *
 * Rules:
 * - Must be ≤ 2048 characters.
 * - Must be a valid absolute URL with http: or https: scheme.
 * - If `sessionDomain` is configured, the URL hostname must match or be a
 *   subdomain of the normalised domain (leading dot stripped).
 */
export function validateRedirect(
	url: string,
	config: Pick<RedirectConfig, "sessionDomain">,
): FederationResult<void> {
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

	const cookieDomain = config.sessionDomain;
	if (cookieDomain) {
		const normalizedDomain = cookieDomain.replace(/^\./, "");
		if (parsed.hostname !== normalizedDomain && !parsed.hostname.endsWith(`.${normalizedDomain}`)) {
			return {
				ok: false,
				status: 400,
				error: "invalid_redirect",
				errorDescription: "Redirect domain not allowed",
			};
		}
	}

	return { ok: true, value: undefined };
}

/**
 * Resolves the post-login redirect URL from the session state.
 *
 * - If session has `redirectTo` and `authCallbackUrl` is configured, returns
 *   `authCallbackUrl?redirect_to=<encoded redirectTo>`.
 * - If session has `redirectTo` but `authCallbackUrl` is absent, returns a
 *   misconfiguration error.
 * - If no `redirectTo`, returns `clientUrl` (or a misconfiguration error when
 *   `clientUrl` is also absent).
 */
export function resolveCallbackRedirect(
	session: { redirectTo?: string },
	config: Pick<RedirectConfig, "authCallbackUrl" | "clientUrl">,
): FederationResult<string> {
	const authCallbackUrl = config.authCallbackUrl;
	if (session.redirectTo && authCallbackUrl) {
		return {
			ok: true,
			value: `${authCallbackUrl}?redirect_to=${encodeURIComponent(session.redirectTo)}`,
		};
	}

	if (session.redirectTo && !authCallbackUrl) {
		return {
			ok: false,
			status: 500,
			error: "misconfiguration",
			errorDescription: "authCallback URL not configured but redirect_to was requested",
		};
	}

	const clientUrl = config.clientUrl;
	if (!clientUrl) {
		return {
			ok: false,
			status: 500,
			error: "misconfiguration",
			errorDescription: "client URL not configured",
		};
	}

	return { ok: true, value: clientUrl };
}

export interface GithubEmailResult {
	readonly email: string;
	readonly verified: boolean;
}

/**
 * Fetches the authenticated user's email list from the GitHub REST API and
 * returns the primary verified email (or first verified if no primary is set).
 * Used by the GitHub federation provider's claim mapping — the passport profile
 * does not carry email for most users because they keep it private.
 *
 * Non-2xx responses resolve to null (consumer treats as "no email available"),
 * never throw, so a transient GitHub API failure does not kill federation login.
 *
 * Requires `user:email` scope, which the built-in GitHub provider already requests.
 */
export async function fetchGithubPrimaryEmail(
	accessToken: string,
	fetchImpl: typeof fetch = fetch,
): Promise<GithubEmailResult | null> {
	const timeoutMs = 10_000;
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), timeoutMs);
	try {
		const res = await fetchImpl("https://api.github.com/user/emails", {
			headers: {
				Authorization: `Bearer ${accessToken}`,
				"User-Agent": "o3co-auth-provider",
				Accept: "application/vnd.github+json",
			},
			signal: controller.signal,
		});
		if (!res.ok) return null;
		const rows = (await res.json()) as Array<{
			email?: unknown;
			primary?: unknown;
			verified?: unknown;
		}>;
		if (!Array.isArray(rows)) return null;
		const verified = rows.filter((r) => r.verified === true && typeof r.email === "string");
		const primary = verified.find((r) => r.primary === true);
		const chosen = primary ?? verified[0];
		if (!chosen || typeof chosen.email !== "string") return null;
		return { email: chosen.email, verified: true };
	} catch {
		// Abort (timeout) and any other transient error treated as "no email available".
		return null;
	} finally {
		clearTimeout(timer);
	}
}
