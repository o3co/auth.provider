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

/**
 * Where a `form_post` federation keeps its transaction: the record's store,
 * taken off the request, and the cookie that addresses it — `HttpOnly`,
 * `Secure`, `SameSite=None`, scoped to the provider's callback path alone.
 */

import type { FederationProvider } from "@o3co/auth-provider-core";
import type { Request, Response } from "express";
import {
	createFederationTransactionStore,
	type FederationTransactionSessionStore,
	type FederationTransactionStore,
} from "../federations/transaction.mjs";

/**
 * The session cookie name assumed when neither
 * `federationTransactionCookieName` nor the configuration's
 * `session-store.name` is given (a router built by hand; the session module
 * passes the name the `sessionCookiePolicy` slot carries): the package
 * default without `__Host-`.
 */
const FALLBACK_SESSION_COOKIE_NAME = "auth.session";

/** Read `session-store.name` without assuming the caller supplied a full configuration. */
export const readSessionCookieName = (config: unknown): string => {
	if (config == null || typeof config !== "object") return FALLBACK_SESSION_COOKIE_NAME;
	const store = (config as { "session-store"?: unknown })["session-store"];
	if (store == null || typeof store !== "object") return FALLBACK_SESSION_COOKIE_NAME;
	const name = (store as { name?: unknown }).name;
	return typeof name === "string" && name.length > 0 ? name : FALLBACK_SESSION_COOKIE_NAME;
};

/** Attributes shared by the `Set-Cookie` that issues the cookie and the one that clears it. */
const transactionCookieAttributes = (path: string) =>
	({
		httpOnly: true,
		// `SameSite=None` is what makes the cookie reach a cross-site POST,
		// and every current browser drops such a cookie unless it is also
		// `Secure`. Apple refuses a non-`https` redirect URI anyway, so a
		// form_post federation is HTTPS-only regardless.
		secure: true,
		sameSite: "none",
		path,
	}) as const;

/** The transaction's store and cookie, as the start writes them and the callback reads and clears them. */
export interface FederationTransactionCookie {
	readonly transactionCookieName: string;
	readonly transactionStore: (req: Request) => FederationTransactionStore | undefined;
	readonly transactionCookiePath: (provider: FederationProvider) => string | undefined;
	readonly transactionCookieAttributes: typeof transactionCookieAttributes;
	readonly clearTransactionCookie: (provider: FederationProvider, res: Response) => void;
}

/** The transaction cookie named `transactionCookieName`, scoped by `providerCallbackUrls`. */
export const createTransactionCookie = (
	providerCallbackUrls: ReadonlyMap<string, string>,
	transactionCookieName: string,
): FederationTransactionCookie => {
	/**
	 * The federation transaction store, over the express-session store the
	 * session middleware mounted (taken off the request, not injected, so it
	 * cannot point elsewhere). Absent means no session middleware — a
	 * composition error the `form_post` start refuses.
	 */
	const transactionStore = (req: Request): FederationTransactionStore | undefined => {
		const store = (req as unknown as { sessionStore?: unknown }).sessionStore;
		if (store == null || typeof store !== "object") return undefined;
		const candidate = store as Partial<FederationTransactionSessionStore>;
		if (
			typeof candidate.get !== "function" ||
			typeof candidate.set !== "function" ||
			typeof candidate.destroy !== "function"
		) {
			return undefined;
		}
		return createFederationTransactionStore(candidate as FederationTransactionSessionStore);
	};

	/**
	 * The path the transaction cookie is scoped to: the provider's callback
	 * route only. A `SameSite=None` cookie rides every cross-site request to a
	 * matching path, so the narrower the better.
	 */
	const transactionCookiePath = (provider: FederationProvider): string | undefined => {
		const callbackUrl = providerCallbackUrls.get(provider.name);
		if (!callbackUrl) return undefined;
		try {
			return new URL(callbackUrl).pathname;
		} catch {
			return undefined;
		}
	};

	/**
	 * Drop the transaction cookie. Called on every callback exit — success,
	 * refusal and error alike — so a consumed or unusable transaction never
	 * leaves a cookie behind for the next attempt to trip over.
	 */
	const clearTransactionCookie = (provider: FederationProvider, res: Response): void => {
		const path = transactionCookiePath(provider);
		if (path === undefined) return;
		res.clearCookie(transactionCookieName, transactionCookieAttributes(path));
	};

	return {
		transactionCookieName,
		transactionStore,
		transactionCookiePath,
		transactionCookieAttributes,
		clearTransactionCookie,
	};
};
