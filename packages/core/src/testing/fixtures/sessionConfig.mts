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
 * The builders a test sets core's `session` and `federations` sections with,
 * so a test that logs in over plain HTTP, or through a federation, writes
 * neither section by hand.
 */

/** The cookie name a plain-HTTP test client keeps: a `__Host-` name requires `Secure`. */
const INSECURE_SESSION_COOKIE_NAME = "auth.session";

/**
 * A copy of `config` whose session cookie a plain-HTTP client keeps — not
 * `Secure`, and named without the `__Host-` prefix, which requires it —
 * every other key kept; `config` itself is left as it was.
 */
export function withInsecureSessionCookie<C extends { readonly session: object }>(config: C): C {
	return {
		...config,
		session: { ...config.session, name: INSECURE_SESSION_COOKIE_NAME, secure: false },
	};
}

/** What {@link withFederation} writes of one federation: its callback URL, and client credentials a test may name. */
export interface FederationForTests {
	readonly callbackURL: string;
	/** Default `<name>-client`. */
	readonly clientId?: string;
	/** Default `<name>-secret`. */
	readonly clientSecret?: string;
}

/** One enabled federation entry, as {@link withFederation} writes it. */
export interface FederationEntryForTests {
	readonly enabled: true;
	readonly clientId: string;
	readonly clientSecret: string;
	readonly callbackURL: string;
}

/**
 * A copy of `config` whose `federations.<name>` is an enabled entry with
 * `entry`'s callback URL and client credentials, every other federation and
 * key kept; `config` itself is left as it was.
 */
export function withFederation<C extends { readonly federations: object }>(
	config: C,
	name: string,
	entry: FederationForTests,
): C & { readonly federations: Readonly<Record<string, FederationEntryForTests>> } {
	const federation: FederationEntryForTests = {
		enabled: true,
		clientId: entry.clientId ?? `${name}-client`,
		clientSecret: entry.clientSecret ?? `${name}-secret`,
		callbackURL: entry.callbackURL,
	};
	return { ...config, federations: { ...config.federations, [name]: federation } };
}
