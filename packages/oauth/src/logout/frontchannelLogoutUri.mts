/*
 * Copyright 2026 1o1 Co. Ltd.
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

import type { Logger } from "@o3co/auth-provider-core";
import { auditErrorText } from "@o3co/auth-provider-core";

/**
 * Why a front-channel logout URI was not used: `not-http` for a parsed
 * protocol other than `http:` / `https:`, `unparsable` for a value `URL`
 * cannot parse, `not-a-string` for a value of another type, `unreadable`
 * when reading the field threw.
 */
export type FrontchannelLogoutUriRefusal =
	| "not-http"
	| "unparsable"
	| "not-a-string"
	| "unreadable";

/** Where the URI is used: the code exchange's RP registration, or logout. */
export type FrontchannelLogoutUriSite = "authorization_code" | "logout";

/** What a front-channel logout URI is read from: a client record or a registered RP. */
export interface FrontchannelLogoutUriSource {
	readonly clientId?: unknown;
	readonly frontchannelLogoutUri?: unknown;
}

const HTTP_PROTOCOLS: ReadonlySet<string> = new Set(["http:", "https:"]);

/** `read()`, or `fallback` when the read throws. */
function guardedRead(read: () => unknown, fallback: unknown): unknown {
	try {
		return read();
	} catch {
		return fallback;
	}
}

/** Marks a read that threw, apart from every value a field can hold. */
const UNREADABLE = Symbol("unreadable");

/**
 * The source's front-channel logout URI, when it may be used; otherwise
 * `undefined`. Absent (`undefined`, `null`, `""`) is silent. Anything else
 * must be a string whose parsed protocol is `http:` or `https:`, on any host,
 * the rule the bundled client schema applies at registration. A refused
 * value is one warn with the reason, never the value. Every read and the
 * warn are guarded, so this never throws: front-channel logout is
 * best-effort, so a refusal drops only this URI.
 *
 * Interim: a custom `ClientRepository` or session RP registry bypasses the
 * registration schema, so the value is checked where it is used. Exit
 * condition: core validating every client record at the repository
 * boundary; once it does, the rule moves to core and this helper goes.
 */
export function usableFrontchannelLogoutUri(
	source: FrontchannelLogoutUriSource | null | undefined,
	site: FrontchannelLogoutUriSite,
	logger: Pick<Logger, "warn"> | undefined,
): string | undefined {
	if (source === null || source === undefined) return undefined;
	const refuse = (reason: FrontchannelLogoutUriRefusal): undefined => {
		const clientId = guardedRead(() => source.clientId, undefined);
		try {
			logger?.warn(
				{ site, clientId: auditErrorText(clientId), reason },
				"logout_frontchannel_uri_refused",
			);
		} catch {
			// A logger that throws costs the line, never the caller's flow.
		}
		return undefined;
	};
	// The error is not logged: its message could carry the value.
	const value = guardedRead(() => source.frontchannelLogoutUri, UNREADABLE);
	if (value === UNREADABLE) return refuse("unreadable");
	if (value === undefined || value === null || value === "") return undefined;
	if (typeof value !== "string") return refuse("not-a-string");
	let protocol: string;
	try {
		// Parsed, never prefix-matched: the parser lowercases the scheme and
		// strips tab and newline, as a browser resolving the value does.
		protocol = new URL(value).protocol;
	} catch {
		return refuse("unparsable");
	}
	return HTTP_PROTOCOLS.has(protocol) ? value : refuse("not-http");
}
