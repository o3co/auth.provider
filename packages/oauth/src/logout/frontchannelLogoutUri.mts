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

import type { Logger, RedirectUriRejection } from "@o3co/auth-provider-core";
import { auditErrorText, checkRedirectUri } from "@o3co/auth-provider-core";

/**
 * Why a front-channel logout URI was not used: a {@link RedirectUriRejection}
 * reason, `not-a-string` for a value of another type, or `unreadable` when
 * reading the field threw.
 */
export type FrontchannelLogoutUriRefusal =
	| RedirectUriRejection["reason"]
	| "not-a-string"
	| "unreadable";

/** Where the URI is used: the code exchange's RP registration, or the logout page. */
export type FrontchannelLogoutUriSite = "authorization_code" | "logout";

/**
 * The front-channel logout URI `read` yields, when it may be used; otherwise
 * `undefined`. Absent (`undefined`, `null`, `""`) is silent. Anything else
 * must be a string `checkRedirectUri` accepts, the whole check: its shape and
 * scheme rules, and its query-name rules, which hold for a URI this server
 * appends parameters to as much as for a redirect target. A refused value is
 * one warn with the reason and never the value.
 *
 * A custom `ClientRepository` or session RP registry bypasses the boot schema,
 * so the value is checked where it is used. Never throws: front-channel
 * logout is best-effort, so a refusal drops only this URI.
 */
export function usableFrontchannelLogoutUri(
	read: () => unknown,
	at: { readonly site: FrontchannelLogoutUriSite; readonly clientId: unknown },
	logger: Pick<Logger, "warn"> | undefined,
): string | undefined {
	const refuse = (reason: FrontchannelLogoutUriRefusal): undefined => {
		logger?.warn(
			{ site: at.site, clientId: auditErrorText(at.clientId), reason },
			"logout_frontchannel_uri_refused",
		);
		return undefined;
	};
	let value: unknown;
	try {
		value = read();
	} catch {
		// The error is not logged: its message could carry the value.
		return refuse("unreadable");
	}
	if (value === undefined || value === null || value === "") return undefined;
	if (typeof value !== "string") return refuse("not-a-string");
	const rejection = checkRedirectUri(value);
	return rejection === null ? value : refuse(rejection.reason);
}
