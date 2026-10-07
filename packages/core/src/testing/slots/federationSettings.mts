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
 * The test double of the `federationSettings` slot:
 * `createTestFederationSettings` builds the map core fills the slot with from
 * the entries a test names; it checks nothing.
 */

import type { ConfiguredFederation, FederationSettings } from "../../federations/settings.mjs";
import { CALLBACK_MEETS_FRESHNESS_DEFAULT } from "../../user-sessions/authentication.mjs";

/** One entry as a test names it: its type, and whatever else it sets. */
export type TestFederationEntry = Pick<ConfiguredFederation, "type"> &
	Partial<Omit<ConfiguredFederation, "type">>;

/**
 * The settings for the entries a test names, in its order, frozen and
 * inheriting nothing; `{}` when it names none. An entry is enabled unless it
 * says otherwise, its upstream `amr` does not count unless it says so, its
 * callback meets a freshness ask as core's default says unless it says
 * otherwise, and an
 * enabled one without a `callbackURL` gets
 * `https://auth.test/session/oauth/federation/<name>/callback`; `issuer` and
 * `clientId` only when given. Only the members of `ConfiguredFederation` are
 * kept.
 */
export function createTestFederationSettings(
	entries: Readonly<Record<string, TestFederationEntry>> = {},
): FederationSettings {
	const settings: Record<string, ConfiguredFederation> = Object.create(null);
	for (const [name, entry] of Object.entries(entries)) {
		const enabled = entry.enabled ?? true;
		const callbackURL =
			entry.callbackURL ??
			(enabled ? `https://auth.test/session/oauth/federation/${name}/callback` : undefined);
		settings[name] = Object.freeze({
			type: entry.type,
			enabled,
			trustsUpstreamAmr: entry.trustsUpstreamAmr ?? false,
			callbackMeetsFreshness: entry.callbackMeetsFreshness ?? CALLBACK_MEETS_FRESHNESS_DEFAULT,
			...(callbackURL === undefined ? {} : { callbackURL }),
			...(entry.issuer === undefined ? {} : { issuer: entry.issuer }),
			...(entry.clientId === undefined ? {} : { clientId: entry.clientId }),
		});
	}
	return Object.freeze(settings);
}
