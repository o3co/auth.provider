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
 * How a reader holds the `oauthTokenSettings` a composition holds before it
 * reads a member (#728).
 *
 * A reader reads every member from a slot the composition holds, and the
 * configuration only when it holds none: never member by member, which
 * would mix two sources in one reading — the slot's issuer beside the
 * configuration's lifetime. Read that way, a member a host's slot lacks is
 * `undefined`, and for a switch that is a quiet `false`:
 * `requireEmailVerified` off, `legacyTypAccept` left to a validator's
 * default. So the slot is held first to what its readers read — the rules
 * of its contract (`oauthTokenSettingsContract`) for each member — and a
 * member it lacks or gets wrong refuses, naming it.
 *
 * The oauth module's provider keeps the contract, so for it this never
 * refuses; it is there for a slot a host fills by hand. It checks what is
 * read, not what the contract adds for its providers: a member no reader
 * reads is left alone, and whether the value is frozen is the contract's.
 */

import { isLifetimeSeconds } from "../config/application.schema.mjs";
import { MAX_DURATION_SECONDS } from "../config/durations.mjs";
import { checkCanonicalIssuer, describeIssuerRejection } from "../issuer/canonical.mjs";
import type { OAuthTokenSettings } from "./types.mjs";

const WHY =
	"A reader reads every member from the oauthTokenSettings a composition holds, and the " +
	"configuration only when it holds none, so a member the slot lacks or gets wrong is refused " +
	"rather than taken from the configuration beside it (#728).";

const shown = (value: unknown): string =>
	value === undefined ? "none" : (JSON.stringify(value) ?? String(value));

const refuse = (member: string, rule: string, value: unknown): never => {
	throw new RangeError(
		`oauthTokenSettings.${member} ${rule}, and the composition's slot carries ${shown(value)}. ${WHY}`,
	);
};

const SWITCHES = ["legacyTypAccept", "resourceIndicatorEnabled", "requireEmailVerified"] as const;

/**
 * `value`, the `oauthTokenSettings` a composition holds, as it is when it
 * keeps what its readers read: a canonical issuer, the access-token default
 * and max each a lifetime with the default not above the max, the
 * refresh-token lifetime a lifetime, every switch a boolean. A `RangeError`
 * naming the first member that does not, or naming the slot when it holds
 * no settings object at all.
 */
export function checkOAuthTokenSettings(value: unknown): OAuthTokenSettings {
	if (typeof value !== "object" || value === null || Array.isArray(value)) {
		throw new RangeError(
			`oauthTokenSettings must be the settings object its contract describes, and the composition's slot holds ${shown(value)}. ${WHY}`,
		);
	}
	const settings = value as Record<string, unknown>;
	const rejection = checkCanonicalIssuer(settings.issuer);
	if (rejection !== null) refuse("issuer", describeIssuerRejection(rejection), settings.issuer);
	const lifetime = settings.accessTokenLifetime as
		| { readonly defaultExpiresIn?: unknown; readonly maxExpiresIn?: unknown }
		| null
		| undefined;
	if (
		typeof lifetime !== "object" ||
		lifetime === null ||
		!isLifetimeSeconds(lifetime.defaultExpiresIn) ||
		!isLifetimeSeconds(lifetime.maxExpiresIn) ||
		lifetime.defaultExpiresIn > lifetime.maxExpiresIn
	) {
		refuse(
			"accessTokenLifetime",
			`must be a default and a max, each a whole number of seconds from 1 to ${MAX_DURATION_SECONDS}, the default not above the max`,
			lifetime,
		);
	}
	if (!isLifetimeSeconds(settings.refreshTokenExpiresIn)) {
		refuse(
			"refreshTokenExpiresIn",
			`must be a whole number of seconds from 1 to ${MAX_DURATION_SECONDS}`,
			settings.refreshTokenExpiresIn,
		);
	}
	for (const name of SWITCHES) {
		if (typeof settings[name] !== "boolean") refuse(name, "must be true or false", settings[name]);
	}
	return value as OAuthTokenSettings;
}
