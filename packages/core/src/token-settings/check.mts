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

import {
	type AccessTokenLifetimeSource,
	isLifetimeSeconds,
	type RefreshTokenLifetimeSource,
	resolveAccessTokenLifetime,
	resolveRefreshTokenLifetime,
} from "../config/application.schema.mjs";
import { MAX_DURATION_SECONDS } from "../config/durations.mjs";
import { describeValue } from "../errors/describe-value.mjs";
import { checkCanonicalIssuer, describeIssuerRejection } from "../issuer/canonical.mjs";
import type { OAuthTokenSettings } from "./types.mjs";

const WHY =
	"A reader reads every member from the oauthTokenSettings a composition holds, and the " +
	"configuration only when it holds none, so a member the slot lacks or gets wrong is refused " +
	"rather than taken from the configuration beside it (#728).";

/** The value a refusal names: `none` for a member the slot lacks, otherwise its kind. */
const shown = (value: unknown): string => (value === undefined ? "none" : describeValue(value));

const refuse = (member: string, rule: string, value: unknown): never => {
	throw new RangeError(
		`oauthTokenSettings.${member} ${rule}, and the composition's slot carries ${shown(value)}. ${WHY}`,
	);
};

const SWITCHES = ["legacyTypAccept", "resourceIndicatorEnabled", "requireEmailVerified"] as const;

/** A token lifetime a slot names beyond the one core resolves from the configuration. */
export interface LifetimeBeyondConfiguration {
	/** The slot's member, as the contract names it. */
	readonly member: "accessTokenLifetime.maxExpiresIn" | "refreshTokenExpiresIn";
	/** The configuration key core resolves the lifetime from. */
	readonly configKey: "oauth.accessToken.maxExpiresIn" | "oauth.refreshToken.expiresIn";
	/** The slot's lifetime, in seconds. */
	readonly slotSeconds: number;
	/** The lifetime core resolves from the configuration, in seconds. */
	readonly configurationSeconds: number;
}

/** A read of a slot's member that answers `undefined` rather than throwing. */
const readMember = (read: () => unknown): unknown => {
	try {
		return read();
	} catch {
		return undefined;
	}
};

/**
 * The first token lifetime `settings` names beyond the one core resolves
 * from `config` — the access-token maximum, then the refresh-token lifetime —
 * or `undefined` when neither is. A member that is not a number is not
 * compared, and one whose read throws counts as none. The configured
 * lifetimes size retention: the default refresh-token family modules keep a
 * revoked family, and the subject revocation boundary lasts, only that long,
 * and neither reads the slot, so a longer slot lifetime would mint a token
 * that outlives the record revoking it. A configuration that resolves no
 * lifetime is refused by its resolver, naming the key. Internal to core.
 */
export function lifetimeBeyondConfiguration(
	settings: object,
	config: unknown,
): LifetimeBeyondConfiguration | undefined {
	const slot = settings as {
		readonly accessTokenLifetime?: { readonly maxExpiresIn?: unknown } | null;
		readonly refreshTokenExpiresIn?: unknown;
	};
	const members = [
		{
			member: "accessTokenLifetime.maxExpiresIn",
			configKey: "oauth.accessToken.maxExpiresIn",
			slotSeconds: readMember(() => slot.accessTokenLifetime?.maxExpiresIn),
			configured: () =>
				resolveAccessTokenLifetime(config as AccessTokenLifetimeSource).maxExpiresIn,
		},
		{
			member: "refreshTokenExpiresIn",
			configKey: "oauth.refreshToken.expiresIn",
			slotSeconds: readMember(() => slot.refreshTokenExpiresIn),
			configured: () => resolveRefreshTokenLifetime(config as RefreshTokenLifetimeSource),
		},
	] as const;
	for (const { member, configKey, slotSeconds, configured } of members) {
		if (typeof slotSeconds !== "number") continue;
		const configurationSeconds = configured();
		if (slotSeconds > configurationSeconds) {
			return { member, configKey, slotSeconds, configurationSeconds };
		}
	}
	return undefined;
}

/**
 * The refusal of a lifetime beyond the configuration's: the member, both
 * values, the configuration key, and why. `from` names where the slot came
 * from, when the caller knows.
 */
export function lifetimeBeyondConfigurationMessage(
	found: LifetimeBeyondConfiguration,
	from?: string,
): string {
	return (
		`oauthTokenSettings.${found.member} is ${found.slotSeconds} s` +
		`${from === undefined ? "" : ` in the slot from ${from}`}, longer than the ` +
		`${found.configurationSeconds} s core resolves from the configuration (${found.configKey}). ` +
		"That configured lifetime sizes retention — the refresh-token family modules keep a revoked " +
		"family, and the subject revocation boundary lasts, only that long — so a token minted on " +
		"the slot's lifetime would outlive the record that revokes it. Lower the slot's lifetime to " +
		"the configuration's or below, or raise the configuration's."
	);
}

/**
 * A member of a host's value, read once. A read that throws — a getter, a
 * proxy trap — is refused, naming the member, rather than answered.
 */
const readOnce = (member: string, read: () => unknown): unknown => {
	try {
		return read();
	} catch (err) {
		throw new RangeError(
			`oauthTokenSettings.${member} could not be read: reading it threw. ${WHY}`,
			{ cause: err },
		);
	}
};

/**
 * The `oauthTokenSettings` a composition holds, as a snapshot its readers
 * read: each member a reader reads, read from `value` exactly once, held to
 * what its readers read — a canonical issuer, the access-token default and
 * max each a lifetime with the default not above the max, the refresh-token
 * lifetime a lifetime, every switch a boolean, and neither lifetime longer
 * than the one core resolves from `config`, whoever provides the slot — and
 * answered frozen at every level. What is validated is what is answered: a
 * getter that answers otherwise on a later read, or a host that changes its
 * object afterwards, changes nothing a reader holds. A member no reader reads
 * is neither refused nor carried. A `RangeError` names the first member that
 * does not hold, with both values for a lifetime, or whose read throws, or
 * names the slot when it holds no settings object at all.
 */
export function checkOAuthTokenSettings(value: unknown, config: unknown): OAuthTokenSettings {
	if (typeof value !== "object" || value === null || Array.isArray(value)) {
		throw new RangeError(
			`oauthTokenSettings must be the settings object its contract describes, and the composition's slot holds ${shown(value)}. ${WHY}`,
		);
	}
	const slot = value as Record<string, unknown>;
	const issuer = readOnce("issuer", () => slot.issuer);
	const lifetime = readOnce("accessTokenLifetime", () => slot.accessTokenLifetime);
	const lifetimeMembers =
		typeof lifetime === "object" && lifetime !== null
			? (lifetime as Record<string, unknown>)
			: undefined;
	const defaultExpiresIn =
		lifetimeMembers === undefined
			? undefined
			: readOnce("accessTokenLifetime.defaultExpiresIn", () => lifetimeMembers.defaultExpiresIn);
	const maxExpiresIn =
		lifetimeMembers === undefined
			? undefined
			: readOnce("accessTokenLifetime.maxExpiresIn", () => lifetimeMembers.maxExpiresIn);
	const refreshTokenExpiresIn = readOnce("refreshTokenExpiresIn", () => slot.refreshTokenExpiresIn);
	const switches = new Map<(typeof SWITCHES)[number], unknown>(
		SWITCHES.map((name) => [name, readOnce(name, () => slot[name])]),
	);

	const rejection = checkCanonicalIssuer(issuer);
	if (rejection !== null) refuse("issuer", describeIssuerRejection(rejection), issuer);
	if (
		!isLifetimeSeconds(defaultExpiresIn) ||
		!isLifetimeSeconds(maxExpiresIn) ||
		defaultExpiresIn > maxExpiresIn
	) {
		return refuse(
			"accessTokenLifetime",
			`must be a default and a max, each a whole number of seconds from 1 to ${MAX_DURATION_SECONDS}, the default not above the max`,
			lifetime,
		);
	}
	if (!isLifetimeSeconds(refreshTokenExpiresIn)) {
		return refuse(
			"refreshTokenExpiresIn",
			`must be a whole number of seconds from 1 to ${MAX_DURATION_SECONDS}`,
			refreshTokenExpiresIn,
		);
	}
	for (const [name, read] of switches) {
		if (typeof read !== "boolean") refuse(name, "must be true or false", read);
	}

	const snapshot: OAuthTokenSettings = Object.freeze({
		issuer: issuer as string,
		legacyTypAccept: switches.get("legacyTypAccept") as boolean,
		accessTokenLifetime: Object.freeze({ defaultExpiresIn, maxExpiresIn }),
		refreshTokenExpiresIn,
		resourceIndicatorEnabled: switches.get("resourceIndicatorEnabled") as boolean,
		requireEmailVerified: switches.get("requireEmailVerified") as boolean,
	});
	const beyond = lifetimeBeyondConfiguration(snapshot, config);
	if (beyond !== undefined) throw new RangeError(lifetimeBeyondConfigurationMessage(beyond));
	return snapshot;
}
