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
 * How long a subject's revocation boundary has to last (#593, D13).
 *
 * There are two boundaries and they are bounded by different things, which is
 * why there are two answers here rather than one number.
 *
 * The **grants** boundary must outlast every grant it could ever cover. What
 * bounds a grant is `FEDERATION_GRANT_LIFETIME_CEILING_MS`, which `activate`
 * enforces at the write — *not* `federationGrants.maxExpiresIn`, which an
 * operator can lower, revoke under, and raise again, resurrecting a grant the
 * revocation was meant to end. So the floor below is a constant derived from a
 * constant, and neither configuration nor a caller can shorten it.
 *
 * The **sessions** boundary must outlast the sessions and tokens a cascade
 * might have missed, and what bounds *those* is configuration — so that one is
 * resolved, not fixed.
 */

import type { SessionCookiePolicy } from "../browser-session/types.mjs";
import {
	type AccessTokenLifetime,
	type AccessTokenLifetimeSource,
	isLifetimeSeconds,
	type RefreshTokenLifetimeSource,
	resolveAccessTokenLifetime,
	resolveRefreshTokenLifetime,
} from "../config/application.schema.mjs";
import { MAX_DURATION_MS, MAX_DURATION_SECONDS } from "../config/durations.mjs";
import { FEDERATION_GRANT_LIFETIME_CEILING_MS } from "../federation-grants/lifetime.mjs";
import { DEFAULT_CLOCK_SKEW_MS, DEFAULT_SUBJECT_REVOCATION_SKEW_MS } from "../jwt/verify.mjs";
import type { OAuthTokenSettings } from "../token-settings/types.mjs";

/**
 * One minute more than the longest grant the code will ever allow.
 *
 * A grant's `expiresAt` is at most `consent.at` plus the ceiling (D3, enforced
 * by `activate`), and a boundary is stamped no earlier than the consent it
 * covers, give or take the comparison's second and the rounding to whole
 * seconds. Both are far inside the minute. So a boundary retained this long
 * outlives every grant it covers, whatever the operator does to the
 * configuration and whether or not the caller passed a grant store.
 *
 * The cost is one small key per revoked subject, for a year.
 */
export const SUBJECT_REVOCATION_MIN_RETENTION_MS = FEDERATION_GRANT_LIFETIME_CEILING_MS + 60_000;

/**
 * Milliseconds an operator configured, or a refusal that names the path. The
 * token lifetimes have resolvers of their own in the configuration schema;
 * this reads what has none, `session.maxAge`.
 */
const lifetimeMs = (value: unknown, path: string): number => {
	const raw = typeof value === "number" ? value : Number.NaN;
	if (!Number.isFinite(raw) || raw <= 0) {
		throw new RangeError(
			`resolveSubjectRevocationHorizonMs: ${path} must be a positive number of ` +
				`milliseconds, and was ${JSON.stringify(value)}. ` +
				"The subject's revocation boundary is sized from it, and one computed from a " +
				"missing lifetime expires while the sessions it covers are still being accepted.",
		);
	}
	return raw;
};

/**
 * The session lifetime a `sessionCookiePolicy` carries, held to the rule the
 * configuration's `session.maxAge` is held to where it is parsed — whole
 * milliseconds from 1 to the one-year ceiling, as the schema and the session
 * store's provider hold it — or a refusal that names the slot's member.
 */
const slotLifetimeMs = (value: unknown, path: string): number => {
	if (
		typeof value !== "number" ||
		!Number.isInteger(value) ||
		value < 1 ||
		value > MAX_DURATION_MS
	) {
		throw new RangeError(
			`resolveSubjectRevocationHorizonMs: ${path} must be a whole number of milliseconds ` +
				`from 1 to ${MAX_DURATION_MS}, and was ${JSON.stringify(value)}. ` +
				"The subject's revocation boundary is sized from it, and one computed from a " +
				"lifetime that is not one expires while the sessions it covers are still accepted.",
		);
	}
	return value;
};

/**
 * Seconds a slot carries, held to the rule the configuration's token lifetimes
 * are (`isLifetimeSeconds`), or a refusal that names the slot's member. A slot
 * a host filled by hand meets no schema either.
 */
const slotLifetimeSeconds = (value: unknown, path: string): number => {
	if (!isLifetimeSeconds(value)) {
		throw new RangeError(
			`resolveSubjectRevocationHorizonMs: ${path} must be a whole number of seconds ` +
				`from 1 to ${MAX_DURATION_SECONDS}, and was ${JSON.stringify(value)}. ` +
				"The subject's revocation boundary is sized from it, and one computed from a " +
				"lifetime that is not one expires while the tokens it covers are still accepted.",
		);
	}
	return value;
};

/**
 * How long a **sessions-only** boundary must be retained, from the lifetimes
 * this deployment is configured with.
 *
 * Three inputs, not two. D13 named the refresh token and the session; the
 * access token belongs here as well, because nothing in the configuration says
 * an access token must be shorter than a refresh token — a deployment is free
 * to invert them, and `verifyJwt` consults the watermark for both.
 *
 * And each is extended by the tolerance with which it is actually accepted,
 * not by its nominal expiry: `verifyJwt` passes `clockTolerance`, so a token is
 * acceptable for `DEFAULT_CLOCK_SKEW_MS` past its `exp`. A boundary sized to
 * the nominal expiry leaves exactly that window with nothing behind it. The
 * revocation comparison's own allowance and a whole second of rounding go on
 * top; neither is the five-minute tolerance, which is a different number for a
 * different comparison.
 *
 * What this cannot know is what was issued *before* an operator lowered these
 * settings. Lowering a lifetime shortens the horizon immediately while the
 * artifacts issued under the old one are still live, so a deployment that
 * lowers one keeps the previous horizon until they have expired. The grants
 * boundary has no such hole, because its floor comes from a ceiling the code
 * enforces rather than from configuration.
 */
export function resolveSubjectRevocationHorizonMs(
	config: unknown,
	/**
	 * The lifetimes as the slots carry them, when the caller holds them
	 * (#728): the oauth module's `oauthTokenSettings` and the session store's
	 * `sessionCookiePolicy`. A slot handed here is read in place of `config`
	 * and held to the rule the configuration's key is held to — a RangeError
	 * naming the slot's member otherwise; a slot not handed is read from
	 * `config`, as before.
	 */
	from: {
		readonly tokenSettings?: Pick<
			OAuthTokenSettings,
			"accessTokenLifetime" | "refreshTokenExpiresIn"
		>;
		readonly sessionCookie?: Pick<SessionCookiePolicy, "maxAgeMs">;
	} = {},
): number {
	const root = config as { session?: { maxAge?: unknown } } | undefined;
	const { tokenSettings, sessionCookie } = from;
	// Through the key's one reader, which holds it to the schema's rule.
	const refreshMs =
		(tokenSettings === undefined
			? resolveRefreshTokenLifetime(config as RefreshTokenLifetimeSource)
			: slotLifetimeSeconds(
					tokenSettings.refreshTokenExpiresIn,
					"oauthTokenSettings.refreshTokenExpiresIn",
				)) * 1000;
	// The MAXIMUM, not the default. `oauth.accessToken.expiresIn` is what a
	// grant mints when the request asks for nothing; token exchange may ask
	// for more, up to `maxExpiresIn`. Sizing the horizon from the default
	// leaves exactly those longer tokens outliving the boundary that revoked
	// them — 60-second defaults beside a one-day maximum would retain the
	// boundary for six minutes. `resolveAccessTokenLifetime` is the one
	// correct reader of that pair, alias and all, and it refuses a value that
	// is not a lifetime rather than letting this compute from one.
	const accessMs =
		(tokenSettings === undefined
			? resolveAccessTokenLifetime(config as AccessTokenLifetimeSource).maxExpiresIn
			: slotLifetimeSeconds(
					(tokenSettings.accessTokenLifetime as Partial<AccessTokenLifetime> | undefined)
						?.maxExpiresIn,
					"oauthTokenSettings.accessTokenLifetime.maxExpiresIn",
				)) * 1000;
	const sessionMs =
		sessionCookie === undefined
			? lifetimeMs(root?.session?.maxAge, "session.maxAge")
			: slotLifetimeMs(sessionCookie.maxAgeMs, "sessionCookiePolicy.maxAgeMs");
	const longest = Math.max(
		sessionMs,
		refreshMs + DEFAULT_CLOCK_SKEW_MS,
		accessMs + DEFAULT_CLOCK_SKEW_MS,
	);
	// The revocation comparison's own allowance, and one whole second for the
	// rounding a caller may have applied to the instant it stamped.
	return longest + DEFAULT_SUBJECT_REVOCATION_SKEW_MS + 1_000;
}
