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
 * `federationGrants.*` as an operator writes it, turned into what the
 * retrieval takes (#593, D3/D10/D12).
 *
 * It lives in core rather than in the routes package because the block is
 * core's — `fullSectionsSchema` declares it, `reference.conf` ships its
 * defaults, and the bundled grant stores read part of it whether the routes
 * are installed or not. A conversion the routes owned would be a second
 * reading of an operator's configuration.
 *
 * Two things a module does wrong here without a symptom, and why this is a
 * function with a name instead of an expression inside a factory:
 *
 *   - seconds forwarded as milliseconds — a thirty-second refresh buffer
 *     becomes thirty milliseconds, and every token is served with no life
 *     left in it;
 *   - a default substituted for a value an operator wrote wrongly, which
 *     turns a typo into a deployment nobody chose.
 */

import { FEDERATION_GRANT_LIFETIME_CEILING_MS } from "./lifetime.mjs";
import {
	assertFederationGrantRetrievalLimits,
	type FederationGrantRetrievalLimits,
} from "./retrieve.mjs";

/**
 * The defaults `config/reference.conf` ships, in the units it writes them.
 *
 * Exported because a hand-built configuration never passes through that file,
 * and a second copy of these numbers inside a module would be the one that is
 * forgotten. `settings.test.mts` reads the block back out of `reference.conf`
 * and compares it to this, so the two cannot drift.
 */
export const FEDERATION_GRANT_SETTING_DEFAULTS = {
	/** Seconds. Thirty days: what a new grant gets (D3), reserved for acquisition. */
	defaultExpiresIn: 2_592_000,
	/**
	 * Seconds. Thirty days, deliberately NOT the one-year ceiling the code
	 * enforces above it: a security-relevant maximum whose default is the
	 * highest value permitted is the wrong way round, and an operator raises
	 * it on purpose.
	 */
	maxExpiresIn: 2_592_000,
	/** Seconds. A token with no more life than this is refreshed (D10). */
	refreshBuffer: 30,
	/** Seconds. The ceiling on how long a failing upstream is not asked (D12). */
	ineligibleRetryAfter: 300,
	/** Seconds. How long a row of failures is honoured for. */
	refreshFailureBackoff: 30,
	/** Milliseconds. The soft deadline: how long a caller waits. */
	upstreamTimeoutMs: 10_000,
	/** Milliseconds. The hard deadline: where the upstream request is aborted. */
	upstreamHardTimeoutMs: 25_000,
	/** Milliseconds. The refresh lock has no renewal, so it must outlive a refresh. */
	refreshLockTtlMs: 30_000,
	/** Milliseconds. How long a call waits for another replica's refresh. */
	lockWaitMs: 5_000,
	/** Milliseconds. How long a refresh keeps trying to write down what it got. */
	persistRetryBudgetMs: 3_000,
	/** Seconds. How long a record answers past the end of what it authorized (D16). */
	tombstoneRetention: 2_592_000,
} as const;

/**
 * How far replicas' clocks may differ, for the backstop (D13).
 *
 * Deliberately not configurable per feature: it is compared against the same
 * subject watermark `verifyJwt` reads, and a second allowance for one
 * comparison is a second number slice 5's retention proof would have to cover.
 * The value is `jwt/verify.mts`'s `DEFAULT_SUBJECT_REVOCATION_SKEW_MS`.
 */
const FEDERATION_GRANT_REVOCATION_SKEW_MS = 1_000;

type Settings = Partial<Record<keyof typeof FEDERATION_GRANT_SETTING_DEFAULTS, unknown>>;

/**
 * A whole number an operator wrote, or the shipped default when they wrote
 * nothing. Anything else is refused by name — never replaced by the default,
 * which is what turns a typo into a deployment.
 */
function setting(settings: Settings, key: keyof typeof FEDERATION_GRANT_SETTING_DEFAULTS): number {
	const written = settings[key];
	if (written === undefined) return FEDERATION_GRANT_SETTING_DEFAULTS[key];
	// `z.coerce` upstream turns `"45"` into 45, but a hand-built config has
	// been through no schema at all, and `Number("soon")` is NaN — which
	// compares as fine against every bound there is.
	const value = typeof written === "number" ? written : Number(written);
	if (!Number.isInteger(value) || value < 0) {
		throw new RangeError(
			`federationGrants.${key} must be a whole number of ${key.endsWith("Ms") ? "milliseconds" : "seconds"}, and was ${JSON.stringify(written)}`,
		);
	}
	return value;
}

/**
 * The limits `retrieveFederationGrantToken` takes, from the configuration an
 * operator wrote.
 *
 * Refuses rather than repairs. `assertFederationGrantRetrievalLimits` carries
 * the relationships between the timers — soft within hard, the lock outliving
 * a refresh and its persistence, the backoff inside the retry interval — and
 * is called here so that a hand-built configuration meets them too (#448).
 * What it does not carry is the grant lifetime ceiling, because that is a
 * lifetime and not a timer, so this checks it.
 */
export function resolveFederationGrantRetrievalLimits(
	config: unknown,
): FederationGrantRetrievalLimits {
	const settings = ((config as { federationGrants?: Settings } | undefined)?.federationGrants ??
		{}) as Settings;
	const maxExpiresInMs = setting(settings, "maxExpiresIn") * 1000;
	if (maxExpiresInMs <= 0 || maxExpiresInMs > FEDERATION_GRANT_LIFETIME_CEILING_MS) {
		throw new RangeError(
			"federationGrants.maxExpiresIn must be a positive number of seconds no greater than " +
				`${FEDERATION_GRANT_LIFETIME_CEILING_MS / 1000} (one year), the ceiling the code enforces`,
		);
	}
	const limits: FederationGrantRetrievalLimits = {
		maxExpiresInMs,
		revocationSkewMs: FEDERATION_GRANT_REVOCATION_SKEW_MS,
		refreshBufferMs: setting(settings, "refreshBuffer") * 1000,
		ineligibleRetryAfterMs: setting(settings, "ineligibleRetryAfter") * 1000,
		refreshFailureBackoffMs: setting(settings, "refreshFailureBackoff") * 1000,
		upstreamTimeoutMs: setting(settings, "upstreamTimeoutMs"),
		upstreamHardTimeoutMs: setting(settings, "upstreamHardTimeoutMs"),
		refreshLockTtlMs: setting(settings, "refreshLockTtlMs"),
		lockWaitMs: setting(settings, "lockWaitMs"),
		persistRetryBudgetMs: setting(settings, "persistRetryBudgetMs"),
	};
	assertFederationGrantRetrievalLimits(limits);
	return limits;
}
