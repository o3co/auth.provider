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
 * `federation-grants {}`, the federation-grants module's section, as an
 * operator writes it, turned into what acquisition and retrieval take. Each
 * function takes the section and nothing else, so there is one reading of it.
 *
 * Named functions guard two silent mistakes: seconds forwarded as
 * milliseconds, and a default substituted for a value written wrongly.
 */

import { DEFAULT_SUBJECT_REVOCATION_SKEW_MS } from "../jwt/verify.mjs";
import { FEDERATION_GRANT_LIFETIME_CEILING_MS } from "./lifetime.mjs";
import {
	assertFederationGrantRetrievalLimits,
	type FederationGrantRetrievalLimits,
} from "./retrieve.mjs";
import { FEDERATION_GRANT_ROTATION_BUDGET_DEFAULTS } from "./rotation-budget.mjs";

/**
 * The defaults of the section's settings, in the units an operator writes
 * them. The federation-grants package's `config/reference.conf` ships those
 * it declares.
 *
 * Exported because a hand-built configuration never passes through that file,
 * and a second copy of these numbers inside a module would be the one that is
 * forgotten. `settings.test.mts` reads the section back out of that file and
 * compares what it ships to this, so the two cannot drift.
 */
export const FEDERATION_GRANT_SETTING_DEFAULTS = {
	/** Seconds. Thirty days: what a new grant gets, reserved for acquisition. */
	defaultExpiresIn: 2_592_000,
	/**
	 * Seconds. Thirty days, deliberately NOT the one-year ceiling the code
	 * enforces above it: a security-relevant maximum whose default is the
	 * highest value permitted is the wrong way round, and an operator raises
	 * it on purpose.
	 */
	maxExpiresIn: 2_592_000,
	/** Seconds. A token with no more life than this is refreshed. */
	refreshBuffer: 30,
	/** Seconds. The ceiling on how long a failing upstream is not asked. */
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
	/** Rotations. How many upstream refresh-token rotations a grant may take in a window. */
	rotationBudget: FEDERATION_GRANT_ROTATION_BUDGET_DEFAULTS.limit,
	/** Seconds. The rotation budget's window. */
	rotationWindow: FEDERATION_GRANT_ROTATION_BUDGET_DEFAULTS.windowMs / 1000,
} as const;

/**
 * How far replicas' clocks may differ, for the backstop. Deliberately the
 * same constant `verifyJwt` uses against the same subject watermark, not a
 * separate setting, so the retention guarantee covers one number. Units
 * differ on purpose: consent is compared in milliseconds, JWT claims in
 * truncated seconds.
 */
const FEDERATION_GRANT_REVOCATION_SKEW_MS = DEFAULT_SUBJECT_REVOCATION_SKEW_MS;

/**
 * The keys of `federation-grants {}` these functions read, each as written.
 * All optional: an absent key reads as its default.
 */
export type FederationGrantSettings = Partial<
	Record<keyof typeof FEDERATION_GRANT_SETTING_DEFAULTS | "allowKeepOnSubjectRevocation", unknown>
>;

type Settings = FederationGrantSettings;

/**
 * The largest any of these may be: one year, in the key's unit, and a safe
 * integer for a count. Needed because `assertFederationGrantRetrievalLimits`
 * bounds only timers, and an allowance like `1e21` passes `Number.isInteger`
 * (a refresh buffer that large makes every token look stale for ever).
 */
const MAXIMUM = {
	seconds: 31_536_000,
	milliseconds: 31_536_000_000,
	rotations: Number.MAX_SAFE_INTEGER,
} as const;

/** The unit a key is written in: a count, or a duration its name says the unit of. */
const unitOf = (key: keyof typeof FEDERATION_GRANT_SETTING_DEFAULTS): keyof typeof MAXIMUM =>
	key === "rotationBudget" ? "rotations" : key.endsWith("Ms") ? "milliseconds" : "seconds";

/** A plain decimal, which is the only shape an operator writes a duration in. */
const DECIMAL = /^\d+$/;

/**
 * A whole number an operator wrote, or its default when they wrote
 * nothing. Anything else is refused by name, never replaced by the default.
 *
 * The type is checked before the value because `Number(written)` accepts
 * too much (`null` and `[]` are `0`, `"0x10"` is `16`), and the schema's
 * `z.coerce.number()` reads `null` as `0`: a `refreshBuffer` of `0` would
 * serve tokens with no life left.
 */
function setting(settings: Settings, key: keyof typeof FEDERATION_GRANT_SETTING_DEFAULTS): number {
	const written = settings[key];
	if (written === undefined) return FEDERATION_GRANT_SETTING_DEFAULTS[key];
	const unit = unitOf(key);
	const refuse = (): never => {
		throw new RangeError(
			`federation-grants.${key} must be a whole number of ${unit} no greater than ` +
				`${MAXIMUM[unit]}, and was ${JSON.stringify(written)}`,
		);
	};
	// A number, or the decimal string HOCON substitutes `${?VAR}` as. Nothing
	// else: a value that has to be converted to be understood was not written
	// as a duration.
	const value =
		typeof written === "number"
			? written
			: typeof written === "string" && DECIMAL.test(written.trim())
				? Number(written.trim())
				: Number.NaN;
	if (!Number.isInteger(value) || value < 0 || value > MAXIMUM[unit]) refuse();
	return value;
}

/** The section as the functions read it; an absent one reads as every default. */
const settingsOf = (section: FederationGrantSettings | undefined): Settings => section ?? {};

/** `maxExpiresIn`, in milliseconds, within the ceiling the code enforces above any setting. */
function resolveMaxExpiresInMs(settings: Settings): number {
	const maxExpiresInMs = setting(settings, "maxExpiresIn") * 1000;
	if (maxExpiresInMs <= 0 || maxExpiresInMs > FEDERATION_GRANT_LIFETIME_CEILING_MS) {
		throw new RangeError(
			"federation-grants.maxExpiresIn must be a positive number of seconds no greater than " +
				`${FEDERATION_GRANT_LIFETIME_CEILING_MS / 1000} (one year), the ceiling the code enforces`,
		);
	}
	return maxExpiresInMs;
}

/**
 * The lifetimes acquisition offers, from the section an operator wrote:
 * what a new grant gets, and the most a client may ask for.
 *
 * A default above the maximum is refused, not clamped: lodging clamps a
 * CLIENT's request and says so, but a silently clamped operator default
 * would give every grant a lifetime nobody wrote.
 */
export function resolveFederationGrantAcquisitionLimits(
	section: FederationGrantSettings | undefined,
): {
	readonly defaultLifetimeMs: number;
	readonly maxLifetimeMs: number;
} {
	const settings = settingsOf(section);
	const maxLifetimeMs = resolveMaxExpiresInMs(settings);
	const defaultLifetimeMs = setting(settings, "defaultExpiresIn") * 1000;
	if (defaultLifetimeMs <= 0) {
		throw new RangeError(
			"federation-grants.defaultExpiresIn must be a positive number of seconds: a grant needs a lifetime",
		);
	}
	if (defaultLifetimeMs > maxLifetimeMs) {
		throw new RangeError(
			`federation-grants.defaultExpiresIn (${defaultLifetimeMs / 1000}) must not exceed ` +
				`federation-grants.maxExpiresIn (${maxLifetimeMs / 1000}): a default the maximum cut down ` +
				"would give every grant a lifetime nobody configured",
		);
	}
	return { defaultLifetimeMs, maxLifetimeMs };
}

/**
 * The limits `retrieveFederationGrantToken` takes, from the section an
 * operator wrote. Refuses rather than repairs: the timer relationships are
 * checked by `assertFederationGrantRetrievalLimits` (so a hand-built config
 * meets them too), and the lifetime ceiling here.
 */
export function resolveFederationGrantRetrievalLimits(
	section: FederationGrantSettings | undefined,
): FederationGrantRetrievalLimits {
	const settings = settingsOf(section);
	const maxExpiresInMs = resolveMaxExpiresInMs(settings);
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
		rotationBudget: setting(settings, "rotationBudget"),
		rotationWindowMs: setting(settings, "rotationWindow") * 1000,
	};
	assertFederationGrantRetrievalLimits(limits);
	return limits;
}

/**
 * `federation-grants.allowKeepOnSubjectRevocation`, from the section an
 * operator wrote. Read on its own because `setting` handles durations only.
 *
 * Refuses rather than repairs: an unreadable value must never become `true`.
 * `"false"`, `"0"` and an empty string (an unset HOCON `${?VAR}` chain) read
 * as false; anything else is refused by name.
 */
export function resolveFederationGrantKeepPolicy(
	section: FederationGrantSettings | undefined,
): boolean {
	const written = section?.allowKeepOnSubjectRevocation;
	if (written === undefined) return false;
	if (typeof written === "boolean") return written;
	if (typeof written === "string") {
		const normalized = written.trim().toLowerCase();
		if (normalized === "true" || normalized === "1") return true;
		if (normalized === "false" || normalized === "0" || normalized === "") return false;
	}
	throw new RangeError(
		'federation-grants.allowKeepOnSubjectRevocation must be one of "true", "false", "1" or "0" ' +
			`(an empty value reads as false), and was ${JSON.stringify(written)}`,
	);
}
