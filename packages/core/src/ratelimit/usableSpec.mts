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

import { isStorableLifetime } from "../adapters/expiry.mjs";
import { configuredNumber, shownConfigValue } from "../config/configuredValue.mjs";
import type { RateLimitSpec } from "./types.mjs";

const isPositiveInteger = (value: unknown): value is number =>
	typeof value === "number" && Number.isInteger(value) && value > 0;

/**
 * Whether a value is a spec a limiter can apply as written: a positive whole
 * `limit`, and a positive whole `windowSeconds` that ends within ECMAScript's
 * Date range (core's `isStorableLifetime`).
 *
 * Each refusal is a budget that is not the one written: a zero window
 * (`EXPIRE key 0`, or an in-process bucket reset on every check) never
 * limits; a limit of zero or less denies everything; past the Date range,
 * Redis refuses the `EXPIRE` after its `INCR` has run and an in-process
 * bucket would reset at an Invalid Date.
 */
export const isUsableRateLimitSpec = (value: unknown): value is RateLimitSpec => {
	if (typeof value !== "object" || value === null) return false;
	const { limit, windowSeconds } = value as { limit?: unknown; windowSeconds?: unknown };
	return (
		isPositiveInteger(limit) &&
		isPositiveInteger(windowSeconds) &&
		isStorableLifetime(windowSeconds * 1000)
	);
};

const described = (spec: unknown): string => {
	if (typeof spec !== "object" || spec === null) return shownConfigValue(spec);
	const { limit, windowSeconds } = spec as { limit?: unknown; windowSeconds?: unknown };
	return `limit ${shownConfigValue(limit)}, windowSeconds ${shownConfigValue(windowSeconds)}`;
};

/**
 * The budget a configuration gives under `key`, or a `RangeError` naming
 * `key` when it is given but is not a spec a limiter can apply.
 *
 * For a module that contributes a budget read from its own config key
 * (`oauth.deviceAuthorization.rateLimit`,
 * `webauthn.rateLimit.authenticationOptions`). Each field is read as the key's
 * schema coerces it. A given key, hand-built config included, is refused
 * rather than skipped, since skipping it runs the route on the limiter's
 * default. A key not given is the caller's to handle.
 */
export function requireUsableConfiguredRateLimitSpec(key: string, value: unknown): RateLimitSpec {
	const spec = readConfiguredRateLimitSpec(value);
	if (spec === undefined) {
		throw new RangeError(
			`${key} must be { limit, windowSeconds } as positive whole numbers, with a window that ends within the Date range (got ${described(value)})`,
		);
	}
	return spec;
}

/**
 * A configured `{ limit, windowSeconds }` budget, read as the key's owning
 * schema reads it (`configuredNumber`, so a numeric string is its number)
 * and judged by the one predicate; `undefined` when it is not one a limiter
 * can apply. The adapters' own `limits` take no such reading: their schemas
 * do not coerce, and neither do they.
 */
export const readConfiguredRateLimitSpec = (value: unknown): RateLimitSpec | undefined => {
	if (typeof value !== "object" || value === null) return undefined;
	const { limit, windowSeconds } = value as { limit?: unknown; windowSeconds?: unknown };
	const spec = { limit: configuredNumber(limit), windowSeconds: configuredNumber(windowSeconds) };
	return isUsableRateLimitSpec(spec)
		? { limit: spec.limit, windowSeconds: spec.windowSeconds }
		: undefined;
};

/**
 * Refuses, when a limiter is built, every spec it was given that
 * {@link isUsableRateLimitSpec} does not accept: each entry of `limits`, and
 * `defaultLimit`. `undefined` is "not given", and nothing else is.
 *
 * Refused, never dropped: a dropped spec lets the adapter's looser default
 * apply (on device verification, the budget RFC 8628 §5.1 sizes the user code
 * against). Every adapter calls this, so one configuration is one budget
 * whichever adapter is mounted. The zod schemas refuse the same values at the
 * config boundary; this covers builder paths and hand-built configs.
 */
export function assertUsableRateLimitSpecs(
	who: string,
	specs: { readonly limits?: unknown; readonly defaultLimit?: unknown },
): void {
	const refuse = (name: string, spec: unknown): never => {
		throw new RangeError(
			`${who}: ${name} must be { limit, windowSeconds } as positive whole numbers, with a window that ends within the Date range (got ${described(spec)})`,
		);
	};
	const { limits, defaultLimit } = specs;
	if (limits !== undefined) {
		if (typeof limits !== "object" || limits === null || Array.isArray(limits)) {
			throw new RangeError(
				`${who}: limits must be an object of { limit, windowSeconds } specs, keyed by prefix (got ${Array.isArray(limits) ? "an array" : String(limits)})`,
			);
		}
		for (const [prefix, spec] of Object.entries(limits as Record<string, unknown>)) {
			if (!isUsableRateLimitSpec(spec)) refuse(`limits.${prefix}`, spec);
		}
	}
	if (defaultLimit !== undefined && !isUsableRateLimitSpec(defaultLimit)) {
		refuse("defaultLimit", defaultLimit);
	}
}
