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

/*
 * The one reading of an upstream access token's lifetime as an adapter
 * answers it (`expiresIn` / `expiresAt`), and the age of a token already
 * held. Every consumer applies its own policy to the verdict: whether a
 * finite lifetime is required, whether both fields are, and any maximum.
 * Pure: no clock, no I/O, and no throw on any field value.
 */

/** The lifetime fields of an adapter's answer, each as the consumer read it once. */
export interface UpstreamLifetimeFields {
	readonly expiresIn: unknown;
	readonly expiresAt: unknown;
}

export interface UpstreamLifetimeClock {
	/** Epoch ms, taken just before the adapter was asked: an `expiresIn` counts from it. */
	readonly calledAt: number;
	/** Epoch ms, when the answer is read. */
	readonly now: number;
	/** A token with less than this left (ms), or none, is `spent`. The value is the consumer's policy. */
	readonly floorMs: number;
}

export type UpstreamTokenLifetime =
	/** Neither field names a lifetime: each is absent or `null`. */
	| { readonly verdict: "unstated" }
	/** A field is present but names no lifetime, or the instant it derives lies outside the Date range. */
	| { readonly verdict: "malformed" }
	/** One field is `null` (no finite lifetime) and the other names one. */
	| { readonly verdict: "contradictory" }
	/** The derived instant leaves less than `floorMs` after `now`, or nothing. */
	| { readonly verdict: "spent" }
	| {
			readonly verdict: "finite";
			/** Which fields named it. `issuedLifetime` is exactly as issued only when `expiresIn` is among them. */
			readonly stated: "both" | "expiresIn" | "expiresAt";
			/** When the lifetime counts from: never after `calledAt`. */
			readonly obtainedAt: Date;
			/** `obtainedAt` + `issuedLifetime` seconds, to the ms: neither field can lengthen the other. */
			readonly expiresAt: Date;
			/** Seconds, above zero. */
			readonly issuedLifetime: number;
	  };

/** A token already held: when it was obtained and when it ends. */
export interface HeldUpstreamToken {
	readonly obtainedAt: Date;
	readonly expiresAt: Date;
}

export interface HeldUpstreamTokenAge {
	/** `obtainedAt` is a valid instant, before `expiresAt`, and not more than `allowanceMs` ahead of `now`. */
	readonly believed: boolean;
	/** `min(obtainedAt, now)` + lifetime − `now`: no token has more left than it was issued with. 0 when not believed. */
	readonly remainingMs: number;
	/** At least half its lifetime has passed, or it is not believed: before then it is never refreshed. */
	readonly halfSpent: boolean;
}

/** The epoch ms of a real `Date` holding an instant, read by its own value, never through a method it may override. */
const instantOf = (value: unknown): number | undefined => {
	try {
		if (!(value instanceof Date)) return undefined;
		const ms = Date.prototype.getTime.call(value);
		return Number.isNaN(ms) ? undefined : ms;
	} catch {
		return undefined;
	}
};

/** A `Date` for `ms`, or `undefined` outside the Date range (ECMA-262 TimeClip). */
const dateWithin = (ms: number): Date | undefined => {
	const date = new Date(ms);
	return Number.isNaN(date.getTime()) ? undefined : date;
};

/** How one field reads: silent (absent), `null` (no finite lifetime), unusable, or a value. */
type Field<T> = "silent" | "none" | "malformed" | { readonly value: T };

const readExpiresIn = (value: unknown): Field<number> => {
	if (value === undefined) return "silent";
	if (value === null) return "none";
	// Its milliseconds must be finite too: 1e306 s is a finite number of seconds.
	return typeof value === "number" && value > 0 && Number.isFinite(value * 1000)
		? { value }
		: "malformed";
};

const readExpiresAt = (value: unknown): Field<number> => {
	if (value === undefined) return "silent";
	if (value === null) return "none";
	const ms = instantOf(value);
	return ms === undefined ? "malformed" : { value: ms };
};

const assertFiniteInstant = (name: string, value: number): void => {
	if (!Number.isFinite(value)) throw new RangeError(`${name} must be a finite epoch ms`);
};

const assertDuration = (name: string, value: number): void => {
	if (!(Number.isFinite(value) && value >= 0)) {
		throw new RangeError(`${name} must be a finite number of ms, at least 0`);
	}
};

/**
 * Read an adapter's `expiresIn` / `expiresAt`. A finite lifetime is dated
 * from `calledAt`, so time the upstream took is not counted as life left:
 * the derived instant is `min(expiresAt, calledAt + expiresIn)`, and
 * `obtainedAt` is `min(expiresAt − expiresIn, calledAt)`. Throws a
 * `RangeError` only for a clock that is not finite.
 */
export function readUpstreamTokenLifetime(
	fields: UpstreamLifetimeFields,
	clock: UpstreamLifetimeClock,
): UpstreamTokenLifetime {
	assertFiniteInstant("calledAt", clock.calledAt);
	assertFiniteInstant("now", clock.now);
	assertDuration("floorMs", clock.floorMs);

	const expiresIn = readExpiresIn(fields.expiresIn);
	const expiresAt = readExpiresAt(fields.expiresAt);
	if (expiresIn === "malformed" || expiresAt === "malformed") return { verdict: "malformed" };
	const lifetime = typeof expiresIn === "object" ? expiresIn.value : undefined;
	const instant = typeof expiresAt === "object" ? expiresAt.value : undefined;
	if (lifetime === undefined && instant === undefined) return { verdict: "unstated" };
	if (
		(lifetime === undefined && expiresIn === "none") ||
		(instant === undefined && expiresAt === "none")
	) {
		return { verdict: "contradictory" };
	}

	const { calledAt } = clock;
	const lifetimeMs = lifetime === undefined ? undefined : lifetime * 1000;
	const anchor =
		instant !== undefined && lifetimeMs !== undefined ? instant - lifetimeMs : calledAt;
	const obtainedAt = dateWithin(Math.min(anchor, calledAt));
	// The earlier of what each stated field names; an absent one names no bound.
	const derived = dateWithin(
		Math.min(
			instant ?? Number.POSITIVE_INFINITY,
			calledAt + (lifetimeMs ?? Number.POSITIVE_INFINITY),
		),
	);
	if (obtainedAt === undefined || derived === undefined) return { verdict: "malformed" };

	const remainingMs = derived.getTime() - clock.now;
	if (
		remainingMs <= 0 ||
		remainingMs < clock.floorMs ||
		derived.getTime() <= obtainedAt.getTime()
	) {
		return { verdict: "spent" };
	}
	return {
		verdict: "finite",
		stated: lifetime === undefined ? "expiresAt" : instant === undefined ? "expiresIn" : "both",
		obtainedAt,
		expiresAt: derived,
		issuedLifetime: lifetime ?? (derived.getTime() - obtainedAt.getTime()) / 1000,
	};
}

const UNBELIEVED: HeldUpstreamTokenAge = { believed: false, remainingMs: 0, halfSpent: true };

/**
 * The age of a token held since `obtainedAt`. One dated ahead of `now` by
 * up to `allowanceMs` (a refresh buffer, or replicas' clock skew) is
 * believed; one dated further ahead, or not before its own end, is not, and
 * reads as ended. Throws a `RangeError` only for a clock that is not finite.
 */
export function judgeHeldUpstreamToken(
	token: HeldUpstreamToken,
	at: { readonly now: number; readonly allowanceMs: number },
): HeldUpstreamTokenAge {
	assertFiniteInstant("now", at.now);
	assertDuration("allowanceMs", at.allowanceMs);

	const obtainedAt = instantOf(token.obtainedAt);
	const expiresAt = instantOf(token.expiresAt);
	if (obtainedAt === undefined || expiresAt === undefined || obtainedAt >= expiresAt) {
		return UNBELIEVED;
	}
	const age = at.now - obtainedAt;
	if (age < -at.allowanceMs) return UNBELIEVED;
	const lifetimeMs = expiresAt - obtainedAt;
	return {
		believed: true,
		remainingMs: Math.min(obtainedAt, at.now) + lifetimeMs - at.now,
		halfSpent: age >= lifetimeMs / 2,
	};
}
