import { policy } from "@mod/http";
import { contract } from "@mod/kernel";

export interface Window {
	readonly limit: number;
	readonly ms: number;
}

export type Counted =
	| { readonly kind: "allowed" }
	/** `retryAfterMs` is a hint: the store judges the window by its own clock. */
	| { readonly kind: "limited"; readonly retryAfterMs: number };

export interface RateLimit {
	/** Counts one use of `key` in the window `name`; throws Unavailable when it cannot count. */
	hit(name: string, key: string, window: Window): Promise<Counted>;
}

export const rateLimit = contract<RateLimit>("rate-limit");
export const attemptLimit = contract<RateLimit>("rate-limit.attempts");

/**
 * Limits a route's attempts per source, in counts that guard credentials (never evicted, replicated).
 * Over the limit `429` with how long to wait; a source or count it cannot tell, `503`.
 */
export const attemptsPerSource = policy<{ readonly name: string; readonly window: Window }>(
	"rate-limit.attempts-per-source",
);

/** Limits a route's requests per source, in counts not waited on for replicas; answers as attempts do. */
export const requestsPerSource = policy<{ readonly name: string; readonly window: Window }>(
	"rate-limit.requests-per-source",
);

/** The numbers of a lockout; the caller owns them, and `lockoutProblem` judges their shape. */
export interface LockoutPolicy {
	/** Consecutive failures before the first hold. */
	readonly threshold: number;
	readonly backoffMs: number;
	readonly maxBackoffMs: number;
	/** Failures allowed in any window of `budgetWindowMs`. */
	readonly budget: number;
	readonly budgetWindowMs: number;
	/** Failures in one run after which the hold is fixed until released. */
	readonly hardLimit: number;
	/** A run of failures is forgotten after this long without one. */
	readonly memoryMs: number;
}

export type Lockout =
	| { readonly kind: "open" }
	/** `retryAfterMs` is a hint and absent for a fixed hold. */
	| {
			readonly kind: "held";
			readonly hold: "backoff" | "budget" | "hard";
			readonly retryAfterMs?: number;
	  };

/** An open answer carries the reservation to hand back on success, and the hold it starts unless handed back. */
export type Reserved =
	| {
			readonly kind: "open";
			readonly reservation: number;
			readonly holds?: "backoff" | "budget" | "hard";
	  }
	| Extract<Lockout, { kind: "held" }>;

/** As of the store's time: the oldest failure the budget counts, and when the fixed hold began; each absent if none. */
export interface Standing {
	readonly firstFailureAt?: number;
	readonly fixedAt?: number;
}

/** `whole` clears everything; `checked` applies each term only while the key still stands as read. */
export type ReleaseTerms =
	| { readonly kind: "whole" }
	| {
			readonly kind: "checked";
			/** A release with this id is applied once while kept; later calls answer `already`. */
			readonly once: { readonly id: string; readonly keepMs: number };
			/** Clears the budget, and the run unless a fixed hold stays, while the first counted failure is still this one; `{}` while nothing is counted. */
			readonly forgive?: { readonly firstFailureAt?: number };
			/** Lifts the fixed hold and ends its run while the hold is still the one fixed at this time. */
			readonly lift?: { readonly fixedAt: number };
	  };

/** `fixedAt` names a fixed hold still standing after the call; `unchanged` wrote nothing. */
export type Released =
	| {
			readonly kind: "released";
			readonly generation: number;
			readonly cleared: { readonly budget: boolean; readonly run: boolean; readonly hard: boolean };
			readonly fixedAt?: number;
	  }
	| { readonly kind: "already"; readonly generation: number; readonly fixedAt?: number }
	| { readonly kind: "unchanged"; readonly fixedAt?: number };

export interface Lockouts {
	/** Throws Unavailable when it cannot tell. */
	check(name: string, key: string, policy: LockoutPolicy): Promise<Lockout>;
	/** Records a failure, always writing; answers the state it leaves. */
	failed(name: string, key: string, policy: LockoutPolicy): Promise<Lockout>;
	/**
	 * Takes one attempt before a guess is judged, as one write: a key already held stays held and
	 * nothing is counted; otherwise the attempt counts as a failure until `succeeded` hands it back.
	 */
	reserve(name: string, key: string, policy: LockoutPolicy): Promise<Reserved>;
	/** Ends the run of failures, and hands back the attempt reserved for this success, if any. */
	succeeded(name: string, key: string, policy: LockoutPolicy, reservation?: number): Promise<void>;
	/** Hands back an attempt reserved for a guess that was never judged; the run goes on without it. */
	abandoned(name: string, key: string, policy: LockoutPolicy, reservation: number): Promise<void>;
	standing(name: string, key: string, policy: LockoutPolicy): Promise<Standing>;
	/** Releases in one write, judged when written, advancing the generation; the caller decides when that is allowed. */
	releaseUnder(
		name: string,
		key: string,
		policy: LockoutPolicy,
		terms: ReleaseTerms,
	): Promise<Released>;
}

export const lockouts = contract<Lockouts>("rate-limit.lockouts");

/** Why a policy cannot be used, or nothing. */
export function lockoutProblem(policy: LockoutPolicy): string | undefined {
	const { threshold, backoffMs, maxBackoffMs, budget, budgetWindowMs, hardLimit, memoryMs } =
		policy;
	const whole = [threshold, backoffMs, maxBackoffMs, budget, budgetWindowMs, hardLimit, memoryMs];
	if (whole.some((n) => !Number.isInteger(n) || n < 1)) return "every number is a positive integer";
	if (maxBackoffMs < backoffMs) return "the longest hold is shorter than the first";
	if (budget < threshold || hardLimit < budget) {
		return "threshold, budget and hard limit must not decrease";
	}
	if (memoryMs < maxBackoffMs) return "a run is forgotten before its hold ends";
	return undefined;
}

export { sourceKey } from "./source.ts";
