import { contract } from "@mod/kernel";
import type { Asked, AskedFrom, RefusedReason } from "@mod/mfa-extensions";

/** Where a subject's fence stood when read: compared across binding and managing, never computed with. */
export type Fence = number & { readonly __fence: never };

/** A factor as the user sees it. */
export interface Shown {
	readonly id: string;
	readonly kind: string;
	readonly label?: string;
}

export type Proved =
	/** `amr` is what this proof adds. */
	| { readonly kind: "valid"; readonly amr: readonly string[] }
	| { readonly kind: "invalid" }
	| { readonly kind: "replayed" }
	/** Right, but the factor changed or went while it was judged: it counts for nothing. */
	| { readonly kind: "raced" };

export type Challenged =
	/** `show` goes to the user unread; `sealed` is kept for the factor's next proof. */
	| {
			readonly kind: "sent";
			readonly factorKind: string;
			readonly show: object;
			readonly sealed: string;
	  }
	/** The factor's kind sends no challenge. */
	| { readonly kind: "none" }
	| { readonly kind: "limited" }
	| { readonly kind: "refused"; readonly factorKind: string; readonly reason?: RefusedReason }
	| { readonly kind: "unknown" };

/** Reading the subject's second factors, and proving one, which updates its state; the records and secrets stay with mfa. */
export interface FactorReading {
	/** The factors of kinds this deployment knows. */
	held(subject: string): Promise<readonly Shown[]>;
	/**
	 * Whether the subject holds a counting factor, judged against the witness where one is composed: a
	 * subject it marks while holding none is unavailable,
	 * recorded with where it was asked.
	 */
	countingHeld(subject: string, at: Asked): Promise<boolean>;
	/** Whether the subject holds a counting factor as written, not judged against the witness. One of a unique value counts once its claim names it, as before that its binding may still end as a duplicate; one written before claims were kept, unless another holds its value. */
	countingWritten(subject: string): Promise<boolean>;
	/** How the subject's factors of a counting kind stand as written, not judged against the witness: `counting` where one counts as `countingWritten` reads it, `unclaimed` where some are written and none counts (a unique value's claim missing or not yet made), `none` where none is written. */
	writtenStanding(subject: string): Promise<"counting" | "unclaimed" | "none">;
	/** How many of the subject's factors of a counting kind are written and do not stand as `countingWritten` reads them (a unique value's claim missing or another's), one beside a factor that stands included. */
	unclaimedWritten(subject: string): Promise<number>;
	/** Whether every session needs a second factor to be used (`mode = required`). */
	secondFactorRequired(): boolean;
	/** What a login asks of the subject: nothing, a proof of a factor, or a first binding. */
	asks(subject: string): Promise<"nothing" | "proof" | "binding">;
	/** Whether guessing can beat this factor; nothing when the subject holds no such factor. */
	guessable(subject: string, factor: string): Promise<boolean | undefined>;
	/** Whether every factor of a guessable kind the subject holds was bound after `after` (epoch ms, kernel's clock); true when it holds none. */
	guessableBoundAfter(subject: string, after: number): Promise<boolean>;
	/** Sends the factor's challenge, good at most until `until` (epoch ms on kernel's clock). */
	challenge(subject: string, factor: string, until: number, from?: AskedFrom): Promise<Challenged>;
	/** Judges a proof, given the sealed challenge kept; the next state is kept only over the state judged. */
	prove(subject: string, factor: string, proof: string, challenge?: string): Promise<Proved>;
}

/** Provided by `mfa`. */
export const factorReading = contract<FactorReading>("mfa.factor-reading");
