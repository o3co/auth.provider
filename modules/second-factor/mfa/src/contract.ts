import { contract, extensionPoint } from "@mod/kernel";
import type { AskedFrom, RefusedReason } from "@mod/mfa-extensions";

/** A step where a user proves a factor at login; without one, a factor could never be proven. */
export interface ProofStep {
	readonly name: string;
}

/** The steps that prove factors. mfa refuses to start without at least one. */
export const proofSteps = extensionPoint<ProofStep>("mfa.proof-steps", { multiplicity: "some" });

/** Where a subject's fence stood when read: compared, never computed with. */
export type Fence = number & { readonly __fence: never };

/** Where a subject's standing is asked, as an inconsistency with the witness is recorded. */
export type Asked = "login" | "binding" | "credentials";

/** A factor as the user sees it. */
export interface Shown {
	readonly id: string;
	readonly kind: string;
	readonly label?: string;
}

/** Whether a page can show `text` as a factor's label; `labels` owns the rule. */
export { isLabel } from "@mod/labels";

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

/** Decisions on the subject's factors, whose records and secrets stay with mfa; a binding takes three calls, so the caller can settle its own records in between. */
export interface Factors {
	/** The factors of kinds this deployment knows. */
	held(subject: string): Promise<readonly Shown[]>;
	/**
	 * Whether the subject holds a counting factor, judged against the witness where one is composed: a
	 * subject it marks while holding none is unavailable,
	 * recorded with where it was asked.
	 */
	countingHeld(subject: string, at: Asked): Promise<boolean>;
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
	/** New secret material of a counting kind, sealed for the subject, and what to show once; `passed` and `transaction` go to the gates unread. Asked from a login, it begins only the subject's first counting factor. */
	begin(
		subject: string,
		kind: string,
		passed?: string,
		transaction?: string,
		from?: AskedFrom,
	): Promise<
		| { readonly kind: "begun"; readonly pending: string; readonly show: object }
		| {
				readonly kind:
					| "unknown-kind"
					| "full"
					| "limited"
					| "refused"
					| "duplicate"
					| "binding-proof-required"
					| "first-binding-closed";
		  }
	>;
	/** Judges the first proof of a binding begun; `amr` is what this proof adds, as `prove` answers it. */
	provePending(
		subject: string,
		pending: string,
		proof: string,
	): Promise<
		| { readonly kind: "valid"; readonly state: unknown; readonly amr: readonly string[] }
		| { readonly kind: "invalid" | "unknown" }
	>;
	/** Binds a proved binding, writing no recovery codes: `reissue` writes them. One begun as the first counting factor, or asked from a login, binds only while no other counts by then (`first-binding-closed`). The caller passes `from` as it passed it to `begin`. */
	bind(
		subject: string,
		pending: string,
		state: unknown,
		label?: string,
		from?: AskedFrom,
	): Promise<
		| {
				readonly kind: "bound";
				readonly factor: Shown;
				/** The fence the binding began under, unmoved when it was written: what `reissue` is given. */
				readonly fence: Fence;
				/** True when the subject held no recovery codes once written, and a way back is composed. */
				readonly codesDue: boolean;
		  }
		| {
				readonly kind:
					| "full"
					| "unknown"
					| "malformed-label"
					| "duplicate"
					| "first-binding-closed"
					/** A reset or a fence since the binding began: no factor is written (a witness mark set first may stay). */
					| "fenced";
		  }
	>;
	/** Moves the subject's fence, when asked: no binding begun before binds (`fenced`). */
	fence(subject: string): Promise<void>;
	/** Where the subject's fence stands, read before a change is allowed: given back, the change is `fenced` once it moved. */
	fenceOf(subject: string): Promise<Fence>;
	rename(
		subject: string,
		factor: string,
		label: string,
	): Promise<"renamed" | "unknown" | "malformed-label">;
	/** Under required mode, the last counting factor is not removed; nothing is removed once the fence moved past `fence`. */
	remove(
		subject: string,
		factor: string,
		fence: Fence,
	): Promise<"removed" | "unknown" | "last" | "fenced">;
	/** Removes every factor of the subject, of any kind, and answers how many and of which kinds; nothing is recorded. */
	clear(subject: string): Promise<{ readonly count: number; readonly kinds: readonly string[] }>;
	/** Writes the recovery codes, the first set or replacing the old, for a subject holding a counting factor; nothing once the fence moved past `fence`, and no first set past `max-factors` (`full`). */
	reissue(
		subject: string,
		fence: Fence,
	): Promise<
		| { readonly kind: "reissued"; readonly codes: unknown }
		| { readonly kind: "no-qualifying-factor" | "unknown-kind" | "fenced" | "full" }
	>;
}

export const factors = contract<Factors>("mfa.factors");

/** Who tells, apart from the store, that a subject enrolled: contributed by `mfa-witnessing` where a witness is composed. */
export interface Witnessing {
	/** `held` for a subject holding a counting factor, `none` where nothing marks it either; unavailable, recorded, where a mark stands beside nothing counting. */
	standing(subject: string, counts: boolean, at: Asked): Promise<"held" | "none">;
	/** After a binding's write: brings the mark in line with the counting factors, as `counting` reads them now. */
	settle(subject: string, counting: () => Promise<boolean>): Promise<void>;
	/** After a reset removed every factor: the mark goes. */
	cleared(subject: string): Promise<void>;
}

/** At most one; with none, the store alone tells. */
export const witnessing = extensionPoint<Witnessing>("mfa.witnessing", { multiplicity: "many" });

/** A module holding sessions to the subject's factors: what `mode` asks to use one, and a recent second factor to change credentials. */
export interface Enforcer {
	readonly name: string;
}

/** The modules holding sessions to the factors; mfa refuses to boot without one. */
export const enforcers = extensionPoint<Enforcer>("mfa.enforcers", { multiplicity: "many" });

export * from "./store.ts";
