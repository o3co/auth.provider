import { contract } from "@mod/kernel";
import type { AskedFrom } from "@mod/mfa-extensions";
import type { Fence, Shown } from "@mod/mfa-reading";

/** What `begin` answers: begun with what to show once, or why not. */
export type Begun =
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
	  };

/** What `provePending` answers. */
export type PendingProved =
	| { readonly kind: "valid"; readonly state: unknown; readonly amr: readonly string[] }
	| { readonly kind: "invalid" | "unknown" };

/** What `bind` answers. */
export type Bound =
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
	  };

/** Binding a new second factor: a binding takes three calls, so the caller can settle its own records in between. */
export interface FactorBinding {
	/** New secret material of a counting kind, sealed for the subject, and what to show once; `passed` and `transaction` go to the gates unread. Asked from a login, it begins only the subject's first counting factor. */
	begin(
		subject: string,
		kind: string,
		passed?: string,
		transaction?: string,
		from?: AskedFrom,
	): Promise<Begun>;
	/** Judges the first proof of a binding begun; `amr` is what this proof adds, as `prove` answers it. */
	provePending(subject: string, pending: string, proof: string): Promise<PendingProved>;
	/** Binds a proved binding, writing no recovery codes: `reissue` writes them. One begun as the first counting factor, or asked from a login, binds only while no other counts by then (`first-binding-closed`). The caller passes `from` as it passed it to `begin`. */
	bind(
		subject: string,
		pending: string,
		state: unknown,
		label?: string,
		from?: AskedFrom,
	): Promise<Bound>;
}

/** Provided by `mfa`. */
export const factorBinding = contract<FactorBinding>("mfa.factor-binding");
