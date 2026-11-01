import { contract } from "@mod/kernel";
import type { Fence } from "@mod/mfa-reading";

/** What `reissue` answers: the codes, handed once in this answer, or why not. */
export type Reissued =
	| { readonly kind: "reissued"; readonly codes: unknown }
	| { readonly kind: "no-qualifying-factor" | "unknown-kind" | "fenced" | "full" };

/** Managing the subject's factors: naming and removing them, the recovery codes, and the fence. */
export interface FactorManaging {
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
	reissue(subject: string, fence: Fence): Promise<Reissued>;
}

/** Provided by `mfa`. */
export const factorManaging = contract<FactorManaging>("mfa.factor-managing");
