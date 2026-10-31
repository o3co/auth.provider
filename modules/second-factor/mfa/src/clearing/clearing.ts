import type { AfterReset } from "@mod/mfa-extensions";
import type { Shared } from "../shared.ts";
import type { Standing } from "../standing/standing.ts";

/** A reset's clearing of the factors and the witness's mark, and a first binding refused. */
export function clearingWith(
	{ p, records, audited }: Shared,
	{ countsNow, writtenStanding }: Standing,
) {
	/**
	 * What stands after a reset that moved the fence to `moved`: the factors are read before the
	 * fence, and a fence behind `moved` (the record lost or put back since) is judged first, so no
	 * loss between the reads answers `none` or `counting`.
	 */
	const afterReset = (subject: string, moved: number) => async (): Promise<AfterReset> => {
		const written = await writtenStanding(subject);
		if ((await records.fences(subject)) < moved) return "unsure";
		if (written === "counting") return "counting";
		return written === "none" ? "none" : "unsure";
	};
	const settle = async (subject: string) => p.witnessing?.settle(subject, () => countsNow(subject));
	/** A first binding refused, recorded with why; nothing of it is kept. */
	const closed = (subject: string, kind: string, reason: "competing" | "reset-cleared") => {
		audited.record("mfa.first_binding_conflict", { subject, attributes: { kind, reason } });
		return { kind: "first-binding-closed" } as const;
	};
	// Factors first, then the mark: a failure between leaves a mark and no factor, which stops logins.
	const clear = async (subject: string) => {
		// Written even when nothing is held: the fence moves, so no binding begun before it binds.
		const { moved, ...cleared } = await records.decide(subject, (all, fences) => ({
			next: [],
			fence: true,
			verdict: {
				count: all.length,
				kinds: [...new Set(all.map((f) => f.kind))].sort(),
				moved: fences + 1,
			},
		}));
		await p.witnessing?.cleared(subject, afterReset(subject, moved));
		return cleared;
	};
	return { settle, closed, clear };
}

export type Clearing = ReturnType<typeof clearingWith>;
