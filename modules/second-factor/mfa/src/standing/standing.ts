import type { Asked } from "@mod/mfa-extensions";
import type { Factor } from "../records/records.ts";
import { counting, type Shared } from "../shared.ts";

/** Whether a subject's counting factors stand: as the witness tells it, and each by its claim. */
export function standingWith({ p, records, secretOf }: Shared) {
	const standing = async (subject: string, counts: boolean, at: Asked) =>
		p.witnessing
			? p.witnessing.standing(subject, counts, at)
			: counts
				? ("held" as const)
				: ("none" as const);
	/**
	 * A counting factor with a unique value counts while its claim names it: one 0.18 left without its
	 * claim may yet be another's. One written before claims were kept counts unless another holds it.
	 */
	const stands = async (subject: string, factor: Factor) => {
		const unique = p.kinds
			.get(factor.kind)
			?.uniqueSecret?.({ secret: secretOf(subject, factor), state: factor.state });
		if (unique === undefined) return true;
		if (await records.claimedFor(subject, factor.kind, unique, factor.id)) return true;
		if (factor.claims) return false;
		return !(await records.heldByAnother(subject, factor.kind, unique, factor.id));
	};
	/** The ids of the subject's counting factors that stand, as `stands` reads them. */
	const standingIds = async (subject: string) => {
		const ids = new Set<string>();
		for (const factor of counting(await records.list(subject), p.kinds)) {
			if (await stands(subject, factor)) ids.add(factor.id);
		}
		return ids;
	};
	const countsNow = async (subject: string) => (await standingIds(subject)).size > 0;
	/** Whether a factor of a counting kind is written and stands, is written and none stands, or none is written. */
	const writtenStanding = async (subject: string) => {
		const written = counting(await records.list(subject), p.kinds);
		if (written.length === 0) return "none" as const;
		for (const factor of written) if (await stands(subject, factor)) return "counting" as const;
		return "unclaimed" as const;
	};
	const unclaimedWritten = async (subject: string) => {
		let left = 0;
		for (const factor of counting(await records.list(subject), p.kinds)) {
			if (!(await stands(subject, factor))) left += 1;
		}
		return left;
	};
	return { standing, standingIds, countsNow, writtenStanding, unclaimedWritten };
}

export type Standing = ReturnType<typeof standingWith>;
