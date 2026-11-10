import type { BoundaryKind, Revocations, SubjectRevocation } from "../contract.ts";

/**
 * A subject's boundaries, opened; `delegations` is absent until a revocation moves it, `erasedAt`
 * until the subject is erased.
 */
export interface Boundaries {
	readonly sessions: number;
	readonly delegations?: number;
	readonly erasedAt?: number;
}

/**
 * The boundaries after a revocation at `now`: a moved kind takes the later time, a kept one stays,
 * and the erasure's mark stays as it was.
 */
export function recorded(
	held: Boundaries | undefined,
	now: number,
	keepDelegations: boolean,
): Boundaries {
	const sessions = Math.max(held?.sessions ?? now, now);
	const delegations = keepDelegations ? held?.delegations : Math.max(held?.delegations ?? now, now);
	return {
		sessions,
		...(delegations === undefined ? {} : { delegations }),
		...(held?.erasedAt === undefined ? {} : { erasedAt: held.erasedAt }),
	};
}

/** Whether something started at `time` holds against the subject's boundaries: an erased subject's nothing does. */
export const comparedTo = (
	held: Boundaries,
	time: number,
	kind: BoundaryKind,
	allowanceMs?: number,
): "valid" | "revoked" =>
	held.erasedAt !== undefined ? "revoked" : compared(time, held[kind], allowanceMs);

/**
 * In seconds: something started in the boundary's own second is revoked too, and up to the
 * allowance after it. An allowance below zero is none; one that is no number revokes. No boundary
 * revokes nothing.
 */
export function compared(
	time: number,
	boundary: number | undefined,
	allowanceMs = 0,
): "valid" | "revoked" {
	if (boundary === undefined) return "valid";
	const widened = boundary + Math.max(0, allowanceMs);
	return Math.floor(time / 1000) > Math.floor(widened / 1000) ? "valid" : "revoked";
}

/** The single-boundary interface, as revocations of both kinds compared with `sessions`. */
export function subjectRevocationOf(revocations: Revocations): SubjectRevocation {
	return {
		revoke: async (subject) => {
			// The single-boundary interface answers nothing; callers that need `complete` use `record`.
			await revocations.record(subject);
		},
		check: (subject, authenticatedAt) => revocations.compare(subject, authenticatedAt, "sessions"),
	};
}
