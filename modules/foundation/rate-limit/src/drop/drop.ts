import { type Eraser, forgottenIn } from "@mod/erasure-extensions";
import type { SubjectLockout } from "../contract.ts";
import { dropped, type LockoutStates, lockoutSpace, parsed } from "../lockout/lockout.ts";

/**
 * rate-limit's eraser: drops a subject's key under each lockout name composed, whatever it held,
 * counting the states it dropped in this run.
 */
export function lockoutEraser(states: LockoutStates, composed: readonly SubjectLockout[]): Eraser {
	const names = composed.map((lockout) => lockout.name).toSorted();
	/** Drops one key; mutate may decide again on a lost race, so the decision written counts. */
	const dropOne = async (name: string, subject: string) => {
		let held = false;
		await states.change(name, subject, (current) => {
			held = parsed(current).kind === "state";
			return { kind: "write", value: dropped, expiry: { kind: "never" } };
		});
		return held ? 1 : 0;
	};
	const dropAll = async (subjects: readonly string[], signal: AbortSignal) => {
		let removed = 0;
		for (const subject of subjects) {
			for (const name of names) {
				signal.throwIfAborted();
				removed += await dropOne(name, subject);
			}
		}
		return { reports: [forgottenIn(lockoutSpace.name, removed)], logoutGaps: 0 };
	};
	return {
		name: "rate-limit",
		erasable: true,
		online: (subject, signal) => dropAll([subject], signal),
		window: (subjects, _walk, signal) => dropAll(subjects, signal),
		migrate: async () => [],
	};
}
