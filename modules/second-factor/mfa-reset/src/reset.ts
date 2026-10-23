import { type Audit, declaredAudit } from "@mod/audit";
import { isUnavailable, type Log, Unavailable } from "@mod/kernel";
import type { FactorManaging } from "@mod/mfa-managing";
import type { LockoutPolicy, Lockouts } from "@mod/rate-limit";
import type { Revocations } from "@mod/subject-revocation";
import events from "./audit-events.ts";
import type { MfaReset, Removed, ResetOutcome } from "./contract.ts";

export interface ResetParts {
	readonly factors: Pick<FactorManaging, "clear">;
	readonly revocations: Pick<Revocations, "record">;
	readonly lockouts: Pick<Lockouts, "releaseUnder">;
	/** `mfa-flows`' lockout: its name and policy. */
	readonly lockout: { readonly name: string; readonly policy: LockoutPolicy };
	readonly audit: Pick<Audit, "record">;
	readonly log: Log;
}

/** The step a run stopped at: a boundary, the factors' removal, or the lockout's release. */
type Stop = "sessions" | "factors" | "lock";

const wellFormed = (text: unknown, max = Number.POSITIVE_INFINITY): text is string =>
	typeof text === "string" && text.length > 0 && text.length <= max && text.isWellFormed();
const typeOf = (error: unknown) => (error instanceof Error ? error.name : typeof error);

/**
 * What a run did: what the factors' removal answered, if it ran, the first failure, if any, and the
 * first failure that is not unavailable, if any, whichever step it came at.
 */
interface Ran {
	readonly cleared: Removed | undefined;
	readonly failure: { readonly at: Stop; readonly error: unknown } | undefined;
	readonly fault: { readonly error: unknown } | undefined;
}

export function resetOver(p: ResetParts): MfaReset {
	/** Runs every step it can, recording and logging how it went. */
	const attempt = async (
		subject: string,
		options: { readonly requestedBy?: string },
	): Promise<Ran> => {
		const { requestedBy } = options;
		if (!wellFormed(subject)) throw new RangeError("subject");
		if (requestedBy !== undefined && !wellFormed(requestedBy, 256)) {
			throw new RangeError("requestedBy");
		}
		let failure: { readonly at: Stop; readonly error: unknown } | undefined;
		let fault: { readonly error: unknown } | undefined;
		/** Runs a step; the first failure, and the first not unavailable, are kept, and the step answers none. */
		const step = async <T>(at: Stop, run: () => Promise<T>): Promise<T | undefined> => {
			try {
				return await run();
			} catch (error) {
				failure ??= { at, error };
				if (!isUnavailable(error)) fault ??= { error };
				return undefined;
			}
		};
		const endSessions = async () =>
			(await step("sessions", async () => {
				const { complete } = await p.revocations.record(subject, { keepDelegations: true });
				// The boundary moved, but a session still open would outlive the reset.
				if (!complete) throw new Unavailable("subject-revocation");
				return true;
			})) === true;
		const sessions = await endSessions();
		const cleared = sessions ? await step("factors", () => p.factors.clear(subject)) : undefined;
		if (cleared) {
			await step("lock", () =>
				p.lockouts.releaseUnder(p.lockout.name, subject, p.lockout.policy, { kind: "whole" }),
			);
		}
		// Runs whatever happened above: a login proved with a factor between the first boundary and the removal ends here.
		const sessionsAgain = sessions ? await endSessions() : undefined;
		declaredAudit(p.audit, events).record("mfa.reset", {
			subject,
			attributes: {
				by: "operator",
				...(cleared ? { kinds: cleared.kinds.join(" "), count: String(cleared.count) } : {}),
				sessions: String(sessions),
				...(sessionsAgain === undefined ? {} : { sessionsAgain: String(sessionsAgain) }),
				complete: String(failure === undefined),
				...(requestedBy === undefined ? {} : { requestedBy }),
			},
		});
		if (failure !== undefined) {
			p.log.warn("mfa-flows.reset_incomplete", {
				stoppedAt: failure.at,
				error: typeOf(failure.error),
			});
		} else {
			p.log.info("mfa-flows.reset", {});
		}
		return { cleared, failure, fault };
	};
	return {
		reset: async (subject, options = {}) => {
			const { cleared, failure } = await attempt(subject, options);
			if (failure !== undefined) throw failure.error;
			// Without a failure, the removal answered.
			return (cleared as Removed).count;
		},
		run: async (subject, options = {}): Promise<ResetOutcome> => {
			const { cleared, failure, fault } = await attempt(subject, options);
			// The one place a step's unavailability becomes a stopped run; any other failure, at any step, is thrown.
			if (fault !== undefined) throw fault.error;
			if (failure !== undefined) {
				// The lockout is released only once the factors went: before them a run stops at the
				// first boundary or the removal, after them at the release or the second boundary.
				if (cleared === undefined)
					return { kind: "stopped", at: failure.at as "sessions" | "factors" };
				return { kind: "stopped", at: failure.at as "sessions" | "lock", removed: cleared };
			}
			const done = cleared as Removed;
			return { kind: "done", removed: done.count, kinds: done.kinds };
		},
	};
}
