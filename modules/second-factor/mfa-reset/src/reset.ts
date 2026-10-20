import { type Audit, declaredAudit } from "@mod/audit";
import { type Log, Unavailable } from "@mod/kernel";
import type { Factors } from "@mod/mfa";
import type { LockoutPolicy, Lockouts } from "@mod/rate-limit";
import type { Revocations } from "@mod/subject-revocation";
import events from "./audit-events.ts";
import type { MfaReset } from "./contract.ts";

export interface ResetParts {
	readonly factors: Pick<Factors, "clear">;
	readonly revocations: Pick<Revocations, "record">;
	readonly lockouts: Pick<Lockouts, "releaseUnder">;
	/** `mfa-flows`' lockout: its name and policy. */
	readonly lockout: { readonly name: string; readonly policy: LockoutPolicy };
	readonly audit: Audit;
	readonly log: Log;
}

/** The step a run stopped at: a boundary, the factors' removal, or the lockout's release. */
type Stop = "sessions" | "factors" | "lock";

const wellFormed = (text: unknown, max = Number.POSITIVE_INFINITY): text is string =>
	typeof text === "string" && text.length > 0 && text.length <= max && text.isWellFormed();
const typeOf = (error: unknown) => (error instanceof Error ? error.name : typeof error);

export function resetOver(p: ResetParts): MfaReset {
	return {
		reset: async (subject, options = {}) => {
			const { requestedBy } = options;
			if (!wellFormed(subject)) throw new RangeError("subject");
			if (requestedBy !== undefined && !wellFormed(requestedBy, 256)) {
				throw new RangeError("requestedBy");
			}
			let failure: { readonly at: Stop; readonly error: unknown } | undefined;
			/** Runs a step; the first failure is kept, and the step answers none. */
			const step = async <T>(at: Stop, run: () => Promise<T>): Promise<T | undefined> => {
				try {
					return await run();
				} catch (error) {
					failure ??= { at, error };
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
				throw failure.error;
			}
			p.log.info("mfa-flows.reset", {});
			// Without a failure, the removal answered.
			return (cleared as { readonly count: number }).count;
		},
	};
}
