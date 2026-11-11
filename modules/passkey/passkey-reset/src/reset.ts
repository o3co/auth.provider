import { type Audit, declaredAudit } from "@mod/audit";
import { isUnavailable, type Log, Unavailable } from "@mod/kernel";
import type { PasskeyClearing } from "@mod/passkeys";
import type { Revocations } from "@mod/subject-revocation";
import events from "./audit-events.ts";
import type { PasskeyReset, PasskeyResetOutcome, PasskeyResetPart } from "./contract.ts";

export interface ResetParts {
	readonly revocations: Pick<Revocations, "record">;
	readonly holders: Pick<PasskeyClearing, "cleared">;
	readonly audit: Pick<Audit, "record">;
	readonly log: Log;
}

/** The step a run stopped at: a boundary, or the passkeys' removal. */
type Stop = "sessions" | "passkeys";

const wellFormed = (text: unknown, max = Number.POSITIVE_INFINITY): text is string =>
	typeof text === "string" && text.length > 0 && text.length <= max && text.isWellFormed();
/** The most UTF-16 code units a requester may name, as the card bounds it. */
const longestRequestedBy = 256;
const typeOf = (error: unknown) => (error instanceof Error ? error.name : typeof error);

/** The operator's reset, and the passkeys' step alone for a reset that moves the boundaries itself. */
export function resetOver(p: ResetParts): { reset: PasskeyReset; part: PasskeyResetPart } {
	const reset: PasskeyReset = {
		reset: async (subject, options = {}): Promise<PasskeyResetOutcome> => {
			const { requestedBy } = options;
			if (!wellFormed(subject)) throw new RangeError("subject");
			if (requestedBy !== undefined && !wellFormed(requestedBy, longestRequestedBy)) {
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
			/** The first boundary step that read the subject erased; whether one read it not erased. */
			let erased: { readonly complete: boolean } | undefined;
			let answeredNotErased = false;
			const endSessions = async () =>
				(await step("sessions", async () => {
					const done = await p.revocations.record(subject, { keepDelegations: true });
					// Erased is read before complete: such a run is refused, never stopped at this step.
					if (done.erased) {
						erased ??= { complete: done.complete };
						return false;
					}
					answeredNotErased = true;
					// The boundary moved, but a session still open would outlive the reset.
					if (!done.complete) throw new Unavailable("subject-revocation");
					return true;
				})) === true;
			const sessions = await endSessions();
			const cleared = sessions
				? await step("passkeys", () => p.holders.cleared(subject))
				: undefined;
			// Runs whatever the removal did: a login with a passkey between the first boundary and the removal ends here.
			const sessionsAgain = sessions ? await endSessions() : undefined;
			if (erased !== undefined) {
				// No record of a run that read the subject erased names it; the passkeys may be gone already.
				declaredAudit(p.audit, events).record("passkey.reset.refused", {
					attributes: {
						by: "operator",
						complete: String(erased.complete),
						...(requestedBy === undefined ? {} : { requestedBy }),
					},
				});
				p.log.warn("passkey-reset.reset_refused", {});
				if (fault !== undefined) throw fault.error;
				return { kind: "erased" };
			}
			// The subject is named only where a boundary step read it, as not erased.
			declaredAudit(p.audit, events).record("passkey.reset", {
				...(answeredNotErased ? { subject } : {}),
				attributes: {
					by: "operator",
					...(answeredNotErased ? {} : { withheld: "unread" }),
					...(cleared ? { count: String(cleared.removed) } : {}),
					sessions: String(sessions),
					...(sessionsAgain === undefined ? {} : { sessionsAgain: String(sessionsAgain) }),
					complete: String(failure === undefined),
					...(requestedBy === undefined ? {} : { requestedBy }),
				},
			});
			if (failure !== undefined) {
				p.log.warn("passkey-reset.reset_incomplete", {
					stoppedAt: failure.at,
					error: typeOf(failure.error),
				});
			} else {
				p.log.info("passkey-reset.reset", {});
			}
			// The one place a step's unavailability becomes a stopped run; any other failure, at any step, is thrown.
			if (fault !== undefined) throw fault.error;
			if (failure !== undefined) {
				// Before the removal answered, a run stops at the first boundary or the removal; after it, at the second boundary.
				if (cleared === undefined) return { kind: "stopped", at: failure.at };
				return { kind: "stopped", at: "sessions", removed: cleared.removed };
			}
			return { kind: "done", removed: (cleared as { removed: number }).removed };
		},
	};
	const part: PasskeyResetPart = {
		passkeys: async (subject) => {
			if (!wellFormed(subject)) throw new RangeError("subject");
			try {
				return { kind: "done", removed: (await p.holders.cleared(subject)).removed };
			} catch (error) {
				if (isUnavailable(error)) return { kind: "stopped" };
				throw error;
			}
		},
	};
	return { reset, part };
}
