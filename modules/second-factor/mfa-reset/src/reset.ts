import { type Audit, declaredAudit } from "@mod/audit";
import { isUnavailable, type Log, Unavailable } from "@mod/kernel";
import type { FactorManaging } from "@mod/mfa-managing";
import type { LockoutPolicy, Lockouts } from "@mod/rate-limit";
import type { Revocations } from "@mod/subject-revocation";
import events from "./audit-events.ts";
import type { MfaReset, Removed, ResetOutcome, ResetPart } from "./contract.ts";

export interface ResetParts {
	readonly factors: Pick<FactorManaging, "clear">;
	readonly revocations: Pick<Revocations, "record">;
	readonly lockouts: Pick<Lockouts, "releaseUnder">;
	/** `mfa-flows`' lockout: its name and policy. */
	readonly lockout: { readonly name: string; readonly policy: LockoutPolicy };
	readonly audit: Pick<Audit, "record">;
	readonly log: Log;
	/** The parts it removes beside the factors, by name. */
	readonly parts: readonly ResetPart[];
}

/** The step a run stopped at: a boundary, the factors' removal, a part's, or the lockout's release. */
type Stop = "sessions" | "factors" | "parts" | "lock";

const wellFormed = (text: unknown, max = Number.POSITIVE_INFINITY): text is string =>
	typeof text === "string" && text.length > 0 && text.length <= max && text.isWellFormed();
/** The most UTF-16 code units a requester may name, as the card bounds it. */
const longestRequestedBy = 256;
const typeOf = (error: unknown) => (error instanceof Error ? error.name : typeof error);

/**
 * What a run did: what the factors' removal answered, if it ran, the first failure, if any, and the
 * first failure that is not unavailable, if any, whichever step it came at.
 */
interface Ran {
	readonly cleared: Removed | undefined;
	/** Each part done, by name, with how many went. */
	readonly parts: Readonly<Record<string, number>>;
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
		const endSessions = async () =>
			(await step("sessions", async () => {
				const { complete } = await p.revocations.record(subject, { keepDelegations: true });
				// The boundary moved, but a session still open would outlive the reset.
				if (!complete) throw new Unavailable("subject-revocation");
				return true;
			})) === true;
		const sessions = await endSessions();
		const cleared = sessions ? await step("factors", () => p.factors.clear(subject)) : undefined;
		// Each part by its name's order, whatever the factors' removal answered, the rest past one that fails.
		const went: [string, number][] = [];
		const partsStopped: string[] = [];
		const ordered = [...p.parts].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
		for (const part of sessions ? ordered : []) {
			const removed = await step("parts", async () => {
				const done = await part.remove(subject);
				// A part stopped is a step unavailable, as a boundary that leaves a session open is.
				if (done.kind === "stopped") throw new Unavailable(part.name);
				return done.removed;
			});
			if (removed === undefined) partsStopped.push(part.name);
			else went.push([part.name, removed]);
		}
		// Each name an own entry, whatever it is: an assignment by `__proto__` would set the prototype.
		const parts: Record<string, number> = Object.fromEntries(went);
		if (cleared && partsStopped.length === 0) {
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
				...(went.length > 0
					? {
							parts: went.map(([n, c]) => `${n}=${c}`).join(" "),
						}
					: {}),
				...(partsStopped.length > 0 ? { partsStopped: partsStopped.join(" ") } : {}),
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
		return { cleared, parts, failure, fault };
	};
	return {
		run: async (subject, options = {}): Promise<ResetOutcome> => {
			const { cleared, parts, failure, fault } = await attempt(subject, options);
			// The one place a step's unavailability becomes a stopped run; any other failure, at any step, is thrown.
			if (fault !== undefined) throw fault.error;
			if (failure !== undefined) {
				// The lockout is released only once the factors went: before them a run stops at the
				// first boundary or the removal, after them at the release or the second boundary.
				if (cleared === undefined)
					return { kind: "stopped", at: failure.at as "sessions" | "factors" };
				return {
					kind: "stopped",
					at: failure.at as "sessions" | "parts" | "lock",
					removed: cleared,
				};
			}
			const done = cleared as Removed;
			return { kind: "done", removed: done.count, kinds: done.kinds, parts };
		},
	};
}
