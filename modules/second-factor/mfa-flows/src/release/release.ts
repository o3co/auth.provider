import type { Audit } from "@mod/audit";
import { jsonAnswer } from "@mod/http";
import type { Log } from "@mod/kernel";
import type { FactorReading } from "@mod/mfa-reading";
import type { LockoutPolicy, Lockouts, Released, ReleaseTerms } from "@mod/rate-limit";
import { longestRecentMs, refusedEntry, type Sessions } from "@mod/session";
import type { SubjectRevocation } from "@mod/subject-revocation";
import type { PermitResult, Permits } from "../permits/permits.ts";
import { auditedBy } from "../recording/recording.ts";
import { type Handler, unavailable } from "../requests/requests.ts";
import { lockoutName } from "../section.ts";

export interface ReleaseParts {
	readonly sessions: Pick<Sessions, "enterFor">;
	readonly permits: Pick<Permits, "of" | "use">;
	readonly lockouts: Pick<Lockouts, "standing" | "releaseUnder">;
	readonly revocation: Pick<SubjectRevocation, "check">;
	readonly factors: Pick<FactorReading, "guessableBoundAfter">;
	readonly policy: LockoutPolicy;
	readonly now: () => number;
	readonly audit: Pick<Audit, "record">;
	readonly log: Log;
}

/** How much later than the first counted failure or the hold's start a change must be to count, as their clocks may differ; 0.17's skew. */
const marginMs = 5 * 60_000;
/** The boundary is compared in whole seconds: a second more keeps the rounding from loosening the margin. */
const roundingMs = 1000;

const exemptRequired = jsonAnswer(403, {
	error: "mfa_exempt_proof_required",
	error_description: "Verify a recovery code or a passkey first, then release",
});
const refused = {
	error: "mfa_lock_release_refused",
	error_description: "Change the account's password, sign in again, then release",
	reason: "not_revoked_since",
};
const heldText =
	"Guessable second factors stay held until each is replaced: replace them, verify a recovery code or a passkey again, then release";

const rebindAfter = (fixedAt: number) => new Date(fixedAt + marginMs).toISOString();
/** What an applied release leaves: released, or a fixed hold still standing. */
const resultOf = (done: Released): PermitResult =>
	done.fixedAt === undefined ? { lock: "released" } : { lock: "held", fixedAt: done.fixedAt };
/** The answer to an applied release, in 0.17's words; the same however often it is asked. */
const answerOf = (result: PermitResult) =>
	result.lock === "released"
		? jsonAnswer(200, { lock: "released" })
		: jsonAnswer(200, {
				lock: "held",
				hold: "hard",
				description: heldText,
				rebind_after: rebindAfter(result.fixedAt),
			});

export function releaseOver(p: ReleaseParts) {
	const recorded = auditedBy(p.audit);
	/** Forgives the count when the subject was revoked well after its first counted failure, or when nothing is counted. */
	const forgiving = async (subject: string, first: number | undefined) => {
		if (first === undefined) return {};
		const revoked = await p.revocation.check(subject, first + marginMs + roundingMs);
		return revoked === "revoked" ? { firstFailureAt: first } : undefined;
	};
	/** Lifts a fixed hold when every guessable factor was bound again well after it began. */
	const lifting = async (subject: string, fixedAt: number | undefined) => {
		if (fixedAt === undefined) return undefined;
		return (await p.factors.guessableBoundAfter(subject, fixedAt + marginMs))
			? { fixedAt }
			: undefined;
	};
	const release: Handler = async (request) => {
		const entry = await p.sessions.enterFor(request, "credentials");
		if (entry.kind !== "entered") return refusedEntry(entry);
		const { id: handle, context } = entry.session;
		const { subject } = context;
		// A boundary written by a host whose clock runs ahead cannot vouch for a revocation: as 0.17, nothing is judged.
		if ((await p.revocation.check(subject, p.now() + marginMs)) === "revoked") {
			p.log.error("mfa-flows.lock_release_boundary_ahead", {});
			return unavailable;
		}
		const permit = await p.permits.of(handle);
		if (permit.kind === "none") return exemptRequired;
		if (permit.kind === "used") {
			p.log.info("mfa-flows.lock_release", { outcome: "repeated" });
			return answerOf(permit.result);
		}
		const stands = await p.lockouts.standing(lockoutName, subject, p.policy);
		const forgive = await forgiving(subject, stands.firstFailureAt);
		const lift = await lifting(subject, stands.fixedAt);
		const terms: ReleaseTerms = {
			kind: "checked",
			// The permit's own id: of releases racing on one permit, one applies and the others answer as it.
			once: { id: permit.id, keepMs: longestRecentMs },
			...(forgive ? { forgive } : {}),
			...(lift ? { lift } : {}),
		};
		const done = await p.lockouts.releaseUnder(lockoutName, subject, p.policy, terms);
		if (done.kind === "unchanged") {
			// A refusal spends nothing: the permit stays for a release once the account is set right.
			p.log.info("mfa-flows.lock_release", { outcome: "refused" });
			const rebind = done.fixedAt === undefined ? {} : { rebind_after: rebindAfter(done.fixedAt) };
			return jsonAnswer(409, { ...refused, ...rebind });
		}
		if (done.kind === "released") {
			// 0.17's name for the budget.
			recorded("lock.recovered", subject, request, {
				operation: "recover",
				generation: String(done.generation),
				week: String(done.cleared.budget),
				run: String(done.cleared.run),
				hard: String(done.cleared.hard),
			});
		}
		const result = resultOf(done);
		// Used once applied, so a later call answers the same without asking rate-limit or a clock.
		await p.permits.use(handle, permit, result);
		const outcome = done.kind === "already" ? "repeated" : result.lock;
		p.log.info("mfa-flows.lock_release", { outcome });
		return answerOf(result);
	};
	return { release };
}
