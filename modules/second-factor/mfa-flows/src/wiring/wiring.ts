import { audit } from "@mod/audit";
import type { BuildContext, Parts } from "@mod/kernel";
import { loginGates, logins } from "@mod/login-gates";
import { factorReading } from "@mod/mfa-reading";
import { type LockoutPolicy, lockouts } from "@mod/rate-limit";
import { longestRecentMs, sessions } from "@mod/session";
import { subjectRevocation } from "@mod/subject-revocation";
import { type EnrollmentFlow, enrollmentFlow } from "../contract.ts";
import { permitsOver } from "../permits/permits.ts";
import { gateOver, proofOver, resumeOver } from "../proof/proof.ts";
import { releaseOver } from "../release/release.ts";
import { flowPartsOf } from "../seams/seams.ts";
import type { Settings } from "../section.ts";
import { transactionStore } from "../store.ts";
import { transactionsIn, transactionsTakes } from "../transactions/transactions.ts";

export const policyOf = (s: Settings): LockoutPolicy => ({
	threshold: s.lockout.threshold,
	backoffMs: s.lockout.backoff * 1000,
	maxBackoffMs: s.lockout["max-backoff"] * 1000,
	budget: s.lockout.budget,
	budgetWindowMs: s.lockout["budget-window"] * 1000,
	hardLimit: s.lockout["hard-limit"],
	memoryMs: s.lockout.memory * 1000,
});

/** What `gating`'s gate takes from the build context. */
export const gatingTakes = [factorReading, ...transactionsTakes] as const;

/** The gate `mfa` the package contributes to `login-gates`, over its factors and transactions. */
export const gating = (m: Parts<Settings>) =>
	m.contribute(loginGates).by(async (c) => ({
		name: "mfa",
		hold: gateOver({
			factors: await c.get(factorReading),
			transactions: await transactionsIn(c),
		}),
	}));

/** What `partsIn` takes from the build context. */
export const partsTakes = [
	sessions,
	logins,
	subjectRevocation,
	audit,
	...transactionsTakes,
] as const;

/** The parts the module binding factors takes, from the contracts this package pulls. */
export async function partsIn(c: BuildContext<Settings>) {
	const transactions = await transactionsIn(c);
	const resume = resumeOver({
		sessions: await c.get(sessions),
		logins: await c.get(logins),
		revocation: await c.get(subjectRevocation),
		transactions,
		log: c.log,
	});
	return flowPartsOf({
		transactions,
		resume,
		audit: await c.get(audit),
		policy: policyOf(c.section),
	});
}

/** What `handlersOver` takes from the build context. */
export const handlersTakes = [
	factorReading,
	sessions,
	subjectRevocation,
	logins,
	transactionStore,
	enrollmentFlow,
	lockouts,
	audit,
	...transactionsTakes,
] as const;

/** Pulls the contracts and gives each internal module only the interfaces it uses. */
export async function handlersOver(c: BuildContext<Settings>, policy: LockoutPolicy) {
	const shared = {
		factors: await c.get(factorReading),
		sessions: await c.get(sessions),
		revocation: await c.get(subjectRevocation),
		transactions: await transactionsIn(c),
	};
	const resuming = { ...shared, logins: await c.get(logins), log: c.log };
	const permits = permitsOver({
		store: await c.get(transactionStore),
		clock: c.clock,
		recent: (at) => shared.sessions.recent(at),
		keepMs: longestRecentMs,
	});
	// The one flow the module binding factors contributes; the kernel refuses boot without it.
	const [flow] = await c.collect(enrollmentFlow);
	const { challenge, ...enrollment } = flow as EnrollmentFlow;
	const proof = proofOver({
		...resuming,
		enrollmentChallenge: challenge,
		lockouts: await c.get(lockouts),
		policy,
		permits,
		audit: await c.get(audit),
	});
	const release = releaseOver({
		...shared,
		permits,
		lockouts: await c.get(lockouts),
		policy,
		now: c.clock.now,
		audit: await c.get(audit),
		log: c.log,
	});
	return { ...proof, ...enrollment, ...release };
}
