import { audit } from "@mod/audit";
import { csrfChecked } from "@mod/csrf";
import { type Route, routes, use } from "@mod/http";
import { type BuildContext, defineModule, isUnavailable } from "@mod/kernel";
import { loginGates, logins } from "@mod/login-gates";
import { factors, proofSteps } from "@mod/mfa";
import { bindingProof } from "@mod/mfa-binding-proof";
import { type LockoutPolicy, lockoutProblem, lockouts, requestsPerSource } from "@mod/rate-limit";
import { longestRecentMs, sessions } from "@mod/session";
import { revocations, subjectRevocation } from "@mod/subject-revocation";
import { mfaReset } from "./contract.ts";
import { enrollmentOver } from "./enrollment/enrollment.ts";
import { permitsOver } from "./permits/permits.ts";
import { gateOver, proofOver, resumeOver } from "./proof/proof.ts";
import { releaseOver } from "./release/release.ts";
import { resetOver } from "./reset/reset.ts";
import { type Handler, unavailable } from "./routing.ts";
import { type Settings, section } from "./section.ts";
import { transactionStore } from "./store.ts";
import { transactionsIn } from "./transactions/transactions.ts";

const policyOf = (s: Settings): LockoutPolicy => ({
	threshold: s.lockout.threshold,
	backoffMs: s.lockout.backoff * 1000,
	maxBackoffMs: s.lockout["max-backoff"] * 1000,
	budget: s.lockout.budget,
	budgetWindowMs: s.lockout["budget-window"] * 1000,
	hardLimit: s.lockout["hard-limit"],
	memoryMs: s.lockout.memory * 1000,
});

/** Pulls the contracts and gives each internal module only the interfaces it uses. */
async function handlersOver(c: BuildContext<Settings>, policy: LockoutPolicy) {
	const shared = {
		factors: await c.get(factors),
		sessions: await c.get(sessions),
		revocation: await c.get(subjectRevocation),
		transactions: await transactionsIn(c),
	};
	const resuming = { ...shared, logins: await c.get(logins), log: c.log };
	const permits = permitsOver({
		store: await c.get(transactionStore),
		clock: c.clock,
		recent: shared.factors.recent,
		keepMs: longestRecentMs,
	});
	const { challengeBinding, ...enrollment } = enrollmentOver({
		...shared,
		bindingProof: await c.get(bindingProof),
		audit: await c.get(audit),
		resume: resumeOver(resuming),
	});
	const proof = proofOver({
		...resuming,
		enrollmentChallenge: challengeBinding,
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
type HandlerName = keyof Awaited<ReturnType<typeof handlersOver>>;

/** The package's routes; every POST checks same-origin, then the requests per source. */
const table = [
	["POST", "/session/mfa/challenge", "challenge"],
	["POST", "/session/mfa/verify", "verify"],
	["GET", "/session/mfa/transaction", "transaction"],
	["POST", "/session/mfa/step-up", "stepUp"],
	["POST", "/session/mfa/enrollment", "enroll"],
	["POST", "/session/mfa/enrollment/complete", "complete"],
	["POST", "/session/mfa/lock/release", "release"],
] as const satisfies readonly (readonly ["GET" | "POST", string, HandlerName])[];

const withUnavailable =
	(handle: Handler): Handler =>
	async (request) => {
		try {
			return await handle(request);
		} catch (error) {
			if (isUnavailable(error)) return unavailable;
			throw error;
		}
	};

export default defineModule({ name: "mfa-flows", section, replicaSafe: true }, (m) => [
	m.contribute(proofSteps).by(() => ({ name: "mfa-flows" })),
	m.provide(mfaReset).by(async (c) =>
		resetOver({
			factors: await c.get(factors),
			revocations: await c.get(revocations),
			lockouts: await c.get(lockouts),
			policy: policyOf(c.section),
			audit: await c.get(audit),
			log: c.log,
		}),
	),
	m.contribute(loginGates).by(async (c) => ({
		name: "mfa",
		hold: gateOver({
			factors: await c.get(factors),
			transactions: await transactionsIn(c),
		}),
	})),
	...table.map(([method, path, name]) =>
		m.contribute(routes).by(async (c): Promise<Route> => {
			const policy = policyOf(c.section);
			const problem = lockoutProblem(policy);
			if (problem) return c.refuse("mfa-flows", `lockout policy: ${problem}`);
			const handle = withUnavailable((await handlersOver(c, policy))[name]);
			if (method === "GET") return { method, path, handle };
			const window = { limit: c.section.requests, ms: c.section.window * 1000 };
			return {
				method,
				path,
				uses: [use(csrfChecked), use(requestsPerSource, { name: "mfa-flows", window })],
				takes: ["form", "json"],
				handle,
			};
		}),
	),
]);
