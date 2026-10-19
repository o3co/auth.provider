import { audit } from "@mod/audit";
import { csrfChecked } from "@mod/csrf";
import { type Route, routes, use } from "@mod/http";
import { defineModule, isUnavailable } from "@mod/kernel";
import { loginGates } from "@mod/login-gates";
import { factors, proofSteps } from "@mod/mfa";
import { lockoutProblem, lockouts, requestsPerSource } from "@mod/rate-limit";
import { revocations } from "@mod/subject-revocation";
import { flowParts, mfaReset } from "./contract.ts";
import { gateOver } from "./proof/proof.ts";
import { resetOver } from "./reset/reset.ts";
import { type Handler, unavailable } from "./routing.ts";
import { section } from "./section.ts";
import { transactionsIn } from "./transactions/transactions.ts";
import { handlersOver, partsIn, policyOf } from "./wiring/wiring.ts";

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
	m.provide(flowParts).by(partsIn),
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
			if (method === "GET") return { method, path, changesState: false, handle };
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
