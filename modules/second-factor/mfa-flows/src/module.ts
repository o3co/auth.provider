import { csrfChecked } from "@mod/csrf";
import { erasers } from "@mod/erasure-extensions";
import { type Route, routes, use } from "@mod/http";
import { defineModule, isUnavailable } from "@mod/kernel";
import { fenceFollower, proofSteps } from "@mod/mfa";
import { lockoutProblem, requestsPerSource } from "@mod/rate-limit";
import { sessions } from "@mod/session";
import { revocationFollowers } from "@mod/subject-revocation";
import { flowParts } from "./contract.ts";
import { flowsEraser } from "./erasure/eraser.ts";
import { type Handler, unavailable } from "./requests/requests.ts";
import { section } from "./section.ts";
import { transactionListings, transactionStore } from "./store.ts";
import {
	gating,
	gatingTakes,
	handlersOver,
	handlersTakes,
	naming,
	partsIn,
	partsTakes,
	policyOf,
} from "./wiring/wiring.ts";

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

/** What the module takes: the revocation followers, and its helpers' (`gating`, `partsIn`, `handlersOver`). */
const takes = [revocationFollowers, ...gatingTakes, ...partsTakes, ...handlersTakes];

export default defineModule({ name: "mfa-flows", section, replicaSafe: true, takes }, (m) => [
	m.contribute(proofSteps).by(() => ({ name: "mfa-flows" })),
	m.provide(flowParts).by(async (c) => {
		// A completed revocation stops a binding begun before it only where something moves mfa's fence.
		if (!(await c.collect(revocationFollowers)).some((f) => f.name === fenceFollower)) {
			return c.refuse(
				"mfa-flows",
				"a binding begun before a revocation would bind: compose mfa-revocation",
			);
		}
		return partsIn(c);
	}),
	gating(m),
	naming(m),
	// Its build takes only its two stores and `session` late, collecting no probes: the erasure gate collects erasers.
	m
		.contribute(erasers)
		.by(async (c) =>
			flowsEraser(
				await c.get(transactionStore),
				await c.get(transactionListings),
				c.late(sessions),
			),
		),
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
