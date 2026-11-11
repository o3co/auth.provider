/**
 * The token endpoint's half of the promise that no credentials are answered past the fence: for any
 * grant outcome and any answer of the fence, under any order of concurrent requests, nothing is
 * answered before the fence passes the bundle, nothing after it refuses or cannot tell, and the
 * subject fenced is the subject signed. The fence is scripted: what it decides is not this
 * property's, so it answers what each run says, as late as the scheduler lets it. The route runs
 * as the assembly builds it, its handler called in the process.
 *
 * Per-PR runs are fixed: FC_SEED (default 20261111) and FC_RUNS (default 200).
 */
import { auditStandIn } from "@mod/audit/testing";
import clientAllowanceModule from "@mod/client-allowance/module";
import { allowancesFor } from "@mod/client-allowance/testing";
import { clientsConfig, confidentialClient } from "@mod/clients/testing";
import { type Grant, type GrantOutcome, grants, type Refused } from "@mod/grants";
import { type HttpResponse, type Route, routes } from "@mod/http";
import { testRequest } from "@mod/http/testing";
import { assemble, contract, defineModule, Unavailable } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import rateLimitModule from "@mod/rate-limit/module";
import { simulatedStore } from "@mod/store/testing";
import { type AccessGrant, issuanceFences, issuancePolicies } from "@mod/tokens";
import fc from "fast-check";
import { afterAll, beforeAll, expect, it } from "vitest";
import { basicOf, endpointConfig, endpointModules } from "../../../test/deployment.ts";
import { tokenPath } from "../endpoint.ts";

const seed = Number(process.env.FC_SEED ?? 20261111);
const numRuns = Number(process.env.FC_RUNS ?? 200);

/**
 * What a request's grant does: issue under its one subject (`fickle`: a grant whose subject answers
 * otherwise once read), under none or two, have the issuance refused by a policy, or answer an error.
 */
type Outcome = "one" | "fickle" | "none" | "two" | "judged" | "error";
type Answer = "passed" | "refused" | "unavailable";
interface Plan {
	readonly outcome: Outcome;
	readonly answer: Answer;
}

const slots = 3;
const grantTypeOf = (slot: number) => `urn:test:slot${slot}`;
/** The subjects a slot's grant issues under; each slot its own, so the fence knows whose bundle it is. */
const subjectsOf = (slot: number, outcome: Outcome): readonly string[] => {
	if (outcome === "one" || outcome === "fickle") return [`s${slot}`];
	if (outcome === "two") return [`s${slot}a`, `s${slot}b`];
	if (outcome === "judged") return [`judged${slot}`];
	return [];
};
const slotOf = (subject: string) => Number(/^(?:s|judged)(\d)/.exec(subject)?.[1] ?? Number.NaN);

/** The claims of an answered access token. */
const claimsOf = (token: unknown) =>
	JSON.parse(Buffer.from(String(token).split(".")[1] ?? "", "base64url").toString()) as {
		sub?: unknown;
	};

/** What one run scripts and sees; the assembly is built once and reads it. */
interface Run {
	plans: readonly Plan[];
	/** Waits at a point the scheduler releases; outside a run, at none. */
	point: (label: string) => Promise<void>;
	/** The subjects the fence was asked, in order. */
	asked: string[];
	/** `settled:<slot>` as the fence answers a slot, `answered:<slot>` as a handler resolves. */
	log: string[];
}
const run: Run = { plans: [], point: async () => {}, asked: [], log: [] };

/** A grant answering as its slot's plan says, waiting at a point before it starts and after it issues. */
const scripted = (slot: number): Grant => ({
	grantType: grantTypeOf(slot),
	readsAmbient: "none",
	handle: async ({ client, issue }): Promise<GrantOutcome | Refused> => {
		await run.point(`${slot}:grant`);
		const { outcome } = run.plans[slot] as Plan;
		if (outcome === "error")
			return { kind: "error", error: "invalid_request", description: "scripted" };
		const tokens: string[] = [];
		for (const subject of subjectsOf(slot, outcome)) {
			let reads = 0;
			const base = { issuedTo: client.id, audience: [], scope: [] };
			// A fickle grant names another subject from its second read on: what is signed and fenced is the first.
			const grant: AccessGrant =
				outcome === "fickle"
					? {
							...base,
							get subject() {
								reads++;
								return reads === 1 ? subject : "mallory";
							},
						}
					: { ...base, subject };
			const issued = await issue(grant);
			if (issued.kind !== "issued") return issued;
			tokens.push(issued.access.token);
		}
		await run.point(`${slot}:issued`);
		return {
			kind: "issued",
			body: { access_token: tokens.join(" ") || "none", token_type: "Bearer" },
		};
	},
});

/** The fence: notes the subject asked, waits at a point, then answers as the subject's slot's plan says. */
const fence = defineModule({ name: "scripted-fence", replicaSafe: true, takes: [] }, (m) => [
	m.contribute(issuanceFences).by(() => ({
		name: "scripted-fence",
		fence: async ({ subject }) => {
			run.asked.push(subject);
			const slot = slotOf(subject);
			await run.point(`${slot}:fence`);
			const answer = run.plans[slot]?.answer ?? "passed";
			run.log.push(`settled:${slot}`);
			if (answer === "unavailable") throw new Unavailable("scripted-fence");
			return answer;
		},
	})),
	...Array.from({ length: slots }, (_, slot) => m.contribute(grants).by(() => scripted(slot))),
	m.contribute(issuancePolicies).by(() => ({
		name: "judging",
		judge: async ({ grant }) =>
			grant.subject.startsWith("judged")
				? { kind: "refused", reason: "scripted", description: "refused by policy" }
				: { kind: "allowed" },
	})),
]);

const seen = contract<{ readonly routes: readonly Route[] }>("test.fenced-routes");
const reader = defineModule({ name: "reader", replicaSafe: true, takes: [routes] }, (m) => [
	m.provide(seen).by(async (c) => ({ routes: await c.collect(routes) })),
]);

let stop = async () => {};
let route: Route;
const recorded = auditStandIn();
beforeAll(async () => {
	const sections = allowancesFor({
		grants: ["client_credentials", ...Array.from({ length: slots }, (_, s) => grantTypeOf(s))],
		scopes: ["read"],
		"default-scopes": ["read"],
	});
	const app = await assemble({
		modules: endpointModules(
			clientAllowanceModule,
			rateLimitModule,
			recorded.module,
			simulatedStore().module,
			fence,
			reader,
		),
		config: {
			...endpointConfig({ issuer: "https://issuer.example" }),
			...clientsConfig([
				confidentialClient({ id: "basic", method: "client_secret_basic", sections }),
			]),
		},
		runtime: quietRuntime(),
	});
	await app.start();
	stop = () => app.stop(1000);
	const found = (await app.get(seen)).routes.find((r) => r.path === tokenPath);
	if (!found) throw new Error("no token route");
	route = found;
});
afterAll(() => stop());

const requestOf = (slot: number) =>
	testRequest({
		method: "POST",
		path: tokenPath,
		form: new Map([["grant_type", [grantTypeOf(slot)]]]),
		headers: new Map([
			["content-type", "application/x-www-form-urlencoded"],
			["authorization", basicOf("basic", "basic-secret")],
		]),
	});

type Settled =
	| { readonly kind: "answered"; readonly response: HttpResponse }
	| { readonly kind: "threw"; readonly error: unknown };
const jsonOf = (response: HttpResponse) =>
	(response.body as { json?: Record<string, unknown> } | undefined)?.json ?? {};

// Grants that reach the fence come more often, so concurrent requests wait at it together.
const plan = fc.record({
	outcome: fc.oneof(
		...(
			[
				["one", 3],
				["fickle", 2],
				["none", 1],
				["two", 1],
				["judged", 1],
				["error", 1],
			] as const
		).map(([outcome, weight]) => ({ arbitrary: fc.constant<Outcome>(outcome), weight })),
	),
	answer: fc.constantFrom<Answer>("passed", "refused", "unavailable"),
});

it("answers credentials only once its fence has passed them, and none where it refuses or cannot tell, the subject fenced being the subject signed, under any order of concurrent requests", async () => {
	await fc.assert(
		fc.asyncProperty(
			fc.array(plan, { minLength: 1, maxLength: slots }),
			fc.scheduler(),
			async (plans, s) => {
				const before = recorded.events.length;
				let pending = plans.length;
				Object.assign(run, {
					plans,
					asked: [],
					log: [],
					point: (label: string) => s.schedule(Promise.resolve(), label).then(() => {}),
				});
				const results: Settled[] = [];
				const sent = plans.map((_, slot) =>
					Promise.resolve(route.handle(requestOf(slot)))
						.then(
							(response) => {
								run.log.push(`answered:${slot}`);
								results[slot] = { kind: "answered", response };
							},
							(error: unknown) => {
								results[slot] = { kind: "threw", error };
							},
						)
						.finally(() => {
							pending--;
						}),
				);
				// A point is released only once every request still running waits at one, so what
				// runs between two points is all the run's work, whatever else takes its time.
				try {
					while (pending > 0) {
						if (s.count() === pending) await s.waitNext(1);
						else await new Promise<void>((resolve) => setImmediate(resolve));
					}
					await Promise.all(sent);
				} finally {
					run.point = async () => {};
				}

				const events = recorded.events.slice(before);
				for (const [slot, { outcome, answer }] of plans.entries()) {
					const result = results[slot] as Settled;
					const asked = run.asked.filter((subject) => slotOf(subject) === slot);
					const recordedHere = events.filter((e) => e.attributes?.grant_type === grantTypeOf(slot));
					if (outcome === "one" || outcome === "fickle") {
						// The fence is asked once, for the subject the grant named first, which tokens signed.
						expect(asked).toEqual([`s${slot}`]);
						if (answer === "passed") {
							expect(result.kind).toBe("answered");
							if (result.kind !== "answered") continue;
							expect(result.response.status).toBe(200);
							expect(claimsOf(jsonOf(result.response).access_token).sub).toBe(`s${slot}`);
							// Nothing is answered before the fence has answered.
							expect(run.log.indexOf(`settled:${slot}`)).toBeGreaterThanOrEqual(0);
							expect(run.log.indexOf(`settled:${slot}`)).toBeLessThan(
								run.log.indexOf(`answered:${slot}`),
							);
							expect(recordedHere.map((e) => e.kind)).toEqual(["token.issued"]);
						} else if (answer === "refused") {
							expect(result).toEqual({
								kind: "answered",
								response: expect.objectContaining({ status: 400 }),
							});
							if (result.kind !== "answered") continue;
							expect(jsonOf(result.response)).toEqual({
								error: "invalid_grant",
								error_description: "issuance refused",
							});
							expect(recordedHere.map((e) => e.attributes?.reason)).toEqual(["issuance_fenced"]);
						} else {
							expect(result.kind).toBe("threw");
							if (result.kind !== "threw") continue;
							expect(result.error).toBeInstanceOf(Unavailable);
							expect(recordedHere).toEqual([]);
						}
						continue;
					}
					// No bundle under one subject reaches the fence, and none is answered.
					expect(asked).toEqual([]);
					if (outcome === "none" || outcome === "two") {
						expect(result.kind).toBe("threw");
						if (result.kind !== "threw") continue;
						expect(result.error).toBeInstanceOf(Error);
						expect(result.error).not.toBeInstanceOf(Unavailable);
						expect(recordedHere).toEqual([]);
					} else {
						expect(result.kind).toBe("answered");
						if (result.kind !== "answered") continue;
						expect(result.response.status).toBe(400);
						expect(jsonOf(result.response)).not.toHaveProperty("access_token");
					}
				}
				// Whatever was answered with a token, its fence had passed it first.
				for (const [slot, result] of results.entries()) {
					if (result?.kind !== "answered" || !("access_token" in jsonOf(result.response))) continue;
					expect(plans[slot]?.answer).toBe("passed");
					expect(run.log.indexOf(`settled:${slot}`)).toBeLessThan(
						run.log.indexOf(`answered:${slot}`),
					);
				}
			},
		),
		{ seed, numRuns },
	);
}, 120_000);
