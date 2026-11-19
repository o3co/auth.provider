import { audit } from "@mod/audit";
import { originEvidence } from "@mod/csrf";
import { site } from "@mod/http";
import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime, takesUnused } from "@mod/kernel/testing";
import { type Entry, sessions } from "@mod/session";
import { handoff } from "@mod/upstream-handoff";
import { type UpstreamContinuation, upstreamContinuations } from "@mod/upstreams";
import { users } from "@mod/users";
import { expect, it } from "vitest";
import linkModule from "../src/module.ts";

/** What the link is built over, never asked: the continuation is only built. */
const stubs = defineModule({ name: "stubs", replicaSafe: true, takes: [] }, (m) => [
	m.provide(site).by(() => ({ origin: "https://as.example", secureCookies: true }) as never),
	m.provide(originEvidence).by(() => ({ sameOrigin: () => true })),
	m.provide(sessions).by(() => ({}) as never),
	m.provide(users).by(() => ({}) as never),
	m.provide(audit).by(() => ({ record: () => {}, lost: () => ({}) })),
	m.provide(handoff).by(() => ({}) as never),
]);

it("takes all it names", async () => {
	const input = { modules: [stubs, linkModule], config: kernelConfig(), runtime: quietRuntime() };
	// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
	expect((await takesUnused(input))["federation-link"]).toBeUndefined();
});

it("awaits a refusal's recording at stop before audit stops, even where the continuation is built before audit", async () => {
	const order: string[] = [];
	let answer: (entry: Entry) => void = () => {};
	const read = new Promise<Entry>((resolve) => {
		answer = resolve;
	});
	const found = contract<readonly UpstreamContinuation[]>("found-continuations");
	// Collects the continuations first, so the link is built before anything has asked for audit.
	const collector = defineModule(
		{ name: "collector", replicaSafe: true, takes: [upstreamContinuations] },
		(m) => [m.provide(found).by((c) => c.collect(upstreamContinuations))],
	);
	const recorded = defineModule({ name: "recorded", replicaSafe: true, takes: [] }, (m) => [
		m.provide(site).by(() => ({ origin: "https://as.example", secureCookies: true }) as never),
		m.provide(originEvidence).by(() => ({ sameOrigin: () => true })),
		m.provide(sessions).by(() => ({ entryOf: () => read }) as never),
		m.provide(users).by(() => ({}) as never),
		m.provide(handoff).by(() => ({}) as never),
		m.provide(audit).by((c) => {
			c.onStop(async () => {
				order.push("audit stopped");
			});
			return { record: (event) => void order.push(event.kind), lost: () => ({}) };
		}),
	]);
	const app = await assemble({
		modules: [collector, linkModule, recorded],
		config: kernelConfig(),
		runtime: quietRuntime(),
	});
	const [link] = app.get(found);
	link?.failed({ idp: "corp", reason: "exchange_failed", kept: { session: "s1" } });
	const stopping = app.stop();
	// The read answers only once the stop is under way, as a slow store's would.
	setTimeout(
		() =>
			answer({
				kind: "entered",
				session: { id: "s1", context: { subject: "alice", amr: [], authenticatedAt: 0 } },
				endsAt: 0,
			}),
		20,
	);
	await stopping;
	expect(order).toEqual(["federation.identity.link_refused", "audit stopped"]);
});
