import { auditStandIn } from "@mod/audit/testing";
import {
	assemble,
	BootRefused,
	contract,
	defineModule,
	isUnavailable,
	kernelConfig,
} from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { type Factors, factors, type Witnessing, witnessing } from "@mod/mfa";
import { factorKinds } from "@mod/mfa-extensions";
import { witnessStandIn } from "@mod/mfa-witness/testing";
import { expect, it } from "vitest";
import { witnessBackfill } from "../src/contract.ts";
import bridge from "../src/module.ts";

const seen = contract<readonly Witnessing[]>("seen");
const reader = defineModule({ name: "reader" }, (m) => [
	m.provide(seen).by(async (c) => c.collect(witnessing)),
]);
/** Two kinds, one counting; the subject holds what `held` names, by kind. */
const kinds = defineModule({ name: "kinds" }, (m) => [
	m.contribute(factorKinds).by(() => ({ kind: "code", counts: true }) as never),
	m.contribute(factorKinds).by(() => ({ kind: "backup", counts: false }) as never),
]);
const holding = (held: Record<string, string[]>) =>
	defineModule({ name: "factors-stand-in" }, (m) => [
		m.provide(factors).by(
			() =>
				({
					held: async (subject: string) =>
						(held[subject] ?? []).map((kind, i) => ({ id: `${i}`, kind })),
				}) as unknown as Factors,
		),
	]);

async function boot(held: Record<string, string[]> = {}, witnesses = [witnessStandIn()]) {
	const recorded = auditStandIn();
	const logged = recordingLog();
	const app = await assemble({
		modules: [
			...witnesses.map((w) => w.module),
			kinds,
			holding(held),
			recorded.module,
			bridge,
			reader,
		],
		config: kernelConfig(),
		runtime: quietRuntime({ log: logged.log }),
	});
	return { app, events: recorded.events, logged, witness: witnesses[0] };
}

it("refuses to boot without an enrollment witness composed, or with two", async () => {
	await expect(boot({}, [])).rejects.toBeInstanceOf(BootRefused);
	await expect(boot({}, [witnessStandIn("one"), witnessStandIn("two")])).rejects.toBeInstanceOf(
		BootRefused,
	);
});

it("contributes mfa's witnessing over the witness: a mark beside nothing counting is recorded and unavailable", async () => {
	const { app, events, witness } = await boot();
	const [told] = app.get(seen);
	if (!told || !witness) throw new Error("no witnessing");
	expect(await told.standing("ann", true, "login")).toBe("held");
	expect(await told.standing("ann", false, "login")).toBe("none");
	witness.marks.set("bob", "t");
	await expect(told.standing("bob", false, "credentials")).rejects.toSatisfy(isUnavailable);
	expect(events.map((e) => [e.kind, e.subject, e.attributes])).toEqual([
		["mfa.enrollment_inconsistent", "bob", { at: "credentials" }],
	]);
	await told.settle("cid", async () => true);
	expect(witness.marks.has("cid")).toBe(true);
	await told.cleared("cid");
	expect(witness.marks.has("cid")).toBe(false);
});

it("fills a missing mark beside a counting factor, and never clears one beside nothing counting", async () => {
	const { app, witness } = await boot({ ann: ["code"], bob: ["backup"], cid: ["code"] });
	if (!witness) throw new Error("no witness");
	const backfill = app.get(witnessBackfill);
	expect(await backfill.settle("ann")).toBe("marked");
	expect(witness.marks.has("ann")).toBe(true);
	expect(await backfill.settle("ann")).toBe("held");
	expect(await backfill.settle("bob")).toBe("none");
	witness.marks.set("dee", "lost");
	expect(await backfill.settle("dee")).toBe("inconsistent");
	expect(witness.marks.get("dee")).toBe("lost");
	witness.failing.read = 1;
	await expect(backfill.settle("cid")).rejects.toSatisfy(isUnavailable);
});
