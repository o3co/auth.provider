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
import { witnessStandIn } from "@mod/mfa-witness/testing";
import { expect, it } from "vitest";
import { witnessBackfill } from "../src/contract.ts";
import bridge from "../src/module.ts";

const seen = contract<readonly Witnessing[]>("seen");
const reader = defineModule({ name: "reader" }, (m) => [
	m.provide(seen).by(async (c) => c.collect(witnessing)),
]);
/**
 * The subject holds what `held` names, by kind, of which only `code` counts. `afterRead` runs after
 * the n-th read of the factors has taken its answer, as a request racing it would.
 */
const holding = (held: Record<string, string[]>, afterRead?: (n: number) => void) => {
	let reads = 0;
	return defineModule({ name: "factors-stand-in" }, (m) => [
		m.provide(factors).by(
			() =>
				({
					countingWritten: async (subject: string) => {
						const answer = (held[subject] ?? []).includes("code");
						reads += 1;
						afterRead?.(reads);
						return answer;
					},
				}) as unknown as Factors,
		),
	]);
};

async function boot(
	held: Record<string, string[]> = {},
	witnesses = [witnessStandIn()],
	afterRead?: (n: number) => void,
) {
	const recorded = auditStandIn();
	const logged = recordingLog();
	const app = await assemble({
		modules: [
			...witnesses.map((w) => w.module),
			holding(held, afterRead),
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
	await expect(told.standing("bob", false, "credentials")).rejects.toSatisfy(
		(error) => isUnavailable(error) && (error as { what: string }).what === "mfa",
	);
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

it("leaves no mark when a reset takes the factors while it fills one, and clears only the mark it set", async () => {
	const held: Record<string, string[]> = { ann: ["code"] };
	const { app, witness } = await boot(held);
	if (!witness) throw new Error("no witness");
	// A reset lands between reading the factors and marking: the factors and the mark go.
	witness.next.beforeEnroll = () => {
		held.ann = [];
		witness.marks.delete("ann");
	};
	expect(await app.get(witnessBackfill).settle("ann")).toBe("none");
	expect(witness.marks.has("ann")).toBe(false);
});

it("marks anew when its clear takes the mark a new binding set after a reset", async () => {
	const held: Record<string, string[]> = { ann: ["code"] };
	// A witness with no withdraw, whose own clear may take any mark.
	const stand = witnessStandIn("enrollment-witness", { withdraw: false });
	// After the late read that sees the reset, a new binding writes its factor and marks it.
	const { app } = await boot(held, [stand], (n) => {
		if (n !== 2) return;
		held.ann = ["code"];
		stand.marks.set("ann", "binding");
	});
	// A reset takes the factors and the mark right after the backfill marks.
	stand.next.afterEnroll = () => {
		held.ann = [];
		stand.marks.delete("ann");
	};
	expect(await app.get(witnessBackfill).settle("ann")).toBe("marked");
	expect(stand.marks.has("ann")).toBe(true);
});

it("checks the last mark it may make, and clears it where a reset took the factors meanwhile", async () => {
	const held: Record<string, string[]> = { ann: ["code"] };
	// A witness with no withdraw, whose own clear may take any mark.
	const stand = witnessStandIn("enrollment-witness", { withdraw: false });
	// Each late read that sees a reset is followed by a binding; each read after its clear, by a reset.
	const { app } = await boot(held, [stand], (n) => {
		if (n < 2 || n > 7) return;
		if (n % 2 === 0) {
			held.ann = ["code"];
			if (!stand.marks.has("ann")) stand.marks.set("ann", "binding");
		} else {
			held.ann = [];
			stand.marks.delete("ann");
		}
	});
	stand.next.afterEnroll = () => {
		held.ann = [];
		stand.marks.delete("ann");
	};
	expect(await app.get(witnessBackfill).settle("ann")).toBe("none");
	expect(stand.marks.has("ann")).toBe(false);
	expect(held.ann).toEqual([]);
});

it("answers held, not marked, where another marked the subject while it filled", async () => {
	const { app, witness } = await boot({ bob: ["code"] });
	if (!witness) throw new Error("no witness");
	// A binding marks first, under its own token.
	witness.next.beforeEnroll = () => witness.marks.set("bob", "binding");
	expect(await app.get(witnessBackfill).settle("bob")).toBe("held");
	expect(witness.marks.get("bob")).toBe("binding");
});

it("answers marked to one of two backfills at once, and held to the other", async () => {
	const { app } = await boot({ cid: ["code"] });
	const backfill = app.get(witnessBackfill);
	const answers = await Promise.all([backfill.settle("cid"), backfill.settle("cid")]);
	expect(answers.sort()).toEqual(["held", "marked"]);
});

it("reports a mark beside nothing counting it did not set, after a binding's mark and a reset's removal", async () => {
	const held: Record<string, string[]> = { dee: ["code"] };
	const { app, witness } = await boot(held);
	if (!witness) throw new Error("no witness");
	witness.next.beforeEnroll = () => {
		witness.marks.set("dee", "binding");
		held.dee = [];
	};
	expect(await app.get(witnessBackfill).settle("dee")).toBe("inconsistent");
	expect(witness.marks.get("dee")).toBe("binding");
});
