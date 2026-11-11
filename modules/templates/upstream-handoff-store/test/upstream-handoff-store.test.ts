import { assemble, type BuildContext, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { simulatedStore } from "@mod/store/testing";
import { heldLoginStore, type StoredHeldLogin } from "@mod/upstream-handoff";
import { heldLoginStoreContract } from "@mod/upstream-handoff/testing";
import { expect, it } from "vitest";
import wiring from "../src/module.ts";

const runtime = quietRuntime({ clock: { now: () => 1_800_000_000_000 } });

/** The wiring over a simulated store, its records in the phase given; and the composition's readiness. */
async function opened(phase: "reader" | "indexed" = "reader", blip = false) {
	const simulated = simulatedStore();
	if (phase === "indexed") simulated.mark("subject-records.phase", "indexed");
	simulated.unreachable(blip);
	let context: BuildContext<unknown> | undefined;
	const app = await assemble({
		modules: [
			simulated.module,
			wiring,
			defineModule({ name: "asker", replicaSafe: false, takes: [] }, (m) => [
				m.provide(contract<object>("asker")).by((c) => {
					context = c;
					return {};
				}),
			]),
		],
		config: kernelConfig(),
		runtime,
	});
	const ready = () => context?.readinessReport(1000).then((r) => r.answer);
	return { app, simulated, ready };
}

for (const phase of ["reader", "indexed"] as const) {
	heldLoginStoreContract(
		`upstream-handoff-store on subject-records, ${phase}, on a simulated replicated store`,
		async () => {
			const { app, simulated } = await opened(phase);
			const held = app.get(heldLoginStore);
			return {
				held,
				advance: (ms) => simulated.shiftClock(ms),
				// A bounded record is kept raw, watching no tombstone: one partition.
				raceNextUpdate: (name, change) =>
					simulated.beforeNext("batch", "upstream-handoff-store.held-logins", async () => {
						await held.update(name, (record) => ({ value: change(record) }));
					}),
				loseNextAnswer: () => simulated.loseNextReply(),
				failover: () => simulated.failover(),
				holds: (text) => simulated.holds(text),
			};
		},
	);
}

it("fences a subject's held logins: an old one changed until its end, no new one saved, another subject's saved", async () => {
	const { app } = await opened("indexed");
	const held = app.get(heldLoginStore);
	const login = (n: number) => ({ n }) as unknown as StoredHeldLogin;
	await held.save("h", login(1), 60_000, "alice");
	expect(await held.erase?.("alice", new AbortController().signal)).toMatchObject({
		kind: "fenced",
	});
	expect(await held.save("h2", login(2), 60_000, "alice")).toBe("erased");
	expect(await held.save("h3", login(3), 60_000, "bob")).toBe("created");
	// One held before the erasure ends by its own end; the subject's sessions are revoked, so none takes it.
	expect(await held.update("h", () => ({ value: login(4) }))).toMatchObject({ after: { n: 4 } });
});

it("keeps no held login past upstream-handoff's bound", async () => {
	const { app } = await opened("indexed");
	const held = app.get(heldLoginStore);
	await expect(
		held.save("h", { n: 1 } as unknown as StoredHeldLogin, 3_600_001, "alice"),
	).rejects.toBeInstanceOf(TypeError);
});

it("starts over a store's blip unready, out of traffic, and turns ready once the store answers", async () => {
	const { simulated, ready } = await opened("indexed", true);
	expect(await ready()).toBe("unready");
	simulated.unreachable(false);
	expect(await ready()).toBe("ready");
});
