import { refreshLocks, upstreamTokenStore } from "@mod/federation-tokens";
import { upstreamTokenStoreContract } from "@mod/federation-tokens/testing";
import { assemble, type BuildContext, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { simulatedStore } from "@mod/store/testing";
import { describe, expect, it } from "vitest";
import wiring from "../src/module.ts";

const runtime = quietRuntime({ clock: { now: () => 1_800_000_000_000 } });

/** The wiring on a simulated store, its records raw (`reader`) or indexed, unreachable at first where `blip`. */
async function open(phase: "reader" | "indexed" = "reader", blip = false) {
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
	return { simulated, ready, records: app.get(upstreamTokenStore), locks: app.get(refreshLocks) };
}

for (const phase of ["reader", "indexed"] as const) {
	// A record's change in indexed records watches its subject's tombstone: a batch across.
	const tokensWrite = phase === "indexed" ? "batchAcross" : "batch";
	upstreamTokenStoreContract(
		`federation-tokens-store on subject-records, ${phase}, on a simulated replicated store`,
		async () => {
			const { simulated, records, locks } = await open(phase);
			return {
				records,
				locks,
				advance: (ms) => simulated.shiftClock(ms),
				raceNextUpdate: (session, change) =>
					simulated.beforeNext(tokensWrite, "federation-tokens-store.tokens", async () => {
						await records.update(session, (record) => ({
							value: change(record),
							lifetimeMs: 60_000,
						}));
					}),
				loseNextAnswer: () => simulated.loseNextReply(),
				failover: () => simulated.failover(),
			};
		},
	);
}

it("erases a subject's records, refusing a new one for the subject and leaving another's", async () => {
	const { records } = await open("indexed");
	const record = (n: number) => ({ format: 1, idps: {}, n }) as never;
	await records.save("s-1", record(1), 60_000, "alice");
	await records.save("s-2", record(2), 60_000, "bob");
	expect(await records.erase?.("alice", new AbortController().signal)).toMatchObject({
		kind: "erased",
		removed: 1,
	});
	expect(await records.read("s-1")).toBeUndefined();
	expect(await records.save("s-3", record(3), 60_000, "alice")).toBe("erased");
	expect(await records.read("s-2")).toEqual(record(2));
});

it("starts over a store's blip unready, out of traffic, and turns ready once the store answers", async () => {
	const { simulated, ready } = await open("indexed", true);
	expect(await ready()).toBe("unready");
	simulated.unreachable(false);
	expect(await ready()).toBe("ready");
});

describe("the spaces federation-tokens-store declares", () => {
	const opened = () => open();

	it("keeps records and locks when memory runs short", async () => {
		const { simulated, records, locks } = await opened();
		const record = { format: 1, idps: {} } as never;
		await records.save("s-1", record, 60_000, "alice");
		await locks.hold("s-1\ncorp", "a", 60_000);
		await simulated.pressMemory();
		expect(await records.read("s-1")).toEqual(record);
		expect(await locks.hold("s-1\ncorp", "b", 60_000)).toBe("exists");
	});

	it("keeps locks in a space of their own, apart from the records", async () => {
		const { simulated, locks } = await opened();
		let seen = false;
		simulated.beforeNext("putIfAbsent", "federation-tokens-store.locks", async () => {
			seen = true;
		});
		await locks.hold("s-1\ncorp", "a", 60_000);
		expect(seen).toBe(true);
	});
});
