import { refreshLocks, upstreamTokenStore } from "@mod/federation-tokens";
import { upstreamTokenStoreContract } from "@mod/federation-tokens/testing";
import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { simulatedStore } from "@mod/store/testing";
import { describe, expect, it } from "vitest";
import wiring from "../src/module.ts";

const runtime = quietRuntime({ clock: { now: () => 1_800_000_000_000 } });

upstreamTokenStoreContract(
	"federation-tokens-store on records, on a simulated replicated store",
	async () => {
		const simulated = simulatedStore();
		const app = await assemble({
			modules: [simulated.module, wiring],
			config: kernelConfig(),
			runtime,
		});
		const records = app.get(upstreamTokenStore);
		return {
			records,
			locks: app.get(refreshLocks),
			advance: (ms) => simulated.shiftClock(ms),
			raceNextUpdate: (session, change) =>
				simulated.beforeNext("replaceIf", "federation-tokens-store.tokens", async () => {
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

describe("the spaces federation-tokens-store declares", () => {
	const opened = async () => {
		const simulated = simulatedStore();
		const app = await assemble({
			modules: [simulated.module, wiring],
			config: kernelConfig(),
			runtime,
		});
		return { simulated, records: app.get(upstreamTokenStore), locks: app.get(refreshLocks) };
	};

	it("keeps records and locks when memory runs short", async () => {
		const { simulated, records, locks } = await opened();
		const record = { format: 1, idps: {} } as never;
		await records.save("s-1", record, 60_000);
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
