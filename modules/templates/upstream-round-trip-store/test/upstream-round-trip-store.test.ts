import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { type Space, store } from "@mod/store";
import { simulatedStore } from "@mod/store/testing";
import { type RoundTripStore, roundTripStore } from "@mod/upstream-round-trip";
import { roundTripStoreContract } from "@mod/upstream-round-trip/testing";
import wiring from "../src/module.ts";

const runtime = quietRuntime({ clock: { now: () => 1_800_000_000_000 } });
/** The walk a maintenance tool hands in, as erasure's type names it. */
type Walk = Parameters<NonNullable<RoundTripStore["walk"]>>[0];

roundTripStoreContract(
	"upstream-round-trip-store on records, on a simulated replicated store",
	async () => {
		const simulated = simulatedStore();
		const app = await assemble({
			modules: [simulated.module, wiring],
			config: kernelConfig(),
			runtime,
		});
		const roundTrips = app.get(roundTripStore);
		const inner = app.get(store);
		// The walk a maintenance tool hands in: the store's own scan, on one server.
		const walk: Walk = {
			sweep: async (space, cursor) => {
				const page = await inner.scan({ name: space, guarantees: [] } as Space, cursor);
				return page.cursor === undefined
					? { keys: page.keys, server: "one" }
					: { keys: page.keys, cursor: page.cursor, server: "one" };
			},
		};
		return {
			roundTrips,
			walkOf: () => walk,
			advance: (ms) => simulated.shiftClock(ms),
			raceNextUpdate: (name, change) =>
				simulated.beforeNext("replaceIf", "upstream-round-trip-store.round-trips", async () => {
					await roundTrips.update(name, (record) => ({ value: change(record) }));
				}),
			loseNextAnswer: () => simulated.loseNextReply(),
			failover: () => simulated.failover(),
			holds: (text) => simulated.holds(text),
		};
	},
);
