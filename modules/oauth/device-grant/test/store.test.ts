import { deviceStoreContract } from "../src/testing.ts";
import { recordsStandIn } from "./stand-in.ts";

deviceStoreContract("records stand-in", async () => {
	let now = 0;
	const { devices, userCodes, approvals, kept } = recordsStandIn(() => now);
	return {
		// The walk alone, not composed: in memory, erasure's other ports are not offered.
		devices: { ...devices, walk: kept.records.walk },
		userCodes,
		approvals,
		walkOf: () => ({ sweep: async () => ({ keys: [], server: "one" }) }),
		advance: (ms) => {
			now += ms;
		},
		raceNextUpdate: (_name, change) => kept.raceNextChange(change),
	};
});
