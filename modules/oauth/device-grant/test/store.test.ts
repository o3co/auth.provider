import { deviceStoreContract } from "../src/testing.ts";
import { recordsStandIn } from "./stand-in.ts";

deviceStoreContract("records stand-in", async () => {
	let now = 0;
	const { devices, userCodes, kept } = recordsStandIn(() => now);
	return {
		devices,
		userCodes,
		advance: (ms) => {
			now += ms;
		},
		raceNextUpdate: (_name, change) => kept.raceNextChange(change),
	};
});
