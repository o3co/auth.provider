import { pendingNoticesContract, sessionClientsContract } from "../src/testing.ts";
import { memoryStores } from "./stores.ts";

let now = 0;
sessionClientsContract("records stand-in", async () => {
	const { clients, size } = memoryStores(() => now);
	return {
		clients,
		size,
		advance: (ms) => {
			now += ms;
		},
	};
});
pendingNoticesContract("records stand-in", async () => ({
	notices: memoryStores(() => now).notices,
}));
