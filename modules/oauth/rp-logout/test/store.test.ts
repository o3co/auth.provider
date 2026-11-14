import {
	noticeBodiesContract,
	noticeQueueContract,
	pendingNoticesContract,
	sessionClientsContract,
} from "../src/testing.ts";
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
noticeBodiesContract("records stand-in", async () => ({
	bodies: memoryStores(() => now).bodies,
	advance: (ms) => {
		now += ms;
	},
}));
noticeQueueContract("records stand-in", async () => ({ queue: memoryStores(() => now).queue }));
