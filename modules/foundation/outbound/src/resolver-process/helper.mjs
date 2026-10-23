// The helper a resolver pool starts: it resolves each name it is sent as the system does, and
// answers with the addresses or the error's code alone. It ends itself when its parent is gone.
import { lookup } from "node:dns/promises";

const gen = Number(process.argv[2]);
const send = (message) => {
	try {
		process.send?.({ gen, ...message });
	} catch {
		process.exit(0);
	}
};
process.on("disconnect", () => process.exit(0));
process.on("message", async (message) => {
	const { id, name, family } = message ?? {};
	try {
		const found = await lookup(name, {
			all: true,
			verbatim: true,
			...(family === 4 ? { family } : {}),
		});
		send({ id, addresses: found.map((each) => each.address) });
	} catch (error) {
		send({ id, code: typeof error?.code === "string" ? error.code : "EAI_FAIL" });
	}
});
send({ ready: true });
