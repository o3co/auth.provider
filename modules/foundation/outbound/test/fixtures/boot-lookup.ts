// Assembles outbound alone and resolves one name, with no other handle open: the lookup's helper
// must keep this process alive until its answer, as discovery does at boot before anything listens.
import { assemble, kernelConfig } from "@mod/kernel";
import { isOutboundUnavailable, outbound } from "../../src/contract.ts";
import outboundModule from "../../src/module.ts";

const app = await assemble({
	modules: [outboundModule],
	config: { ...kernelConfig(), outbound: { "allow-any-public": true } },
});
const answer = await app
	.get(outbound)
	.fetch("https://nowhere.invalid/")
	.then(
		() => "answered",
		(error: unknown) => (isOutboundUnavailable(error) ? error.failure : "other"),
	);
process.stdout.write(`${answer}\n`);
await app.stop();
