import { execFileSync } from "node:child_process";
import { createServer } from "node:http";
import { join } from "node:path";
import { assemble, kernelConfig } from "@mod/kernel";
import { outboundLimits } from "@mod/outbound-policy";
import { expect, it } from "vitest";
import { outbound } from "../src/contract.ts";
import outboundModule, { section } from "../src/module.ts";

const boot = (settings: Record<string, unknown>) =>
	assemble({ modules: [outboundModule], config: { ...kernelConfig(), outbound: settings } });

it("resolves in its helper processes by default, a plain-ipv4 pair's name to IPv4 alone", async () => {
	const server = createServer((_, res) => res.end("ok"));
	await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
	const { port } = server.address() as { port: number };
	const pair = `localhost:${port}`;
	const app = await boot({
		"allow-any-public": true,
		"plain-loopback": [pair],
		"plain-ipv4": [pair],
	});
	try {
		const answer = await app.get(outbound).fetch(`http://localhost:${port}/`);
		expect(new TextDecoder().decode(answer.body)).toBe("ok");
	} finally {
		await app.stop();
		server.close();
	}
}, 30_000);

it("takes four lookups at once by default, never more than max-concurrent, the outside party's half among them", async () => {
	expect(() => section.parse({ "max-concurrent": 2, "max-lookups": 3 })).toThrow(
		"max-lookups is never more than max-concurrent",
	);
	const shares = async (settings: Record<string, unknown>) => {
		const app = await boot(settings);
		const limits = app.get(outboundLimits);
		const answer = [limits.lookupsOf?.(), limits.lookupsOf?.({ outsideChosen: true })];
		await app.stop();
		return answer;
	};
	expect(await shares({})).toEqual([2, 2]);
	expect(await shares({ "max-concurrent": 1 })).toEqual([1, 0]);
	expect(await shares({ "max-lookups": 6 })).toEqual([3, 3]);
}, 30_000);

it("keeps a process alive while it waits on a lookup at boot, with no other handle open", () => {
	const script = join(import.meta.dirname, "fixtures", "boot-lookup.ts");
	const said = execFileSync(process.execPath, [script], { encoding: "utf8", timeout: 20_000 });
	expect(said).toBe("unreachable\n");
}, 30_000);
