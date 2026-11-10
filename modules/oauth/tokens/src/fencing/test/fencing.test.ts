import { assemble, defineModule, isUnavailable, type Module, Unavailable } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import { composedConfig, composedModules } from "../../../test/composed.ts";
import { type FencedBundle, issuanceFences, issuanceFencing } from "../../contract.ts";

/** tokens with fences contributed in this order, each answering as given and noting what it was asked. */
async function boot(answers: readonly ("passed" | "refused" | "unavailable")[]) {
	const asked: { readonly fence: string; readonly bundle: FencedBundle }[] = [];
	const fences: Module[] = answers.map((answer, n) =>
		defineModule({ name: `fence-${n}`, replicaSafe: true, takes: [] }, (m) => [
			m.contribute(issuanceFences).by(() => ({
				name: `fence-${n}`,
				fence: async (bundle) => {
					asked.push({ fence: `fence-${n}`, bundle });
					if (answer === "unavailable") throw new Unavailable(`fence-${n}`);
					return answer;
				},
			})),
		]),
	);
	let n = 0;
	const app = await assemble({
		modules: [...composedModules, ...fences],
		config: { ...composedConfig(), tokens: { "subject-check": "none", revocation: "unsupported" } },
		runtime: quietRuntime({ random: { bytes: (size) => new Uint8Array(size).fill(++n) } }),
	});
	return { fencing: app.get(issuanceFencing), asked };
}

it("passes a bundle with no fence, making no receipt", async () => {
	const { fencing, asked } = await boot([]);
	expect(await fencing.pass({ subject: "alice" })).toEqual({ kind: "passed" });
	expect(asked).toEqual([]);
});

it("passes a bundle through every fence in order, under one receipt id each bundle", async () => {
	const { fencing, asked } = await boot(["passed", "passed"]);
	expect(await fencing.pass({ subject: "alice" })).toEqual({ kind: "passed" });
	await fencing.pass({ subject: "bob" });
	expect(asked.map((a) => [a.fence, a.bundle.subject])).toEqual([
		["fence-0", "alice"],
		["fence-1", "alice"],
		["fence-0", "bob"],
		["fence-1", "bob"],
	]);
	const ids = asked.map((a) => a.bundle.receiptId);
	expect(ids[0]).toBe(ids[1]);
	expect(ids[2]).toBe(ids[3]);
	expect(ids[0]).not.toBe(ids[2]);
	expect(Buffer.from(ids[0] ?? "", "base64url")).toHaveLength(16);
});

it("ends at the first fence to refuse, naming it with any refusal's description, and is unavailable where one cannot tell", async () => {
	const refusing = await boot(["passed", "refused", "passed"]);
	expect(await refusing.fencing.pass({ subject: "alice" })).toEqual({
		kind: "refused",
		fence: "fence-1",
		description: "issuance refused",
	});
	expect(refusing.asked.map((a) => a.fence)).toEqual(["fence-0", "fence-1"]);
	const failing = await boot(["unavailable"]);
	const failed = await failing.fencing.pass({ subject: "alice" }).catch((e: unknown) => e);
	expect(isUnavailable(failed)).toBe(true);
});
