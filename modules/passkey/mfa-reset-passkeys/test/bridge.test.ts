import { assemble, contract, defineModule, kernelConfig, Unavailable } from "@mod/kernel";
import { takesUnused } from "@mod/kernel/testing";
import { type ResetPart, resetParts } from "@mod/mfa-reset";
import { type PasskeyResetPart, passkeyResetPart } from "@mod/passkey-reset";
import { expect, it } from "vitest";
import bridge from "../src/module.ts";

/** The bridge over a part answering `answer`, with a probe reading the reset parts. */
function composition(answer: PasskeyResetPart["passkeys"]) {
	const asked: string[] = [];
	const scripted = defineModule({ name: "scripted-part", takes: [] }, (m) => [
		m.provide(passkeyResetPart).by(() => ({
			passkeys: async (subject) => {
				asked.push(subject);
				return answer(subject);
			},
		})),
	]);
	const parts = contract<readonly ResetPart[]>("test.parts");
	const probe = defineModule({ name: "probe", takes: [resetParts] }, (m) => [
		m.provide(parts).by((c) => c.collect(resetParts)),
	]);
	return { input: { modules: [scripted, bridge, probe], config: kernelConfig() }, parts, asked };
}

/** The bridge over a part answering `answer`, and the reset part it contributes. */
async function contributed(answer: PasskeyResetPart["passkeys"]) {
	const { input, parts, asked } = composition(answer);
	const app = await assemble(input);
	const [part, ...more] = app.get(parts);
	expect(more).toEqual([]);
	if (!part) throw new Error("no part contributed");
	return { part, asked };
}

it("takes all it names", async () => {
	const { input } = composition(async () => ({ kind: "done", removed: 0 }));
	// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
	expect((await takesUnused(input))["mfa-reset-passkeys"]).toBeUndefined();
});

it("contributes the part named passkeys, as the reset's audit names it", async () => {
	const { part } = await contributed(async () => ({ kind: "done", removed: 0 }));
	expect(part.name).toBe("passkeys");
});

it("answers what the passkeys' step answers, as it is", async () => {
	const done = await contributed(async () => ({ kind: "done", removed: 2 }));
	expect(await done.part.remove("ann")).toEqual({ kind: "done", removed: 2 });
	expect(done.asked).toEqual(["ann"]);
	const stopped = await contributed(async () => ({ kind: "stopped" }));
	expect(await stopped.part.remove("ann")).toEqual({ kind: "stopped" });
	const thrown = await contributed(async () => {
		throw new TypeError("broken");
	});
	await expect(thrown.part.remove("ann")).rejects.toThrow(TypeError);
	const unavailable = await contributed(async () => {
		throw new Unavailable("passkeys");
	});
	await expect(unavailable.part.remove("ann")).rejects.toThrow(Unavailable);
});
