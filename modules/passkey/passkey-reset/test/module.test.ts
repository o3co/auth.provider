import { audit } from "@mod/audit";
import { assemble, type BootRefused, contract, defineModule, kernelConfig } from "@mod/kernel";
import { takesUnused } from "@mod/kernel/testing";
import { passkeyHolders } from "@mod/passkeys";
import { revocations } from "@mod/subject-revocation";
import { expect, it } from "vitest";
import { passkeyReset, passkeyResetPart } from "../src/contract.ts";
import resetModule from "../src/module.ts";

/** The contracts the reset takes, answering as scripted, recording what they were asked. */
const parts = (calls: string[]) =>
	defineModule({ name: "parts", replicaSafe: false, takes: [] }, (m) => [
		m.provide(revocations).by(
			() =>
				({
					record: async (subject: string) => {
						calls.push(`record ${subject}`);
						return { complete: true };
					},
				}) as never,
		),
		m.provide(passkeyHolders).by(
			() =>
				({
					cleared: async (subject: string) => {
						calls.push(`cleared ${subject}`);
						return { removed: 1 };
					},
				}) as never,
		),
		m.provide(audit).by(() => ({ record: () => {}, lost: () => ({}) })),
	]);

it("takes all it names", async () => {
	// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
	expect(
		(await takesUnused({ modules: [parts([]), resetModule], config: kernelConfig() }))[
			"passkey-reset"
		],
	).toBeUndefined();
});

it("resets over the contracts it is given, and offers the passkeys' step alone over the same holdings", async () => {
	const calls: string[] = [];
	const app = await assemble({ modules: [parts(calls), resetModule], config: kernelConfig() });
	expect(await app.get(passkeyReset).reset("ann")).toEqual({ kind: "done", removed: 1 });
	expect(calls).toEqual(["record ann", "cleared ann", "record ann"]);
	// The embedder's own code takes any contract: takenBy binds modules, not who composes them.
	expect(await app.get(passkeyResetPart).passkeys("bob")).toEqual({ kind: "done", removed: 1 });
	expect(calls.slice(3)).toEqual(["cleared bob"]);
});

it("gives the passkeys' step to the bridge alone, refusing boot to any other module that takes it", async () => {
	const took = contract<unknown>("test.took");
	const taker = (name: string) =>
		defineModule({ name, replicaSafe: true, takes: [passkeyResetPart] }, (m) => [
			m.provide(took).by(async (c) => c.get(passkeyResetPart)),
		]);
	const composedWith = (name: string) =>
		assemble({
			modules: [parts([]), resetModule, taker(name)],
			config: kernelConfig(),
		}).then((app) => app.get(took));
	await expect(composedWith("mfa-reset-passkeys")).resolves.toBeDefined();
	const refused = await composedWith("someone-else").catch((error: unknown) => error);
	expect((refused as BootRefused).refusals).toEqual([
		{ where: "someone-else", reason: "passkey-reset.part is taken by mfa-reset-passkeys alone" },
	]);
});
