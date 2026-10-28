import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { describe, expect, it } from "vitest";
import { hintReaders } from "../../contract.ts";
import { hintCheckOver } from "../hint.ts";

describe("hint: an id_token_hint", () => {
	/** The hint check over these readers, as the assembly collects them. */
	const over = (...readers: { read: (hint: string) => Promise<unknown> }[]) =>
		hintCheckOver({
			collect: (async (point: unknown) => (point === hintReaders ? readers : [])) as never,
		});
	const reader = {
		read: async (hint: string) =>
			hint === "id:alice" ? { kind: "subject", subject: "alice" } : { kind: "invalid" },
	};

	it("names the End-User of a hint the reader takes, and refuses one it does not as invalid_request [oidc-core-3.1.2.2-f]", async () => {
		const check = await over(reader);
		expect(await check("id:alice")).toEqual({ kind: "hint", subject: "alice" });
		expect(await check("forged")).toEqual({
			kind: "refuse",
			error: "invalid_request",
			description: "id_token_hint is not valid",
		});
	});

	it("names no End-User for an empty hint or none, nor for any where no module reads hints, as a parameter it does not understand", async () => {
		const read = await over(reader);
		for (const hint of [undefined, ""]) expect(await read(hint)).toEqual({ kind: "hint" });
		const unread = await over();
		for (const hint of ["id:alice", "forged"]) expect(await unread(hint)).toEqual({ kind: "hint" });
	});

	it("is refused at boot where a second module reads hints, the point keyed by one key", async () => {
		const reading = (name: string) =>
			defineModule({ name, replicaSafe: false, takes: [] }, (m) => [
				m.contribute(hintReaders).by(() => ({ read: async () => ({ kind: "invalid" }) as const })),
			]);
		const asking = defineModule(
			{ name: "asking", replicaSafe: false, takes: [hintReaders] },
			(m) => [m.provide(contract<unknown>("asked")).by((c) => hintCheckOver(c))],
		);
		const modules = [reading("one"), reading("two"), asking];
		await expect(
			assemble({ modules, config: kernelConfig(), runtime: quietRuntime() }),
		).rejects.toMatchObject({
			refusals: [
				{
					where: "authorize.hint-reader:hint-reader",
					reason: "more than one contribution for the same key",
				},
			],
		});
	});
});
