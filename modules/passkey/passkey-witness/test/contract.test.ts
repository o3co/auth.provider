import { kernelConfig } from "@mod/kernel";
import { quietRuntime, takesUnused } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import {
	passkeyWitnessContract,
	passkeyWitnessProblems,
	passkeyWitnessStandIn,
} from "../src/testing.ts";

passkeyWitnessContract("the witness in memory", async () => passkeyWitnessStandIn().witness);
it("takes all its stand-in names", async () => {
	const input = {
		modules: [passkeyWitnessStandIn().module],
		config: kernelConfig(),
		runtime: quietRuntime(),
	};
	// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
	expect((await takesUnused(input))["passkey-witness"]).toBeUndefined();
});
it("offers no clear from the witness in memory: passkeys withdraws only by token", () => {
	expect("clear" in passkeyWitnessStandIn().witness).toBe(false);
});

it("names each way a witness's markedWith breaks its promise", async () => {
	/** The witness in memory, its markedWith answering as `lie` says from what it holds. */
	const lying = (lie: (subject: string, marks: Map<string, string>) => string | undefined) => {
		const stand = passkeyWitnessStandIn();
		return { ...stand.witness, markedWith: async (subject: string) => lie(subject, stand.marks) };
	};
	const cases: Record<string, ReturnType<typeof lying>> = {
		"a token for a subject never marked": lying(() => "made-up"),
		"another token than the one its enroll owned": lying((s, m) =>
			m.has(s) ? "other" : undefined,
		),
		"none for a marked subject": lying(() => undefined),
	};
	const { markedWith: _, ...untold } = passkeyWitnessStandIn().witness;
	expect(await passkeyWitnessProblems(untold as never)).toContain(
		"the witness does not tell its mark's token",
	);
	for (const [what, witness] of Object.entries(cases)) {
		expect(await passkeyWitnessProblems(witness), what).not.toEqual([]);
	}
	// One that answers a withdrawn mark's token still.
	const stand = passkeyWitnessStandIn();
	const remembered = new Map<string, string>();
	const sticky = {
		...stand.witness,
		enroll: async (subject: string, token: string) => {
			const owned = await stand.witness.enroll(subject, token);
			if (owned) remembered.set(subject, token);
			return owned;
		},
		markedWith: async (subject: string) => stand.marks.get(subject) ?? remembered.get(subject),
	};
	expect(await passkeyWitnessProblems(sticky)).toContain(
		"markedWith answers the token of a mark withdrawn",
	);
});
