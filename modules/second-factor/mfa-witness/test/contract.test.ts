import { expect, it } from "vitest";
import { enrollmentWitnessContract, witnessProblems, witnessStandIn } from "../src/testing.ts";

enrollmentWitnessContract("the stand-in", async () => witnessStandIn().witness);
enrollmentWitnessContract(
	"the stand-in without withdraw",
	async () => witnessStandIn("enrollment-witness", { withdraw: false }).witness,
);

it("tells a witness answering from a lagging replica from one that keeps its promises", async () => {
	const behind = witnessStandIn().witness;
	const lagging = { ...behind, read: async () => false };
	expect(await witnessProblems(lagging)).toContain("a read after an answered enroll misses it");
});

it("tells a witness whose withdraw takes any token's mark from one that keeps its promises", async () => {
	const kept = witnessStandIn().witness;
	const careless = { ...kept, withdraw: (subject: string) => kept.clear(subject) };
	expect(await witnessProblems(careless)).toContain("a withdraw takes another token's mark");
});

it("leaves withdraw out of a stand-in made without it, so a caller tells it is not offered", () => {
	const without = witnessStandIn("enrollment-witness", { withdraw: false }).witness;
	expect([typeof without.withdraw, "withdraw" in without]).toEqual(["undefined", false]);
	expect(typeof witnessStandIn().witness.withdraw).toBe("function");
});
