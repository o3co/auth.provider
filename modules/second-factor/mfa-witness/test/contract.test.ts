import { expect, it } from "vitest";
import { enrollmentWitnessContract, witnessProblems, witnessStandIn } from "../src/testing.ts";

enrollmentWitnessContract("the stand-in", async () => witnessStandIn().witness);

it("tells a witness answering from a lagging replica from one that keeps its promises", async () => {
	const behind = witnessStandIn().witness;
	const lagging = { ...behind, read: async () => false };
	expect(await witnessProblems(lagging)).toContain("a read after an answered enroll misses it");
});
