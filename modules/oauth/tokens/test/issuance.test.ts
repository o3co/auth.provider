import { isUnavailable } from "@mod/kernel";
import { expect, it } from "vitest";
import type { IssuancePolicy } from "../src/contract.ts";
import { judging } from "../src/issuance/issuance.ts";
import { section } from "../src/section.ts";

const request = {
	grant: { subject: "s", issuedTo: "c", audience: ["api"], scope: [] },
	grantType: "test",
} as const;

/** A deadline the test fires itself, so no load on the machine moves it. */
const deadlineFired = () => {
	const deadline = new AbortController();
	return { deadline, of: () => deadline.signal };
};

it("answers unavailable once the policies' deadline passes, aborting the policy's signal, and allows nothing", async () => {
	const seen: AbortSignal[] = [];
	const hanging: IssuancePolicy = {
		name: "hanging",
		judge: (_request, signal) => {
			if (signal) seen.push(signal);
			return new Promise(() => {});
		},
	};
	const { deadline, of } = deadlineFired();
	const judged = judging([hanging], () => 0, of)(request);
	deadline.abort();
	await expect(judged).rejects.toSatisfy(isUnavailable);
	expect(seen.map((signal) => signal.aborted)).toEqual([true]);
});

it("holds one deadline over every policy together, asking none once it passed", async () => {
	const asked: string[] = [];
	const { deadline, of } = deadlineFired();
	const first: IssuancePolicy = {
		name: "a",
		judge: async () => {
			asked.push("a");
			deadline.abort();
			return { kind: "allowed" };
		},
	};
	const second: IssuancePolicy = {
		name: "b",
		judge: async () => {
			asked.push("b");
			return { kind: "allowed" };
		},
	};
	await expect(judging([second, first], () => 0, of)(request)).rejects.toSatisfy(isUnavailable);
	expect(asked).toEqual(["a"]);
});

it("judges as before within the deadline", async () => {
	const allowing: IssuancePolicy = { name: "a", judge: async () => ({ kind: "allowed" }) };
	expect(await judging([allowing], () => 0, deadlineFired().of)(request)).toEqual({
		kind: "allowed",
	});
});

it("takes the policies' deadline written with its unit, from 1s to 1m, 10s unless set", () => {
	const parsed = (value?: string) =>
		section.safeParse({ revocation: "denylist", ...(value ? { "issuance-timeout": value } : {}) });
	expect(parsed().data?.["issuance-timeout"]).toBe(10_000);
	expect(["1s", "1m", "2500ms"].map((value) => parsed(value).data?.["issuance-timeout"])).toEqual([
		1000, 60_000, 2500,
	]);
	expect(["999ms", "61s", "10"].map((value) => parsed(value).success)).toEqual([
		false,
		false,
		false,
	]);
});
