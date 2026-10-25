import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { takesUnused } from "@mod/kernel/testing";
import { type AuthContext, type EntryJudge, type EntryLevel, entryJudge } from "@mod/session";
import { expect, it } from "vitest";
import { type EntryRequirement, entryRequirements } from "../src/contract.ts";
import { judgeOf } from "../src/judge.ts";
import requirementsModule from "../src/module.ts";

const context: AuthContext = { subject: "alice", amr: ["pwd"], authenticatedAt: 0 };
const asked: string[] = [];
const requirement = (
	name: string,
	short: readonly EntryLevel[],
	judges: readonly EntryLevel[] = short,
): EntryRequirement => ({
	name,
	judges,
	admits: async (_context, level) => {
		asked.push(name);
		return short.includes(level) ? { kind: "short", answer: { error: name } } : { kind: "admit" };
	},
});

it("asks the requirements in name order and answers the first that falls short, asking no later one", async () => {
	asked.length = 0;
	const judge = judgeOf([
		requirement("c", ["use"]),
		requirement("a", []),
		requirement("b", ["use"]),
	]);
	expect(await judge.judge(context, "use")).toEqual({
		kind: "short",
		requirement: "b",
		answer: { error: "b" },
	});
	expect(asked).toEqual(["a", "b"]);
});

it("admits where none falls short, saying whether one judged the level", async () => {
	const judge = judgeOf([requirement("a", [], ["credentials"])]);
	expect(await judge.judge(context, "credentials")).toEqual({ kind: "admit", judged: true });
	expect(await judge.judge(context, "use")).toEqual({ kind: "admit", judged: false });
	expect(await judgeOf([]).judge(context, "credentials")).toEqual({ kind: "admit", judged: false });
});

it("contributes the one entry judge over the requirements the composition contributes", async () => {
	const judged = contract<EntryJudge>("test.judged");
	const reading = defineModule({ name: "reading", takes: [entryJudge] }, (m) => [
		m.provide(judged).by(async (c) => {
			const [judge] = await c.collect(entryJudge);
			if (!judge) throw new Error("no judge");
			return judge;
		}),
		m.contribute(entryRequirements).by(() => requirement("mfa", ["use"])),
	]);
	const app = await assemble({ modules: [requirementsModule, reading], config: kernelConfig() });
	expect(
		(await takesUnused({ modules: [requirementsModule, reading], config: kernelConfig() }))[
			"session-requirements"
		],
	).toBeUndefined();
	expect(await app.get(judged).judge(context, "use")).toMatchObject({ requirement: "mfa" });
});
