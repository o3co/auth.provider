import { isUnavailable } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import { type AuthContext, type EntryJudge, sessionRules } from "../../contract.ts";

const context: AuthContext = { subject: "alice", amr: ["pwd"], authenticatedAt: 0 };

describe("session's rules", () => {
	it("takes a proof's start of epoch milliseconds, or none while it may be left out, and throws a TypeError for anything else", () => {
		const facts = { subject: "alice", amr: ["pwd"], authenticatedAt: "opening" as const };
		expect(() => sessionRules.checkProvenSince(facts)).not.toThrow();
		expect(() => sessionRules.checkProvenSince({ ...facts, provenSince: 0 })).not.toThrow();
		for (const provenSince of [-1, 8.64e15 + 1, Number.NaN, "1", null]) {
			expect(
				() => sessionRules.checkProvenSince({ ...facts, provenSince } as never),
				String(provenSince),
			).toThrow(TypeError);
		}
	});

	it("closes each listed session in the listing's order, past one that fails or is left pending, and then fails", async () => {
		const members = async () => ["x", "y", "z"].map((member) => ({ member }));
		const closed: string[] = [];
		const close = async (handle: string) => {
			closed.push(handle);
			if (handle === "x") throw new Error("down");
			return { kind: handle === "y" ? ("pending" as const) : ("closed" as const), cookies: [] };
		};
		await expect(sessionRules.closeListed("alice", { members }, close)).rejects.toSatisfy(
			isUnavailable,
		);
		expect(closed).toEqual(["x", "y", "z"]);
		const done = async () => ({ kind: "closed" as const, cookies: [] });
		await expect(sessionRules.closeListed("alice", { members }, done)).resolves.toBeUndefined();
	});

	it("takes the judge's answer, then at credentials, where nothing judged it, needs a sign-in at a known time that is recent", async () => {
		const judging = (answer: Awaited<ReturnType<EntryJudge["judge"]>>): EntryJudge => ({
			judge: async () => answer,
		});
		const recent = (at: number) => at >= 100;
		const at = (authenticatedAt: number, unknown?: true): AuthContext => ({
			...context,
			authenticatedAt,
			...(unknown && { authenticatedAtUnknown: unknown }),
		});
		const short = { kind: "short", requirement: "mfa", answer: { error: "x" } } as const;
		const step = { requirement: "session", answer: { error: "step_up_required" } };
		const unjudged = sessionRules.judgedShortOf(judging({ kind: "admit", judged: false }), recent);
		expect(await sessionRules.judgedShortOf(judging(short), recent)(at(200), "use")).toEqual({
			requirement: "mfa",
			answer: { error: "x" },
		});
		expect(await unjudged(at(0), "use")).toBeUndefined();
		expect(await unjudged(at(200), "credentials")).toBeUndefined();
		expect(await unjudged(at(0), "credentials")).toEqual(step);
		expect(await unjudged(at(200, true), "credentials")).toEqual(step);
		const judged = sessionRules.judgedShortOf(judging({ kind: "admit", judged: true }), recent);
		expect(await judged(at(0), "credentials")).toBeUndefined();
		const none = sessionRules.judgedShortOf(undefined, recent);
		expect(await none(at(0), "credentials")).toEqual(step);
		expect(await none(at(0), "use")).toBeUndefined();
	});
});
