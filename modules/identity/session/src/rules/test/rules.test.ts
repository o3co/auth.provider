import { isUnavailable } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import {
	type AuthContext,
	type EntryLevel,
	type EntryRequirement,
	type Session,
	sessionRules,
} from "../../contract.ts";

const context: AuthContext = { subject: "alice", amr: ["pwd"], authenticatedAt: 0 };
const session: Session = { id: "h", context };

describe("session's rules", () => {
	it("calls the participants one at a time in the order given, past a failing one, and answers each that failed", async () => {
		const calls: string[] = [];
		let running = 0;
		let overlapped = false;
		const participant = (name: string, fails?: unknown) => ({
			name,
			closing: async () => {
				running++;
				overlapped ||= running > 1;
				calls.push(name);
				await new Promise((resolve) => setTimeout(resolve, 5));
				running--;
				if (fails !== undefined) throw fails;
			},
		});
		const given = [participant("b", new TypeError("x")), participant("a"), participant("c", "x")];
		expect(await sessionRules.failedParticipants(given, session)).toEqual([
			{ participant: "b", kind: "TypeError" },
			{ participant: "c", kind: "string" },
		]);
		expect(calls).toEqual(["b", "a", "c"]);
		expect(overlapped).toBe(false);
		expect(await sessionRules.failedParticipants([participant("a")], session)).toEqual([]);
	});

	it("asks the requirements in name order, and answers the first that falls short", async () => {
		const asked: string[] = [];
		const requirement = (name: string, short: boolean) => ({
			name,
			judges: ["use" as const],
			admits: async () => {
				asked.push(name);
				return short ? { kind: "short" as const, answer: name } : { kind: "admit" as const };
			},
		});
		const given = [requirement("c", true), requirement("a", false), requirement("b", true)];
		expect(await sessionRules.firstShortOf(given)(context, "use")).toEqual({
			requirement: "b",
			answer: "b",
		});
		expect(asked).toEqual(["a", "b"]);
		expect(await sessionRules.firstShortOf([requirement("a", false)])(context, "use")).toBe(
			undefined,
		);
	});

	describe("entry where no requirement judges changing credentials", () => {
		const at = 1_000_000;
		const now = () => at;
		const signedIn = (authenticatedAt: number): AuthContext => ({ ...context, authenticatedAt });
		const unknown: AuthContext = { ...context, authenticatedAt: at, authenticatedAtUnknown: true };
		const stepUp = { requirement: "session", answer: { error: "step_up_required" } };
		const judging = (judges: readonly EntryLevel[]): EntryRequirement => ({
			name: "r",
			judges,
			admits: async () => ({ kind: "admit" }),
		});

		it("needs a sign-in at a known time within the seconds given, and nothing at other levels", async () => {
			const shortOf = sessionRules.entryShortOf([], now, 300_000);
			expect(await shortOf(signedIn(at - 300_000), "credentials")).toBe(undefined);
			expect(await shortOf(signedIn(at - 300_001), "credentials")).toEqual(stepUp);
			expect(await shortOf(unknown, "credentials")).toEqual(stepUp);
			for (const level of ["use", "none"] as const) {
				expect(await shortOf(unknown, level)).toBe(undefined);
			}
			const byDefault = sessionRules.entryShortOf([], now);
			expect(await byDefault(signedIn(at - 300_000), "credentials")).toBe(undefined);
			expect(await byDefault(signedIn(at - 300_001), "credentials")).toEqual(stepUp);
			expect(sessionRules.credentialsSecondsDefault).toBe(300);
		});

		it("leaves credentials to a requirement that judges them, after asking each, and to none that judges only others", async () => {
			const judged = sessionRules.entryShortOf([judging(["credentials"])], now, 300_000);
			expect(await judged(unknown, "credentials")).toBe(undefined);
			for (const judges of [["use"], []] as const) {
				const shortOf = sessionRules.entryShortOf([judging(judges)], now, 300_000);
				expect(await shortOf(unknown, "credentials")).toEqual(stepUp);
			}
			// @ts-expect-error A requirement says which levels it judges.
			const undeclared: EntryRequirement = { name: "x", admits: async () => ({ kind: "admit" }) };
			expect(undeclared.judges).toBeUndefined();
			const short = {
				...judging(["use"]),
				admits: async () => ({ kind: "short" as const, answer: 1 }),
			};
			const first = sessionRules.entryShortOf([short], now, 300_000);
			expect(await first(unknown, "credentials")).toEqual({ requirement: "r", answer: 1 });
		});
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
});
