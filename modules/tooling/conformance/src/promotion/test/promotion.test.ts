import { describe, expect, it } from "vitest";
import type { Reply } from "../../relay/relay.ts";
import { type Member, type Membership, promote } from "../promotion.ts";

const ok: Reply = { kind: "simple", text: "OK" };
const bulk = (text: string): Reply => ({ kind: "bulk", data: Buffer.from(text) });

/** A member that answers as a caught-up node of one history, recording what it was told. */
function member(name: string, told: string[][] = [], online = 1): Member & { told: string[][] } {
	return {
		name,
		told,
		ask: async (...args) => {
			told.push(args);
			if (args[0] === "INFO")
				return bulk(
					[
						"master_replid:one",
						"master_repl_offset:10",
						"slave_repl_offset:10",
						...Array.from({ length: online }, (_, i) => `slave${i}:ip=x,state=online`),
					].join("\n"),
				);
			return ok;
		},
	};
}

function membership(old: Member, nodes: Member[]): Membership<Member> & { killed: Set<string> } {
	let primary = old;
	const follows = new Map(nodes.map((n) => [n.name, n === old ? undefined : old.name]));
	return {
		nodes,
		follows,
		killed: new Set(),
		primary: () => primary,
		setPrimary: (n) => {
			primary = n;
		},
		kill: () => {},
	};
}

describe("a promotion whose step outlasts its barrier", () => {
	it("fails every time, before the old primary goes, however the deadline's timer fires", async () => {
		for (let round = 0; round < 25; round++) {
			const old = member("old");
			const [next, other] = [member("next"), member("other")];
			const m = membership(old, [old, next, other]);
			await expect(
				promote(m, {
					replica: next,
					reattach: [other],
					catchUpMs: 0,
					holdMs: 1_050,
					// Never done: the deadline must end it.
					between: () => new Promise(() => {}),
				}),
			).rejects.toThrow(/barrier/);
			expect(m.killed.size).toBe(0);
			expect(next.told.some((a) => a[0] === "REPLICAOF")).toBe(false);
		}
	});
});

describe("a barrier whose answer was lost", () => {
	it("releases the old primary's writes, though the pause may have been applied", async () => {
		const told: string[][] = [];
		const base = member("old", told);
		// Redis applies the pause, and the connection closes before its OK comes back.
		const old: Member = {
			name: "old",
			ask: async (...args) => {
				if (args[0] === "CLIENT" && args[1] === "PAUSE") {
					told.push(args);
					throw new Error("closed before its reply to CLIENT");
				}
				return base.ask(...args);
			},
		};
		const [next, other] = [member("next"), member("other")];
		const m = membership(old, [old, next, other]);
		await expect(promote(m, { replica: next, reattach: [other] })).rejects.toThrow(/closed/);
		expect(told.map((a) => a.slice(0, 2).join(" "))).toContain("CLIENT UNPAUSE");
		expect(m.primary().name).toBe("old");
	});
});
