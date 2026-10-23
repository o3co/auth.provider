import { describe, expect, it } from "vitest";
import { ledgerRoutes, usersWire, witnessWire } from "../src/contract.ts";

describe("the user ledger's calls", () => {
	it("puts the identifier under the name the password call reads, and a lookup's keys as asked", () => {
		expect(usersWire.verify("alice", "pw")).toEqual({ email: "alice", password: "pw" });
		expect(usersWire.bySubject("u-1")).toEqual({ subject: "u-1" });
		expect(usersWire.byUpstream("corp", "up-1")).toEqual({ idp: "corp", subject: "up-1" });
	});

	it("says no such user only by a 404 or a 410 naming it, and refuses a password with a 401", () => {
		expect(usersWire.noUser).toEqual({ 404: "not_found", 410: "gone" });
		expect(usersWire.refused).toBe(401);
	});
});

describe("a witness ledger's calls", () => {
	it("sends the subject, the token where it names one, and the deadline of each write", () => {
		expect(witnessWire.read("s")).toEqual({ subject: "s" });
		expect(witnessWire.enroll("s", "t", 9)).toEqual({ subject: "s", token: "t", deadline: 9 });
		expect(witnessWire.withdraw("s", "t", 9)).toEqual({ subject: "s", token: "t", deadline: 9 });
		expect(witnessWire.clear("s", 9)).toEqual({ subject: "s", deadline: 9 });
		expect(witnessWire.written).toBe(204);
	});

	it("reads whether a subject is marked, and where withdraw is offered, the mark's token", () => {
		expect(witnessWire.readAnswer.safeParse({ enrolled: true }).success).toBe(true);
		expect(witnessWire.readAnswer.safeParse({ enrolled: "yes" }).success).toBe(false);
		const mark = (x: unknown) => witnessWire.markAnswer.safeParse(x).success;
		expect([mark({ enrolled: true, token: "t" }), mark({ enrolled: false })]).toEqual([true, true]);
		expect([mark({ enrolled: true }), mark({ enrolled: true, token: "" })]).toEqual([false, false]);
		expect(witnessWire.enrollAnswer.safeParse({ owner: false }).success).toBe(true);
		expect(witnessWire.enrollAnswer.safeParse({}).success).toBe(false);
	});
});

it("serves each call at a route of its own, the same for a fake ledger and the examples", () => {
	const routes = Object.values(ledgerRoutes).flatMap((calls) => Object.values(calls));
	expect(new Set(routes).size).toBe(routes.length);
	expect(Object.keys(ledgerRoutes.mfaWitness)).toEqual(["read", "enroll", "clear", "withdraw"]);
	expect(Object.keys(ledgerRoutes.passkeyWitness)).toEqual(["read", "enroll", "withdraw"]);
});

it("holds every word frozen", () => {
	for (const words of [usersWire, usersWire.noUser, witnessWire, ledgerRoutes]) {
		expect(Object.isFrozen(words)).toBe(true);
	}
	for (const calls of Object.values(ledgerRoutes)) expect(Object.isFrozen(calls)).toBe(true);
});
