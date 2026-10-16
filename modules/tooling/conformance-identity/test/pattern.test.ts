import { expect, it } from "vitest";
import { statedWhereJudged } from "../src/pattern.ts";

const alice = { identifier: "alice", password: "pw" };
const bob = { identifier: "bob", password: "pw" };

it("states every user verified, keeping an address given, where verified-email judges a scene that states none", () => {
	const addressed = { ...alice, email: "a@example.com" };
	expect(statedWhereJudged([addressed, bob], ["@mod/verified-email"])).toEqual([
		{ ...addressed, emailVerified: true },
		{ ...bob, email: "bob@users.example", emailVerified: true },
	]);
});

it("leaves the users as the scene gave them where verified-email is not composed, or one is stated either way", () => {
	expect(statedWhereJudged([alice, bob], ["@mod/users"])).toEqual([alice, bob]);
	const stated = [alice, { ...bob, emailVerified: false }];
	expect(statedWhereJudged(stated, ["@mod/verified-email"])).toEqual(stated);
});
