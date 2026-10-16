import { userAttribute } from "@mod/users";
import { describe, expect, it } from "vitest";
import { keptAttributes, loginSource, sourcedAttributesShape } from "../src/contract.ts";

const keptOf = (source: unknown, values: unknown) => keptAttributes({ source, values }).kept;
const bytes = (count: number) => `${"é".repeat(Math.floor(count / 2))}${"a".repeat(count % 2)}`;
const groups = (count: number) => Array.from({ length: count }, (_, n) => `g${n}`);

describe("login sources", () => {
	it("names users' ledger, and an upstream by its IdP, never as users", () => {
		expect(loginSource.users).toBe("users");
		expect(loginSource.upstream("corp")).toBe("upstream:corp");
		for (const idp of ["users", "", ":users"]) {
			expect(loginSource.upstream(idp)).not.toBe(loginSource.users);
		}
		expect(Object.isFrozen(loginSource)).toBe(true);
	});
});

describe("keeping a login's attributes", () => {
	it("keeps a frozen copy of the named ones, read once, unchanged by the giver afterwards", () => {
		const values = {
			email: "alice@example.com",
			email_verified: true,
			name: "Alice",
			picture: "https://pictures.example/alice",
			groups: ["staff", "ops"],
		};
		const kept = keptOf("users", values);
		values.groups.push("admin");
		values.name = "Mallory";
		expect(kept).toEqual({
			source: "users",
			values: { ...values, name: "Alice", groups: ["staff", "ops"] },
		});
		expect(Object.isFrozen(kept)).toBe(true);
		expect(Object.isFrozen(kept?.values)).toBe(true);
		expect(Object.isFrozen(kept?.values.groups)).toBe(true);
		let reads = 0;
		const counted = {
			get name() {
				reads++;
				return reads === 1 ? "Al" : "n".repeat(600);
			},
		};
		expect(keptOf("users", counted)?.values).toEqual({ name: "Al" });
		expect(reads).toBe(1);
	});

	it("keeps only the named attributes within their caps, dropping each other one whole", () => {
		const within = {
			email: `${"a".repeat(242)}@example.com`,
			name: bytes(512),
			picture: `https://p.example/${"a".repeat(2048 - 18)}`,
			groups: [...groups(63), bytes(256)],
		};
		expect(keptOf("users", within)?.values).toEqual(within);
		const over = {
			email: `${"a".repeat(243)}@example.com`,
			name: bytes(513),
			picture: `https://p.example/${"a".repeat(2048 - 17)}`,
			groups: groups(65),
		};
		expect(keptOf("users", over)).toBeUndefined();
		expect(keptOf("users", { name: "Al", groups: ["ok", bytes(257)] })?.values).toEqual({
			name: "Al",
		});
		const odd = {
			email: 1,
			name: "",
			picture: "\ud800",
			groups: ["staff", 2],
			role: "admin",
			email_verified: "true",
			emailVerified: true,
		};
		expect(keptOf("users", odd)).toBeUndefined();
		expect(keptOf("users", { [userAttribute.emailVerified]: true })).toBeUndefined();
		const unverified = { email: "a@b.example", [userAttribute.emailVerified]: false };
		expect(keptOf("users", unverified)?.values).toEqual(unverified);
		// Only users' names count: another spelling of a name is outside the set.
		const spelled = { email: "a@b.example", emailVerified: true };
		expect(keptOf("users", spelled)?.values).toEqual({ email: "a@b.example" });
		const lone = { name: "Al\ud800", groups: ["ok"] };
		expect(keptOf("users", lone)?.values).toEqual({ groups: ["ok"] });
		expect(keptOf("users", null)).toBeUndefined();
	});

	it("drops alone a value users does not take, and a verification beside an email it does not take", () => {
		const good = { email: "a@b.example", name: "Al" };
		expect(keptOf("users", { ...good, name: "Al\u0000" })?.values).toEqual({ email: good.email });
		expect(keptOf("users", { ...good, picture: "http://p.example/a" })?.values).toEqual(good);
		const given = { email: "a@", [userAttribute.emailVerified]: true, name: "Al" };
		expect(keptOf("users", given)?.values).toEqual({ name: "Al" });
	});

	it("drops them all for a source empty, ill-formed, over 128 bytes or holding a control character", () => {
		expect(keptOf("", { name: "Al" })).toBeUndefined();
		expect(keptOf("s".repeat(128), { name: "Al" })?.source).toBe("s".repeat(128));
		expect(keptOf("s".repeat(129), { name: "Al" })).toBeUndefined();
		expect(keptOf("us\u0007ers", { name: "Al" })).toBeUndefined();
		expect(keptOf("us\ud800", { name: "Al" })).toBeUndefined();
	});

	it("tells the names it dropped and how many others were given, never a value", () => {
		expect(keptAttributes(undefined)).toEqual({ kept: undefined, dropped: [], others: 0 });
		const whole = keptAttributes({ source: "users", values: { email: "a@b.example" } });
		expect([whole.dropped, whole.others]).toEqual([[], 0]);
		const values = {
			email: "a@b.example",
			email_verified: "secret-flag",
			emailVerified: true,
			name: "n".repeat(513),
			role: "secret-role",
			"secret-key": 1,
			toString: "secret-text",
		};
		const told = (given: unknown) => {
			const { dropped, others } = keptAttributes(given);
			return { dropped, others };
		};
		expect(told({ source: "users", values })).toEqual({
			dropped: ["email_verified", "name"],
			others: 4,
		});
		expect(told({ source: "", values: { name: "secret-name" } })).toEqual({
			dropped: ["source", "name"],
			others: 0,
		});
		expect(told({ source: "users", values: { email: "a@b.example", "secret-only": 1 } })).toEqual({
			dropped: [],
			others: 1,
		});
		expect(told(null)).toEqual({ dropped: ["source"], others: 0 });
		// Only a plain object carries attributes: a function with the same properties keeps nothing.
		const callable = Object.assign(() => {}, { source: "users", values: { name: "Al" } });
		expect(keptAttributes(callable)).toEqual({ kept: undefined, dropped: ["source"], others: 0 });
		expect(Object.isFrozen(keptAttributes(null).dropped)).toBe(true);
	});
});

describe("the form a kept copy is read back in", () => {
	it("takes the named set by type only, and refuses another name or type", () => {
		const read = (value: unknown) => sourcedAttributesShape.safeParse(value).success;
		expect(
			read({ source: "users", values: { email: "x", name: "n".repeat(600), groups: [] } }),
		).toBe(true);
		expect(read({ source: "users", values: { role: "admin" } })).toBe(false);
		expect(read({ source: "users", values: { email_verified: "true" } })).toBe(false);
		expect(read({ source: "users", values: { groups: "staff" } })).toBe(false);
		expect(read({ source: "users", values: { groups: ["staff", 1] } })).toBe(false);
		expect(read({ source: 1, values: {} })).toBe(false);
		expect(read({ source: "users", values: {}, extra: true })).toBe(false);
	});
});
