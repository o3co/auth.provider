import { describe, expect, it } from "vitest";
import {
	acceptedAttributes,
	isAttributeValue,
	isWellFormedSubject,
	type UserAttributes,
	userAttribute,
} from "../src/contract.ts";

describe("user attributes", () => {
	it("names them with the OIDC claim names, fixed", () => {
		expect(userAttribute).toEqual({
			email: "email",
			emailVerified: "email_verified",
			name: "name",
			picture: "picture",
			groups: "groups",
		});
		expect(Object.isFrozen(userAttribute)).toBe(true);
	});

	it("types each named attribute, and leaves other names open", () => {
		const full = {
			email: "alice@example.com",
			email_verified: true,
			name: "Alice",
			picture: "https://example.com/a.png",
			groups: ["admins"],
		} satisfies UserAttributes;
		const attributes: Readonly<Record<string, unknown>> = full;
		expect(attributes[userAttribute.emailVerified]).toBe(true);
		// @ts-expect-error email_verified holds a boolean.
		const wrong: UserAttributes = { email_verified: "true" };
		// @ts-expect-error groups holds a list of strings.
		const loose: UserAttributes = { groups: "admins" };
		expect([wrong, loose]).toHaveLength(2);
	});
});

describe("attribute values", () => {
	const judged = (name: string, values: readonly unknown[], expected: boolean) => {
		for (const value of values) {
			expect(isAttributeValue(name, value), `${name} ${JSON.stringify(value)}`).toBe(expected);
		}
	};
	const unreadable = ["a\u202Eb", "a\u200Bb", "a\u0000b", "a\nb", "a\tb", "a\u007Fb", "a\u0085b"];

	it("accepts an email that mail takes, and refuses any other", () => {
		judged("email", ["alice@example.com", "Alice@example.com", "josé@bücher.example"], true);
		judged(
			"email",
			[
				"a@victim.test/x",
				"a@victim.test?x",
				" a@example.com",
				"a@b@example.com",
				"",
				7,
				["a@example.com"],
			],
			false,
		);
		judged(
			"email",
			unreadable.map((text) => `${text}@example.com`),
			false,
		);
	});

	it("accepts a picture only as an https URL that reads back as given", () => {
		judged("picture", ["https://pic.example/a.png", "https://pic.example/a?b=c#d"], true);
		judged(
			"picture",
			[
				"javascript:alert(1)",
				"http://pic.example/a.png",
				"data:image/png;base64,AAAA",
				"//pic.example/a.png",
				"https://PIC.example/a.png",
				"https://pic.example",
				"https://pic.example/a b",
				" https://pic.example/a",
				"https://pic.example/a\n",
				"https://pic.example/\u202Ea",
				"https://pic.example/\u00ADa",
				"https:pic.example/a",
				"",
				7,
			],
			false,
		);
	});

	it("accepts email_verified only as a boolean", () => {
		judged("email_verified", [true, false], true);
		judged("email_verified", ["true", 1, null, [true]], false);
	});

	it("accepts a name and each group only as text with no control or format character", () => {
		judged("name", ["Alice", "", "Élodie O'Brien", "العربية"], true);
		judged("name", [...unreadable, 7, { first: "Alice" }, ["Alice"]], false);
		judged("groups", [[], ["admins", "staff"]], true);
		judged(
			"groups",
			[
				...unreadable.map((text) => ["admins", text]),
				"admins",
				["admins", 1],
				[null],
				{ admins: true },
			],
			false,
		);
	});

	it("accepts any value of another name, but a string only with no control or format character", () => {
		judged("hd", ["example.com", 7, { list: ["a\u202Eb"] }, null, true], true);
		judged("hd", unreadable, false);
		judged("__proto__", ["x", {}], true);
		judged("toString", ["x"], true);
	});
});

describe("subject shape", () => {
	it("accepts 1 to 255 ASCII characters", () => {
		for (const subject of ["a", "s-alice", "x".repeat(255), "a b\t~", "\x7f"]) {
			expect(isWellFormedSubject(subject), JSON.stringify(subject)).toBe(true);
		}
	});

	it("refuses an empty subject, one past 255, a character outside ASCII, or no string [oidc-core-2-c]", () => {
		for (const subject of ["", "x".repeat(256), "é", "s-\u{1F600}", "\x80", 7, null, undefined]) {
			expect(isWellFormedSubject(subject), JSON.stringify(subject)).toBe(false);
		}
	});
});

it("takes from values of any shape the attributes users names, each in a form it accepts, and nothing else", () => {
	expect(
		acceptedAttributes({
			email: "ann@example.invalid",
			email_verified: true,
			name: "Ann",
			picture: "https://pictures.example.invalid/ann.png",
			groups: ["staff"],
			other: "kept by nobody",
		}),
	).toEqual({
		email: "ann@example.invalid",
		email_verified: true,
		name: "Ann",
		picture: "https://pictures.example.invalid/ann.png",
		groups: ["staff"],
	});
	// A verification says something only of an email kept beside it.
	expect(
		acceptedAttributes({ email: "not an address", email_verified: true, name: "Ann" }),
	).toEqual({
		name: "Ann",
	});
	expect(
		acceptedAttributes({ email_verified: "yes", picture: "http://x.invalid/p", groups: [1] }),
	).toEqual({});
	for (const nothing of [undefined, null, "email", ["email"]])
		expect(acceptedAttributes(nothing)).toEqual({});
	const accepted = acceptedAttributes({ groups: ["a"] });
	expect(Object.isFrozen(accepted) && Object.isFrozen(accepted.groups)).toBe(true);
});

it("reads each value once, so what it checked is what it keeps", () => {
	let reads = 0;
	const shifting = {
		get email() {
			reads++;
			return reads === 1 ? "ann@example.invalid" : "not an address";
		},
		groups: new Proxy(["staff"], {
			get: (target, key, receiver) =>
				key === "0" && ++reads > 2 ? "\u0000" : Reflect.get(target, key, receiver),
		}),
	};
	const accepted = acceptedAttributes(shifting);
	expect(accepted.email).toBe("ann@example.invalid");
	expect(accepted.groups).toEqual(["staff"]);
});
