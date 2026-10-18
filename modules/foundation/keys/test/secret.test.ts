import { randomBytes } from "node:crypto";
import { expect, it } from "vitest";
import { bearerToken, secretBytes } from "../src/contract.ts";

const issues = (
	schema: { safeParse: ReturnType<typeof secretBytes>["safeParse"] },
	value: unknown,
) => {
	const read = schema.safeParse(value);
	return read.success ? [] : read.error.issues.map((i) => i.message);
};

it("takes base64 of enough random-looking bytes, as many as asked or at least as many", () => {
	const random = randomBytes(32).toString("base64");
	expect(issues(secretBytes({ exactly: 32 }), random)).toEqual([]);
	expect(issues(secretBytes({ atLeast: 32 }), randomBytes(48).toString("base64"))).toEqual([]);
	expect(issues(secretBytes({ exactly: 32 }), randomBytes(48).toString("base64"))).not.toEqual([]);
	expect(issues(secretBytes({ atLeast: 32 }), randomBytes(16).toString("base64"))).not.toEqual([]);
});

it("refuses a sample, loose base64, and a weak key, never naming the value", () => {
	const schema = secretBytes({ atLeast: 32 });
	const refused = [
		"REPLACE-32-RANDOM-BYTES-BASE64-ENCODED-PLEASE",
		"A".repeat(44),
		Buffer.alloc(32).toString("base64"),
		"correct horse battery staple and a few more words",
		`${randomBytes(32).toString("base64")}!`,
	];
	for (const value of refused) {
		const said = issues(schema, value);
		expect(said, value).not.toEqual([]);
		expect(said.join(" "), value).not.toContain(value);
	}
	expect(issues(schema, "REPLACE-ME")).toEqual([
		"a sample left in place: REPLACE- is never a secret",
	]);
});

it("takes hex where asked, by the same rules", () => {
	const hex = randomBytes(32).toString("hex");
	expect(issues(secretBytes({ atLeast: 32 }, { hex: true }), hex)).toEqual([]);
	expect(issues(secretBytes({ atLeast: 32 }, { hex: true }), hex.toUpperCase())).toEqual([]);
	expect(
		issues(secretBytes({ atLeast: 32 }, { hex: true }), randomBytes(32).toString("base64")),
	).toEqual([]);
	for (const weak of [
		"00".repeat(32),
		"ab".repeat(32),
		randomBytes(31).toString("hex"),
		`${hex}0`,
	]) {
		expect(issues(secretBytes({ atLeast: 32 }, { hex: true }), weak), weak).not.toEqual([]);
	}
});

it("takes a bearer token whose fewest bytes of key material, as written, hex or base64, are enough", () => {
	const schema = bearerToken({ atLeast: 32 });
	const taken = [
		randomBytes(32).toString("hex"),
		randomBytes(32).toString("base64"),
		randomBytes(32).toString("base64url"),
		`tok.${randomBytes(24).toString("base64url")}~`,
	];
	for (const token of taken) expect(issues(schema, token), token).toEqual([]);
});

it("refuses a bearer token that is no b64token, too short read any way, or a sample, never naming it", () => {
	const schema = bearerToken({ atLeast: 32 });
	const token = randomBytes(32).toString("hex");
	const refused = [
		"",
		`has ${token} space`,
		`Bearer ${token}`,
		`${token}\n`,
		`${token}é`,
		`${token}@`,
		"ab".repeat(31),
		"Z".repeat(42),
		"Zz0".repeat(11).slice(0, 32),
		`REPLACE-${token}`,
	];
	for (const value of refused) {
		const said = issues(schema, value);
		expect(said, value).not.toEqual([]);
		if (value) expect(said.join(" "), value).not.toContain(value);
	}
	expect(issues(schema, `${token} x`)).toEqual(["not an RFC 6750 b64token"]);
	expect(issues(schema, "ab".repeat(31))).toEqual(["at least 32 bytes of key material"]);
	expect(issues(schema, `REPLACE-${token}`)).toEqual([
		"a sample left in place: REPLACE- is never a secret",
	]);
});
