import { describe, expect, it } from "vitest";
import { listedProblems, orderProblems } from "../problems.ts";

describe("the tarballs publish takes, against those the lists were made of", () => {
	const a = {
		name: "@o3co/auth-provider-oauth",
		version: "1.0.0",
		integrity: "sha512-A",
		file: "o3co-auth-provider-oauth-1.0.0.tgz",
	};
	const b = {
		name: "@o3co/create-auth-provider",
		version: "1.0.0",
		integrity: "sha512-B",
		file: "o3co-create-auth-provider-1.0.0.tgz",
	};

	it("are the same tarballs, by name, version, integrity and file", () => {
		expect(listedProblems([a, b], [b, a])).toEqual([]);
	});

	it("names one of other bytes, one the lists never held, and one they held that is not there", () => {
		expect(listedProblems([{ ...a, integrity: "sha512-X" }, b], [a, b])).toEqual([
			"@o3co/auth-provider-oauth@1.0.0: another tarball than the lists were made of",
		]);
		expect(listedProblems([a, b], [a])).toEqual(["@o3co/create-auth-provider@1.0.0: in no list"]);
		expect(listedProblems([a], [a, b])).toEqual([
			"@o3co/create-auth-provider@1.0.0: listed, and not among the tarballs to publish",
		]);
	});

	it("names a tarball twice over, one not in the file npm packs it as, and one in another file than listed", () => {
		expect(listedProblems([a, a, b], [a, b])).toEqual([
			"@o3co/auth-provider-oauth@1.0.0: 2 tarballs",
		]);
		const renamed = { ...b, file: "entrance.tgz" };
		expect(listedProblems([a, renamed], [a, renamed])).toEqual([
			"@o3co/create-auth-provider@1.0.0: in entrance.tgz, not o3co-create-auth-provider-1.0.0.tgz as npm packs it",
		]);
		expect(listedProblems([a, b], [a, { ...b, file: "other.tgz" }])).toEqual([
			"@o3co/create-auth-provider@1.0.0: in o3co-create-auth-provider-1.0.0.tgz, listed in other.tgz",
		]);
	});
});

describe("the order the release publishes in, against the tarballs it publishes", () => {
	const files = ["a-1.0.0.tgz", "s-1.0.0.tgz", "e-1.0.0.tgz"];

	it("names each tarball once, and nothing else", () => {
		expect(orderProblems(["a-1.0.0.tgz", "s-1.0.0.tgz", "e-1.0.0.tgz"], files)).toEqual([]);
	});

	it("names a tarball it leaves out, one it names twice, and one that is not there", () => {
		expect(orderProblems(["a-1.0.0.tgz", "s-1.0.0.tgz"], files)).toEqual([
			"e-1.0.0.tgz: not in the order the release publishes in",
		]);
		expect(orderProblems([...files, "a-1.0.0.tgz"], files)).toEqual([
			"a-1.0.0.tgz: named twice in the order",
		]);
		expect(orderProblems([...files, "x-1.0.0.tgz"], files)).toEqual([
			"x-1.0.0.tgz: in the order, and not among the tarballs",
		]);
	});
});
