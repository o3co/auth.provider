import { describe, expect, it } from "vitest";
import { listedProblems } from "../problems.ts";

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
