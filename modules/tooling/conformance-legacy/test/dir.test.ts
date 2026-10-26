import { describe, expect, it } from "vitest";
import { legacyCommit, legacyCommitOf, legacyDir, legacyVersion } from "../src/dir.ts";

const home = "/home/u";
const kept = `auth-provider/legacy-${legacyVersion}`;

describe("legacyDir", () => {
	it("takes LEGACY_DIR when it is set", () => {
		expect(legacyDir({ LEGACY_DIR: "/w/legacy", XDG_CACHE_HOME: "/c" }, home)).toBe("/w/legacy");
	});

	it("keeps the build in the user's cache by default, never the OS temp dir", () => {
		expect(legacyDir({ XDG_CACHE_HOME: "/c" }, home)).toBe(`/c/${kept}`);
		expect(legacyDir({}, home)).toBe(`/home/u/.cache/${kept}`);
	});

	it("passes over an empty LEGACY_DIR and an XDG_CACHE_HOME that is empty or relative", () => {
		expect(legacyDir({ LEGACY_DIR: "", XDG_CACHE_HOME: "" }, home)).toBe(`/home/u/.cache/${kept}`);
		expect(legacyDir({ XDG_CACHE_HOME: "cache" }, home)).toBe(`/home/u/.cache/${kept}`);
	});
});

describe("legacyCommitOf", () => {
	it("builds the commit this tree names unless LEGACY_COMMIT names another", () => {
		expect(legacyCommitOf({})).toBe(legacyCommit);
		expect(legacyCommitOf({ LEGACY_COMMIT: "" })).toBe(legacyCommit);
		expect(legacyCommitOf({ LEGACY_COMMIT: "a".repeat(40) })).toBe("a".repeat(40));
	});

	it("refuses a ref that could be moved, or a short sha", () => {
		expect(() => legacyCommitOf({ LEGACY_COMMIT: "v0.17.0" })).toThrow("full commit sha");
		expect(() => legacyCommitOf({ LEGACY_COMMIT: "5708b53e" })).toThrow("full commit sha");
		expect(() => legacyCommitOf({ LEGACY_COMMIT: "A".repeat(40) })).toThrow("full commit sha");
	});
});
