import { describe, expect, it } from "vitest";
import { legacyDir, legacyVersion } from "../src/dir.ts";

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
