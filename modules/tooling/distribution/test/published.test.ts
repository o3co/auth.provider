import { describe, expect, it } from "vitest";
import { type Lookup, lookupOf, publishedProblems } from "../src/published.ts";
import type { Packed } from "../src/seal.ts";

const packed: Packed[] = [
	{ name: "@o3co/auth-provider-foundation", version: "0.19.0", integrity: "sha512-F" },
	{ name: "@o3co/auth-provider-oauth", version: "0.19.0", integrity: "sha512-O" },
	{ name: "@o3co/auth-provider-scaffold", version: "0.19.0", integrity: "sha512-S2" },
	{ name: "@o3co/create-auth-provider", version: "0.19.0", integrity: "sha512-E" },
];
const lookups = (by: Record<string, Lookup>) =>
	new Map(packed.map((p) => [p.name, by[p.name] ?? ({ kind: "absent" } as Lookup)]));

describe("what is published already, before this run publishes", () => {
	it("lets a first publish through: nothing is there", () => {
		expect(publishedProblems(packed, lookups({}))).toEqual([]);
	});

	it("lets a resumed publish through where what is there is this run's, the entrance alone missing", () => {
		const there = { kind: "present" } as const;
		const found = lookups({
			"@o3co/auth-provider-foundation": { ...there, integrity: "sha512-F" },
			"@o3co/auth-provider-oauth": { ...there, integrity: "sha512-O" },
			"@o3co/auth-provider-scaffold": { ...there, integrity: "sha512-S2" },
		});
		expect(publishedProblems(packed, found)).toEqual([]);
	});

	it("stops where the scaffold went out before a failure and a bundle packed again since seals another index", () => {
		// The first run published foundation and the scaffold, whose index held oauth's first integrity;
		// oauth, packed again, differs, so this run's sealed scaffold differs from the one published.
		const found = lookups({
			"@o3co/auth-provider-foundation": { kind: "present", integrity: "sha512-F" },
			"@o3co/auth-provider-scaffold": { kind: "present", integrity: "sha512-S1" },
		});
		expect(publishedProblems(packed, found)).toEqual([
			"@o3co/auth-provider-scaffold@0.19.0: published with another integrity than this run's tarball",
		]);
	});

	it("stops on a lookup it cannot read, never taking it as absent", () => {
		const found = lookups({
			"@o3co/auth-provider-oauth": { kind: "failed", why: "npm view exited 1" },
		});
		expect(publishedProblems(packed, found)).toEqual([
			"@o3co/auth-provider-oauth@0.19.0: the registry's answer is unread (npm view exited 1)",
		]);
		expect(publishedProblems(packed, new Map())).toHaveLength(packed.length);
	});
});

describe("reading npm view's answer", () => {
	it("takes E404 alone as absent, and a sha512 string as present", () => {
		const e404 = JSON.stringify({ error: { code: "E404", summary: "No match found" } });
		expect(lookupOf({ status: 1, stdout: e404, stderr: "npm error code E404" })).toEqual({
			kind: "absent",
		});
		expect(lookupOf({ status: 0, stdout: '"sha512-AbC+/="\n', stderr: "" })).toEqual({
			kind: "present",
			integrity: "sha512-AbC+/=",
		});
	});

	it("takes any other failure, an answer that is no JSON, and one without a sha512 integrity as unread", () => {
		const other = JSON.stringify({ error: { code: "ETIMEDOUT" } });
		for (const answer of [
			{ status: 1, stdout: other, stderr: "" },
			{ status: 1, stdout: "", stderr: "network down" },
			{ status: 0, stdout: "not json", stderr: "" },
			{ status: 0, stdout: "", stderr: "" },
			{ status: 0, stdout: '"sha1-abc"', stderr: "" },
			{ status: 0, stdout: "null", stderr: "" },
		]) {
			expect(lookupOf(answer).kind, JSON.stringify(answer)).toBe("failed");
		}
	});
});
