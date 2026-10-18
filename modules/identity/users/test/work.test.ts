import { randomBytes } from "node:crypto";
import { readSecretHash } from "@mod/secret-hash";
import { recordingChecker, testBcryptHash } from "@mod/secret-hash/testing";
import { expect, it } from "vitest";
import { registeredUsers } from "../src/registered.ts";
import { testPasswordHash } from "../src/testing.ts";

it("computes once for each kind of work in use, whoever is asked for", async () => {
	const entries = [
		{ identifier: "b", hash: testBcryptHash("p") },
		{ identifier: "s10", hash: testPasswordHash("p", 10) },
		{ identifier: "s11", hash: testPasswordHash("p", 11) },
	].map(({ identifier, hash }) => ({
		identifier,
		"password-hash": hash,
		attributes: {},
		upstream: [],
	}));
	const kinds = new Set(entries.map((entry) => readSecretHash(entry["password-hash"])?.work));
	let works: readonly string[] = [];
	const u = registeredUsers(entries, (inUse) => {
		const recording = recordingChecker(inUse, randomBytes);
		works = recording.works;
		return recording.checker;
	});
	for (const id of ["b", "s10", "s11", "nobody", ""]) {
		const before = works.length;
		await u.verify(id, "p");
		expect(new Set(works.slice(before)), id).toEqual(kinds);
		expect(works.length - before, id).toBe(kinds.size);
	}
});
