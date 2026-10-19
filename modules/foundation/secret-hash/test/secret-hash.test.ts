import { randomBytes, scryptSync } from "node:crypto";
import { assemble, BootRefused, isUnavailable, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import bcrypt from "bcryptjs";
import { describe, expect, it } from "vitest";
import { checkerWith, type Places, placesOf } from "../src/checker.ts";
import * as offered from "../src/contract.ts";
import { readSecretHash, type SecretHash, secretCheckers } from "../src/contract.ts";
import { decoyOf, type Hash, matches, readHash } from "../src/hashes.ts";
import secretHash from "../src/module.ts";
import {
	recordingChecker,
	seventyTwoBytes,
	testBcryptHash,
	testScryptHash,
} from "../src/testing.ts";

const unpadded = (bytes: Buffer) => bytes.toString("base64").replace(/=+$/, "");
const zeros = (n: number) => unpadded(Buffer.alloc(n));
const scryptText = (ln: number, r: number, p: number, salt = 16, key = 32) =>
	`$scrypt$ln=${ln},r=${r},p=${p}$${zeros(salt)}$${zeros(key)}`;
const read = (text: string) => readSecretHash(text) as SecretHash;
/** A checker for the hashes in use, with its own limit, as an assembly's checkers have. */
const checkerFor = (inUse: Iterable<SecretHash>) => recordingChecker(inUse, randomBytes).checker;
/** bcrypt's 53 characters with no loose final bits: the salt's last of 22 and the hash's last of 31. */
const bcryptTail = (c: string) => `${c.repeat(21)}e${c.repeat(30)}e`;

describe("reading", () => {
	it("reads bcrypt from cost 4 to 14 and scrypt within 128 MiB, p up to 2, in exact unpadded base64", () => {
		const b = (prefix: string, cost: string) => `${prefix}${cost}$${bcryptTail("a")}`;
		const cases: Record<string, [text: string, read: boolean]> = {
			"bcrypt $2y$ at cost 4": [b("$2y$", "04"), true],
			"bcrypt $2a$ at cost 14": [b("$2a$", "14"), true],
			"bcrypt at cost 15": [b("$2b$", "15"), false],
			"bcrypt at cost 3": [b("$2b$", "03"), false],
			"bcrypt $2x$": [b("$2x$", "10"), false],
			"bcrypt one character too long": [`${b("$2b$", "10")}a`, false],
			// The salt's 22nd character carries 4 unused bits, the hash's 31st 2; both must be zero.
			"bcrypt with loose salt bits": [`$2b$10$${"a".repeat(21)}/${"a".repeat(30)}e`, false],
			"bcrypt with loose hash bits": [`$2b$10$${"a".repeat(21)}e${"a".repeat(30)}f`, false],
			"scrypt at ln 10": [scryptText(10, 8, 1), true],
			"scrypt at 128 MiB with p 2": [scryptText(17, 8, 2), true],
			"scrypt at ln 9": [scryptText(9, 8, 1), false],
			"scrypt over 128 MiB": [scryptText(18, 8, 1), false],
			"scrypt with p 3": [scryptText(10, 8, 3), false],
			"scrypt with r 0": [scryptText(10, 0, 1), false],
			"scrypt with p 0": [scryptText(10, 8, 0), false],
			"scrypt salt of 15 bytes": [scryptText(10, 8, 1, 15), false],
			"scrypt key of 31 bytes": [scryptText(10, 8, 1, 16, 31), false],
			"scrypt key with padding": [`${scryptText(10, 8, 1)}=`, false],
			// The key's last character carries 2 unused bits; B sets one of them.
			"scrypt key with loose final bits": [scryptText(10, 8, 1).replace(/A$/, "B"), false],
			"plain text": ["plain", false],
		};
		for (const [name, [text, read]] of Object.entries(cases)) {
			expect(readSecretHash(text) !== undefined, name).toBe(read);
		}
	});

	it("refuses scrypt whose N is not below 2^(16·r), which every computation would reject", async () => {
		expect(readSecretHash(scryptText(15, 1, 1))).toBeDefined();
		expect(readSecretHash(scryptText(16, 1, 1))).toBeUndefined();
		expect(readSecretHash(scryptText(20, 1, 1))).toBeUndefined();
		expect(readSecretHash(scryptText(16, 2, 1))).toBeDefined();
		expect(await matches(readHash(scryptText(15, 1, 1)) as Hash, "x")).toBe(false);
		expect(await matches(readHash(scryptText(16, 2, 1)) as Hash, "x")).toBe(false);
	});

	it("reads a scrypt salt of 16 to 64 bytes and a key of 32 to 64, since their length slows every check", () => {
		expect(readSecretHash(scryptText(10, 8, 1, 64, 64))).toBeDefined();
		expect(readSecretHash(scryptText(10, 8, 1, 65))).toBeUndefined();
		expect(readSecretHash(scryptText(10, 8, 1, 16, 65))).toBeUndefined();
	});

	it("takes as a hash only what readSecretHash made", () => {
		// @ts-expect-error A hand-built value lacks the mark readSecretHash gives.
		const handBuilt: SecretHash = { work: "bcrypt:4" };
		expect(handBuilt.work).toBe(read(`$2b$04$${bcryptTail("a")}`).work);
	});

	it("names bcrypt by cost alone, and scrypt by ln, r, p and key length but not salt length", () => {
		const work = (text: string) => read(text).work;
		expect(work(`$2b$04$${bcryptTail("a")}`), "bcrypt prefix").toBe(
			work(`$2y$04$${bcryptTail("b")}`),
		);
		expect(work(scryptText(10, 8, 1)), "scrypt salt length").toBe(work(scryptText(10, 8, 1, 24)));
		const distinct = [
			`$2b$04$${bcryptTail("a")}`,
			`$2b$05$${bcryptTail("a")}`,
			scryptText(10, 8, 1),
			scryptText(10, 8, 1, 16, 64),
			scryptText(10, 8, 2),
			scryptText(10, 4, 1),
			scryptText(11, 8, 1),
		].map(work);
		expect(new Set(distinct).size).toBe(distinct.length);
	});
});

describe("matching", () => {
	it("matches a bcrypt and a scrypt hash of the secret, and nothing else", async () => {
		for (const text of [testBcryptHash("s3cret"), testScryptHash("s3cret")]) {
			const checker = checkerFor([read(text)]);
			expect(await checker.check(read(text), "s3cret")).toBe(true);
			expect(await checker.check(read(text), "s3cret ")).toBe(false);
			expect(await checker.check(read(text), "")).toBe(false);
		}
	});

	it("matches bcrypt under $2a$ and $2y$ as under $2b$", async () => {
		const text = testBcryptHash("s3cret");
		for (const prefix of ["$2a$", "$2y$"]) {
			const other = read(text.replace("$2b$", prefix));
			expect(await checkerFor([other]).check(other, "s3cret"), prefix).toBe(true);
		}
	});

	it("compares a secret's bytes as sent, with no Unicode normalization", async () => {
		const composed = "caf\u00e9";
		const text = testScryptHash(composed);
		const checker = checkerFor([read(text)]);
		expect(await checker.check(read(text), composed)).toBe(true);
		expect(await checker.check(read(text), composed.normalize("NFD"))).toBe(false);
	});

	it("matches a scrypt key of any length the hash holds, not 32 bytes alone", async () => {
		for (const length of [32, 48, 64]) {
			const salt = randomBytes(16);
			const key = scryptSync("pw", salt, length, { N: 1024, r: 8, p: 1 });
			const hash = readHash(`$scrypt$ln=10,r=8,p=1$${unpadded(salt)}$${unpadded(key)}`) as Hash;
			expect(await matches(hash, "pw"), String(length)).toBe(true);
			expect(await matches(hash, "other"), String(length)).toBe(false);
		}
	});

	it("matches a bcrypt hash up to 72 bytes and never past them", async () => {
		const hash = read(testBcryptHash(seventyTwoBytes));
		const checker = checkerFor([hash]);
		expect(await checker.check(hash, seventyTwoBytes)).toBe(true);
		expect(await checker.check(hash, `${seventyTwoBytes}a`)).toBe(false);
	});

	it("matches a secret of exactly 1024 bytes, and refuses a longer one before any computation", async () => {
		const exact = read(testScryptHash("x".repeat(1024)));
		// 342 characters, but 1026 bytes.
		const long = "あ".repeat(342);
		const over = read(testScryptHash(long));
		expect(await checkerFor([exact]).check(exact, "x".repeat(1024))).toBe(true);
		const { checker, works } = recordingChecker([exact, over], randomBytes);
		expect(await checker.check(over, long)).toBe(false);
		expect(await checker.check(undefined, long)).toBe(false);
		expect(works).toEqual([]);
	});
});

describe("the same work for any call", () => {
	const inUse = [
		read(testBcryptHash("b", 4)),
		read(testScryptHash("s10", 10)),
		read(testScryptHash("s11", 11)),
	];

	it("computes once per kind of work in use, with a hash, without one, or with one not in use", async () => {
		const foreign = read(testBcryptHash("f", 5));
		for (const hash of [...inUse, undefined, foreign]) {
			const { checker, works } = recordingChecker(inUse, randomBytes);
			await checker.check(hash, "p");
			const expected = [...new Set(inUse.map((h) => h.work))];
			const extra = hash === foreign ? [foreign.work] : [];
			expect(works.toSorted()).toEqual([...expected, ...extra].toSorted());
		}
	});

	it("answers a decoy's match as no match, and the hash's own match as one", async () => {
		const alwaysMatches = checkerWith(inUse, randomBytes, async () => true, placesOf(8));
		expect(await alwaysMatches.check(undefined, "x")).toBe(false);
		expect(await alwaysMatches.check(inUse[0], "x")).toBe(true);
	});

	it("computes nothing without a hash when no hash is in use", async () => {
		const { checker, works } = recordingChecker([], randomBytes);
		expect(await checker.check(undefined, "p")).toBe(false);
		expect(works).toEqual([]);
	});

	it("makes decoys with exactly the work of the hash they stand for, drawn only from the given bytes", () => {
		const filled = (value: number) => (n: number) => new Uint8Array(n).fill(value);
		for (const like of [
			readHash(bcrypt.hashSync("x", 5)) as Hash,
			readHash(scryptText(11, 4, 2, 24, 48)) as Hash,
		]) {
			const decoy = decoyOf(like, filled(1));
			expect(decoy.work).toBe(like.work);
			if (decoy.format === "bcrypt") expect(readHash(decoy.text)?.work).toBe(like.work);
			expect(decoyOf(like, filled(1))).toEqual(decoy);
			expect(decoyOf(like, filled(2))).not.toEqual(decoy);
			expect(decoyOf(like, randomBytes)).not.toEqual(like);
		}
	});
});

describe("the checks under way at once", () => {
	const hash = read(testBcryptHash("right"));
	/** A checker sharing `places`, with the work of every computation recorded in order. */
	const recordingIn = (places: Places, inUse: SecretHash[]) => {
		const works: string[] = [];
		const record = (h: Hash, secret: string) => {
			works.push(h.work);
			return matches(h, secret);
		};
		return { checker: checkerWith(inUse, randomBytes, record, places), works };
	};

	it("refuses a check past `max-concurrent` as unavailable before any computation, in any checker", async () => {
		const places = placesOf(1);
		const { checker, works } = recordingIn(places, [hash]);
		const other = recordingIn(places, [hash]);
		const first = checker.check(hash, "right");
		await expect(checker.check(hash, "right")).rejects.toSatisfy(isUnavailable);
		await expect(other.checker.check(undefined, "right")).rejects.toSatisfy(isUnavailable);
		expect(await first).toBe(true);
		expect([works, other.works]).toEqual([[hash.work], []]);
	});

	it("gives a place back once its check ends, matched, unmatched or failed", async () => {
		const places = placesOf(1);
		const fails = async () => {
			throw new Error("computation failed");
		};
		const failing = checkerWith([hash], randomBytes, fails, places);
		await expect(failing.check(hash, "right")).rejects.toThrow("computation failed");
		const { checker } = recordingIn(places, [hash]);
		expect(await checker.check(hash, "wrong")).toBe(false);
		expect(await checker.check(hash, "right")).toBe(true);
	});

	it("keeps the place while any computation runs, even after another throws before it gives a promise", async () => {
		const places = placesOf(1);
		const pending = Promise.withResolvers<boolean>();
		const two = [hash, read(scryptText(10, 8, 1))];
		let calls = 0;
		const firstWaitsThenThrows = () => {
			calls++;
			if (calls === 1) return pending.promise;
			throw new Error("thrown at once");
		};
		const throwing = checkerWith(two, randomBytes, firstWaitsThenThrows, places);
		const failed = throwing.check(hash, "right").catch((error: unknown) => error);
		// Let everything the throw set off run, so a place given back early would be free by now.
		await new Promise((resolve) => setTimeout(resolve, 0));
		const { checker } = recordingIn(places, [hash]);
		await expect(checker.check(hash, "right")).rejects.toSatisfy(isUnavailable);
		pending.resolve(false);
		expect(await failed).toMatchObject({ message: "thrown at once" });
		expect(await checker.check(hash, "right")).toBe(true);
	});

	it("answers a secret over 1024 bytes as no match without a place", async () => {
		const places = placesOf(1);
		const { checker } = recordingIn(places, [hash]);
		const first = checker.check(hash, "right");
		expect(await checker.check(hash, "x".repeat(1025))).toBe(false);
		await first;
	});

	it("runs 8 checks at once by default, and refuses a limit outside 1 to 1024 at boot", async () => {
		const assembled = (section?: Record<string, unknown>) =>
			assemble({
				modules: [secretHash],
				config: { ...kernelConfig(), ...(section ? { "secret-hash": section } : {}) },
				runtime: quietRuntime(),
			});
		const checker = (await assembled()).get(secretCheckers).checkerOf([hash]);
		const eight = Array.from({ length: 8 }, () => checker.check(hash, "right"));
		await expect(checker.check(hash, "right")).rejects.toSatisfy(isUnavailable);
		expect(await Promise.all(eight)).toEqual(Array(8).fill(true));
		for (const max of [0, 1025]) {
			await expect(assembled({ "max-concurrent": max })).rejects.toBeInstanceOf(BootRefused);
		}
	});
});

describe("the checkers an assembly makes", () => {
	const hash = read(testBcryptHash("right"));
	const assembled = (max: number) =>
		assemble({
			modules: [secretHash],
			config: { ...kernelConfig(), "secret-hash": { "max-concurrent": max } },
			runtime: quietRuntime(),
		});

	it("keeps each assembly's limit apart, and shares it among the checkers one assembly makes", async () => {
		const [one, two] = [await assembled(1), await assembled(1)];
		const own = one.get(secretCheckers).checkerOf([hash]);
		const sibling = one.get(secretCheckers).checkerOf([hash]);
		const apart = two.get(secretCheckers).checkerOf([hash]);
		const first = own.check(hash, "right");
		await expect(sibling.check(hash, "right")).rejects.toSatisfy(isUnavailable);
		expect(await apart.check(hash, "right")).toBe(true);
		expect(await first).toBe(true);
	});

	it("makes checkers only through the assembly's contract, never apart from one", () => {
		expect(Object.keys(offered)).not.toContain("secretChecker");
	});

	it("checks the hash's own match, and a decoy's never", async () => {
		const checker = (await assembled(8)).get(secretCheckers).checkerOf([hash]);
		expect(await checker.check(hash, "right")).toBe(true);
		expect(await checker.check(hash, "wrong")).toBe(false);
		expect(await checker.check(undefined, "right")).toBe(false);
	});
});
