import {
	assemble,
	BootRefused,
	defineModule,
	isUnavailable,
	kernelConfig,
	Unavailable,
} from "@mod/kernel";
import { quietRuntime, type RecordingLog, recordingLog } from "@mod/kernel/testing";
import secretHashModule from "@mod/secret-hash/module";
import { describe, expect, it } from "vitest";
import { type Ledger, ledgers, type Users, users, type Verified } from "../src/contract.ts";
import usersModule from "../src/module.ts";
import { memoryUsersStores, testUser, usersContract } from "../src/testing.ts";

const alice = { subject: "s-alice", attributes: { name: "Alice", email: "Alice@example.com" } };
const none: Verified = { kind: "none" };

/** A ledger holding alice, recording each call. */
function fakeLedger(calls: string[] = []): Ledger {
	return {
		verify: async (identifier, password) => {
			calls.push("verify");
			return identifier === "alice" && password === "correct horse"
				? { kind: "user", user: alice }
				: none;
		},
		bySubject: async (subject) => {
			calls.push("bySubject");
			return subject === alice.subject ? { kind: "user", user: alice } : none;
		},
	};
}

const ledgerModule = (ledger: Ledger, name = "test-ledger") =>
	defineModule({ name, takes: [] }, (m) => [m.contribute(ledgers).by(() => ledger)]);

const boot = (
	modules: ReturnType<typeof ledgerModule>[],
	registered: unknown[] = [],
	recorded?: RecordingLog,
) =>
	assemble({
		modules: [usersModule, secretHashModule, memoryUsersStores().module, ...modules],
		config: { ...kernelConfig(), users: { registered } },
		...(recorded ? { runtime: quietRuntime({ log: recorded.log }) } : {}),
	});

const usersOf = async (ledger: Ledger, recorded?: RecordingLog) =>
	(await boot([ledgerModule(ledger)], [], recorded)).get(users);
/** A ledger that gives the same answer to every question. */
const answering = (answer: unknown): Ledger => ({
	verify: async () => answer as Verified,
	bySubject: async () => answer as Verified,
});

async function openWith(ledger: Ledger): Promise<Users> {
	const u = await usersOf(ledger);
	await u.link("s-alice", { idp: "example", subject: "u-alice" });
	return u;
}

usersContract("a contributed user ledger", {
	open: () => openWith(fakeLedger()),
	openCounting: async () => {
		const checks: string[] = [];
		return { users: await openWith(fakeLedger(checks)), checks };
	},
	writtenLinksOnly: true,
});

/** The same ledger, unable to look users up by subject. */
const verifyOnly = (calls?: string[]): Ledger => ({
	...fakeLedger(calls),
	bySubject: async () => ({ kind: "unanswerable" }),
});
usersContract("a contributed user ledger that cannot look users up by subject", {
	open: () => openWith(verifyOnly()),
	openCounting: async () => {
		const checks: string[] = [];
		return { users: await openWith(verifyOnly(checks)), checks };
	},
	writtenLinksOnly: true,
	unanswerableBySubject: true,
});

describe("users ledgers", () => {
	it("refuses to start with more than one ledger, or with one and users in the settings", async () => {
		const one = ledgerModule(fakeLedger());
		const two = ledgerModule(fakeLedger(), "other-ledger");
		await expect(boot([one, two])).rejects.toBeInstanceOf(BootRefused);
		await expect(boot([one], [testUser("bob", "p")])).rejects.toBeInstanceOf(BootRefused);
		await expect(boot([one])).resolves.toBeDefined();
	});

	it("answers from the ledger, not the settings, and finds the user of a written link there", async () => {
		const u = await openWith(fakeLedger());
		expect(await u.verify("alice", "correct horse")).toEqual({ kind: "user", user: alice });
		expect(await u.byUpstream("example", "u-alice")).toEqual({ kind: "user", user: alice });
	});

	it("answers none for an empty identifier, a password past 1024 bytes and an empty subject without asking", async () => {
		const calls: string[] = [];
		const u = await openWith(fakeLedger(calls));
		expect(await u.verify("", "correct horse")).toEqual(none);
		expect(await u.verify("alice", "x".repeat(1025))).toEqual(none);
		expect(await u.bySubject("")).toEqual(none);
		expect(await u.bySubject("s-é")).toEqual(none);
		expect(await u.bySubject("s".repeat(256))).toEqual(none);
		expect(await u.claimedContacts("")).toEqual([]);
		expect(calls).toEqual([]);
	});

	it("answers any failure of a ledger as unavailable, never as none or as it came", async () => {
		const failures: Record<string, () => Promise<Verified>> = {
			unavailable: () => Promise.reject(new Unavailable("ledger")),
			"another error": () => Promise.reject(new TypeError("ledger")),
			"a synchronous throw": () => {
				throw new Error("ledger");
			},
		};
		for (const [name, fail] of Object.entries(failures)) {
			const u = await usersOf({ verify: fail, bySubject: fail });
			await u.link("s-alice", { idp: "example", subject: "u-alice" });
			for (const call of [
				() => u.verify("alice", "correct horse"),
				() => u.bySubject("s-alice"),
				() => u.claimedContacts("s-alice"),
				() => u.byUpstream("example", "u-alice"),
			]) {
				await expect(call(), name).rejects.toSatisfy(isUnavailable);
			}
		}
	});

	it("takes a frozen copy of the declared fields, read once", async () => {
		const attributes: Record<string, unknown> = { name: "Alice", nested: { list: ["a"] } };
		const answer = { kind: "user", user: { subject: "s-alice", attributes, extra: 1 }, extra: 2 };
		const found = await (await usersOf(answering(answer))).verify("alice", "p");
		attributes.name = "Mallory";
		(attributes.nested as { list: string[] }).list.push("b");
		expect(found).toEqual({
			kind: "user",
			user: { subject: "s-alice", attributes: { name: "Alice", nested: { list: ["a"] } } },
		});
		expect(found.kind === "user" && Object.isFrozen(found.user.attributes.nested)).toBe(true);
	});

	it("reads each field of an answer once, getters included", async () => {
		const reads: string[] = [];
		const counted = (fields: Record<string, unknown>) =>
			Object.defineProperties(
				{},
				Object.fromEntries(
					Object.entries(fields).map(([key, value]) => [
						key,
						{
							enumerable: true,
							get: () => {
								reads.push(key);
								return value;
							},
						},
					]),
				),
			);
		const user = counted({ subject: "s-alice", attributes: counted({ name: "Alice" }) });
		const found = await (await usersOf(answering(counted({ kind: "user", user })))).verify(
			"a",
			"p",
		);
		expect(found).toEqual({
			kind: "user",
			user: { subject: "s-alice", attributes: { name: "Alice" } },
		});
		expect(reads.toSorted()).toEqual(["attributes", "kind", "name", "subject", "user"]);
	});

	it("refuses unanswerable as an answer to a verification", async () => {
		const u = await usersOf(answering({ kind: "unanswerable" }));
		await expect(u.verify("alice", "correct horse")).rejects.toSatisfy(isUnavailable);
	});

	it("refuses a malformed answer, or the user of another subject, as unavailable [oidc-core-2-c]", async () => {
		const user = (subject: unknown, attributes: unknown = {}) => ({
			kind: "user",
			user: { subject, attributes },
		});
		const malformed: Record<string, unknown> = {
			"empty subject": user(""),
			"subject outside ASCII": user("s-é"),
			"subject past 255": user("s".repeat(256)),
			"subject not a string": user(7),
			"attributes an array": user("s-alice", ["a"]),
			"attributes null": user("s-alice", null),
			"attributes not cloneable": user("s-alice", { f: () => 1 }),
			"user missing": { kind: "user" },
			"unknown kind": { kind: "maybe" },
			"unknown kind with a user": { kind: "maybe", user: { subject: "s-alice", attributes: {} } },
			"user an array": {
				kind: "user",
				user: Object.assign([], { subject: "s-alice", attributes: {} }),
			},
			"null answer": null,
		};
		for (const [name, answer] of Object.entries(malformed)) {
			const u = await usersOf(answering(answer));
			await expect(u.verify("a", "p"), name).rejects.toSatisfy(isUnavailable);
			await expect(u.bySubject("s-alice"), name).rejects.toSatisfy(isUnavailable);
		}
		const u = await usersOf({
			...fakeLedger(),
			bySubject: async () => ({ kind: "user", user: alice }),
		});
		await expect(u.bySubject("s-bob")).rejects.toSatisfy(isUnavailable);
	});

	it("answers unanswerable by subject when the ledger cannot look users up by subject", async () => {
		const u = await usersOf(verifyOnly());
		expect(await u.verify("alice", "correct horse")).toEqual({ kind: "user", user: alice });
		expect(await u.bySubject("s-alice")).toEqual({ kind: "unanswerable" });
		expect(await u.bySubject("")).toEqual(none);
		expect(await u.claimedContacts("s-alice")).toEqual({ kind: "unanswerable" });
		expect(await u.claimedContacts("")).toEqual([]);
		await u.link("s-alice", { idp: "example", subject: "u-alice" });
		// The link stands for no one the ledger can name: neither none nor a user.
		await expect(u.byUpstream("example", "u-alice")).rejects.toSatisfy(isUnavailable);
	});

	it("answers none for a written link to a subject the ledger answers none for: the ledger's none outweighs the link", async () => {
		const u = await usersOf({ ...fakeLedger(), bySubject: async () => none });
		expect(await u.link("s-gone", { idp: "example", subject: "u-gone" })).toBe("linked");
		expect(await u.byUpstream("example", "u-gone")).toEqual(none);
	});

	it("claims only a non-empty email attribute, exactly as given", async () => {
		const held = (attributes: Record<string, unknown>): Ledger => ({
			...fakeLedger(),
			bySubject: async (subject) => ({ kind: "user", user: { subject, attributes } }),
		});
		for (const email of [7, ["a@example.com"], "", { value: "a@example.com" }]) {
			const u = await usersOf(held({ email }));
			expect(await u.claimedContacts("s"), JSON.stringify(email)).toEqual([]);
		}
		const u = await usersOf(held({ email: "A@Example.com" }));
		expect(await u.claimedContacts("s")).toEqual([{ kind: "email", value: "A@Example.com" }]);
	});

	it("leaves out only an attribute whose value users does not accept, logging its name but never its value", async () => {
		const attributes = {
			name: "Alice",
			email: "a@victim.test/x",
			email_verified: "true",
			picture: "javascript:alert(1)",
			groups: ["admins"],
			hd: "example.com\u202E",
			level: 3,
		};
		const recorded = recordingLog();
		const u = await usersOf(
			answering({ kind: "user", user: { subject: "s-alice", attributes } }),
			recorded,
		);
		const kept = { name: "Alice", groups: ["admins"], level: 3 };
		expect(await u.verify("alice", "p")).toEqual({
			kind: "user",
			user: { subject: "s-alice", attributes: kept },
		});
		expect(await u.bySubject("s-alice")).toEqual({
			kind: "user",
			user: { subject: "s-alice", attributes: kept },
		});
		const dropped = ["email", "email_verified", "picture", "hd"].map((attribute) => ({
			level: "warn",
			event: "users.attribute_dropped",
			fields: { attribute },
		}));
		expect(recorded.lines()).toEqual([...dropped, ...dropped]);
		for (const value of ["victim", "javascript", "\u202E", "true"]) {
			expect(JSON.stringify(recorded.lines())).not.toContain(value);
		}
	});

	it("logs an attribute's name with no control or format character, and at most 200 characters", async () => {
		const attributes = { "h\u202Ed\u0000": "x\u0000", ["n".repeat(300)]: "x\u0000" };
		const recorded = recordingLog();
		const u = await usersOf(
			answering({ kind: "user", user: { subject: "s", attributes } }),
			recorded,
		);
		expect(await u.verify("a", "p")).toEqual({
			kind: "user",
			user: { subject: "s", attributes: {} },
		});
		expect(recorded.lines().map((line) => line.fields.attribute)).toEqual(["hd", "n".repeat(200)]);
	});
});
