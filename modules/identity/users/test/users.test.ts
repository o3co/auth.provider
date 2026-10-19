import { randomBytes } from "node:crypto";
import { assemble, BootRefused, defineModule, isUnavailable, kernelConfig } from "@mod/kernel";
import { switchedModule, unavailableSwitch } from "@mod/kernel/testing";
import secretHashModule from "@mod/secret-hash/module";
import { recordingChecker, testBcryptHash } from "@mod/secret-hash/testing";
import { describe, expect, it } from "vitest";
import {
	type Contact,
	type LinkStore,
	linkStore,
	type StoredContacts,
	upstreamNames,
	users,
} from "../src/contract.ts";
import { ledgerUsers } from "../src/ledger.ts";
import { keptLinks } from "../src/links/kept.ts";
import usersModule from "../src/module.ts";
import { record, registeredUsers } from "../src/registered.ts";
import {
	ledgerContract,
	memoryUsersStores,
	seventyTwoBytes,
	testPasswordHash,
	testUser,
	usersContract,
} from "../src/testing.ts";

/** The IdP names the registered users below link through, as a federation would declare them. */
const named = defineModule({ name: "test-idps" }, (m) => [
	m.contribute(upstreamNames).by(() => ({
		declaredBy: "test-idps",
		names: ["example", "corp:eu", "idp", "i"].map((name) => ({
			name,
			issuer: `https://${name.replace(":", "-")}.example`,
		})),
	})),
]);

const boot = (registered: unknown[]) =>
	assemble({
		modules: [usersModule, secretHashModule, memoryUsersStores().module, named],
		config: { ...kernelConfig(), users: { registered } },
	});

const aliceEntry = {
	identifier: "alice",
	subject: "s-alice",
	"password-hash": testPasswordHash("correct horse"),
	attributes: { name: "Alice", email: "Alice@example.com" },
	upstream: [{ idp: "example", subject: "u-alice" }],
};

/** Users from the settings holding alice, with the work of every password check recorded in order. */
function counting() {
	let checks: readonly string[] = [];
	const stores = memoryUsersStores();
	const source = registeredUsers([aliceEntry], (inUse) => {
		const recording = recordingChecker(inUse, randomBytes);
		checks = recording.works;
		return recording.checker;
	});
	const counted = ledgerUsers(source, keptLinks(source, stores.links.store), stores.contacts.store);
	return { source, users: counted, checks };
}

usersContract("settings", {
	open: async () => (await boot([aliceEntry])).get(users),
	openBcrypt: async () =>
		(await boot([{ identifier: "long", "password-hash": testBcryptHash(seventyTwoBytes) }])).get(
			users,
		),
	openCounting: async () => counting(),
});

ledgerContract("settings", {
	open: async () => {
		const { source, checks } = counting();
		return { ledger: source, checks };
	},
	upstreamOfAlice: { idp: "example", subject: "u-alice" },
});

it("matches a password of exactly 1024 bytes", async () => {
	const u = (await boot([testUser("a", "x".repeat(1024))])).get(users);
	expect((await u.verify("a", "x".repeat(1024))).kind).toBe("user");
});

it("refuses a password past 1024 bytes before any check", async () => {
	const { users: u, checks } = counting();
	// 342 characters, but 1026 bytes.
	const long = "\u3042".repeat(342);
	expect(await u.verify("alice", long)).toEqual({ kind: "none" });
	expect(await u.verify("nobody", long)).toEqual({ kind: "none" });
	expect(checks).toEqual([]);
});

it("refuses to start with a plain password, work past the limits or a repeated identifier", async () => {
	await expect(boot([{ identifier: "a", "password-hash": "plain" }])).rejects.toBeInstanceOf(
		BootRefused,
	);
	const zeros = (n: number) => Buffer.alloc(n).toString("base64").replace(/=+$/, "");
	const tooCostly = `$scrypt$ln=30,r=8,p=1$${zeros(16)}$${zeros(32)}`;
	await expect(boot([{ identifier: "a", "password-hash": tooCostly }])).rejects.toBeInstanceOf(
		BootRefused,
	);
	// An N Node's scrypt rejects (ln at least 16·r) would fail every login through the decoys.
	const nodeRejects = `$scrypt$ln=16,r=1,p=1$${zeros(16)}$${zeros(32)}`;
	await expect(boot([{ identifier: "a", "password-hash": nodeRejects }])).rejects.toBeInstanceOf(
		BootRefused,
	);
	await expect(boot([testUser("a", "x"), testUser("a", "y")])).rejects.toBeInstanceOf(BootRefused);
});

it("matches identifiers exactly", async () => {
	const zoe = testUser("Zo\u00eb", "p", { subject: "s-zoe" });
	const u = (await boot([testUser("Alice", "p"), zoe])).get(users);
	expect((await u.verify("Alice", "p")).kind).toBe("user");
	for (const other of ["alice", " Alice", "\uff21lice"])
		expect((await u.verify(other, "p")).kind).toBe("none");
	expect((await u.verify("Zo\u00eb", "p")).kind).toBe("user");
	expect((await u.verify("Zoe\u0308", "p")).kind).toBe("none");
});

it("refuses to start on identifiers a person could mistake, or a shared subject", async () => {
	for (const pair of [
		["Alice", "alice"],
		["Zo\u00eb", "Zoe\u0308"],
		["bob", " bob"],
		["\ufb01ona", "fiona"],
		["stra\u00dfe", "STRASSE"],
		["stra\u1e9ee", "strasse"],
		["\u03bf\u03b4\u03bf\u03c3", "\u039f\u0394\u039f\u03a3"],
	]) {
		// Each with a subject of its own, so only the identifiers can refuse the boot.
		const pairOf = pair.map((id, i) => testUser(id, "p", { subject: `s-${i}` }));
		await expect(boot(pairOf), pair.join(" ")).rejects.toBeInstanceOf(BootRefused);
	}
	await expect(
		boot([testUser("bob", "p", { subject: "alice" }), testUser("alice", "q")]),
	).rejects.toBeInstanceOf(BootRefused);
	await expect(
		boot([testUser("a", "p", { subject: "s" }), testUser("b", "q", { subject: "s" })]),
	).rejects.toBeInstanceOf(BootRefused);
});

it("refuses to start on an empty identifier or subject, or a plain password, naming where", async () => {
	const where = async (registered: unknown[]) =>
		((await boot(registered).catch((error) => error)) as BootRefused).refusals.map((r) => r.where);
	expect(await where([testUser("", "p")])).toEqual(["users.registered.0.identifier"]);
	expect(await where([testUser("a", "p", { subject: "" })])).toEqual([
		"users.registered.0.subject",
	]);
	expect(await where([{ identifier: "a", "password-hash": "plain" }])).toEqual([
		"users.registered.0.password-hash",
	]);
});

it("refuses to start on a subject that is not 1 to 255 ASCII characters, the identifier standing in where it is left out", async () => {
	const where = async (registered: unknown[]) =>
		((await boot(registered).catch((error) => error)) as BootRefused).refusals.map((r) => r.where);
	for (const user of [
		testUser("a", "p", { subject: "s-é" }),
		testUser("a", "p", { subject: "s".repeat(256) }),
		testUser("アリス", "p"),
	]) {
		expect(await where([user]), JSON.stringify(user)).toEqual(["users.registered.0.subject"]);
	}
	const named = await boot([testUser("アリス", "p", { subject: "s-alice" })]);
	expect((await named.get(users).bySubject("s-alice")).kind).toBe("user");
});

it("refuses to start on an attribute value users does not accept, naming the attribute but never the value", async () => {
	const refused = async (attributes: Record<string, unknown>) =>
		((await boot([testUser("a", "p", { attributes })]).catch((error) => error)) as BootRefused)
			.refusals;
	for (const [name, value] of [
		["picture", "javascript:alert(1)"],
		["picture", "http://pic.example/a.png"],
		["picture", "https://PIC.example/a.png"],
		["email", "a@victim.test/x"],
		["name", "Al\u202Eice"],
		["groups", ["admins", "st\u0000aff"]],
		["email_verified", "true"],
		["hd", "example.com\u0000"],
	] as const) {
		const refusals = await refused({ name: "Alice", [name]: value });
		expect(refusals, name).toEqual([
			{
				where: `users.registered.0.attributes.${name}`,
				reason: "not a value this attribute takes",
			},
		]);
	}
	const accepted = {
		name: "Alice",
		email: "alice@example.com",
		email_verified: true,
		picture: "https://pic.example/a.png",
		groups: ["admins"],
		hd: "example.com",
		level: 3,
	};
	const u = (await boot([testUser("a", "p", { subject: "s-a", attributes: accepted })])).get(users);
	expect(await u.bySubject("s-a")).toEqual({
		kind: "user",
		user: { subject: "s-a", attributes: accepted },
	});
});

it("links an upstream identity as its IdP's name and upstream subject, matched exactly, and once", async () => {
	const hash = testPasswordHash("p");
	const app = await boot([
		{ identifier: "a", "password-hash": hash, upstream: [{ idp: "corp:eu", subject: "s:1" }] },
	]);
	expect((await app.get(users).byUpstream("corp:eu", "s:1")).kind).toBe("user");
	expect((await app.get(users).byUpstream("corp", "eu:s:1")).kind).toBe("none");
	await expect(
		boot([
			{ identifier: "a", "password-hash": hash, upstream: [{ idp: "idp", subject: "same" }] },
			{ identifier: "b", "password-hash": hash, upstream: [{ idp: "idp", subject: "same" }] },
		]),
	).rejects.toBeInstanceOf(BootRefused);
	// One string is no pair: it is refused, never split.
	for (const bad of [
		{ idp: "", subject: "s" },
		{ idp: "i", subject: "" },
		{ idp: "i" },
		"idp:sub",
	]) {
		await expect(
			boot([{ identifier: "a", "password-hash": hash, upstream: [bad] }]),
			JSON.stringify(bad),
		).rejects.toBeInstanceOf(BootRefused);
	}
});

it("answers unavailable, never none, when written links cannot be read", async () => {
	const down = unavailableSwitch<LinkStore>("link store");
	down.unavailable("save", "read", "update");
	const u = (
		await assemble({
			modules: [
				usersModule,
				secretHashModule,
				switchedModule(memoryUsersStores().module, linkStore, down),
			],
			config: { ...kernelConfig(), users: { registered: [testUser("a", "p")] } },
		})
	).get(users);
	await expect(u.byUpstream("idp", "s")).rejects.toSatisfy(isUnavailable);
	await expect(u.link("a", { idp: "idp", subject: "s" })).rejects.toSatisfy(isUnavailable);
});

it("checks passwords within its own assembly's secret-hash limit, whatever another assembly sets", async () => {
	const assembled = (max: number) =>
		assemble({
			modules: [usersModule, secretHashModule, memoryUsersStores().module],
			config: {
				...kernelConfig(),
				users: { registered: [testUser("a", "p")] },
				"secret-hash": { "max-concurrent": max },
			},
		});
	const one = (await assembled(1)).get(users);
	// Built after, with its own limit; the first keeps its one.
	await assembled(8);
	const first = one.verify("a", "p");
	await expect(one.verify("a", "p")).rejects.toSatisfy(isUnavailable);
	expect((await first).kind).toBe("user");
});

describe("records", () => {
	const empty = () => registeredUsers([], (inUse) => recordingChecker(inUse, randomBytes).checker);
	const open = () => {
		const stores = memoryUsersStores();
		const source = empty();
		const u = ledgerUsers(source, keptLinks(source, stores.links.store), stores.contacts.store);
		return { u, stores };
	};

	it("reads only email contacts from the contact store, each as its kind and value", async () => {
		const { u, stores } = open();
		const held = [
			{ kind: "email", value: "a@example.com", extra: 1 },
			{ kind: "phone", value: "1" },
			{ kind: "email", value: 7 },
			null,
			"b@example.com",
		];
		await stores.contacts.store.save("s", held as unknown as StoredContacts, "endless");
		const one = { kind: "email", value: "c@example.com" };
		await stores.contacts.store.save("t", one as unknown as StoredContacts, "endless");
		expect(await u.contactsOf("s")).toEqual([{ kind: "email", value: "a@example.com" }]);
		expect(await u.contactsOf("t")).toEqual([]);
	});

	it("writes only a contact's kind and value", async () => {
		const { u, stores } = open();
		const given = { kind: "email", value: "a@example.com", extra: 1 } as Contact;
		await u.verifiedContact("s", given);
		expect(await stores.contacts.store.read("s")).toEqual([
			{ kind: "email", value: "a@example.com" },
		]);
	});

	it("answers unavailable when a record the store said it held is gone on the next change", async () => {
		const { stores } = open();
		const vanishing: LinkStore = {
			save: async () => "exists",
			read: async () => undefined,
			update: async () => undefined,
		};
		const source = empty();
		const u = ledgerUsers(source, keptLinks(source, vanishing), stores.contacts.store);
		await expect(u.link("s", { idp: "i", subject: "u" })).rejects.toSatisfy(isUnavailable);
	});
});

it("registers no users, and a user no attributes or upstream identities, that the operator leaves out", () => {
	expect(usersModule.section?.parse({})).toEqual({ registered: [] });
	const written = { identifier: "bob", "password-hash": aliceEntry["password-hash"] };
	expect(record.parse(written)).toEqual({ ...written, attributes: {}, upstream: [] });
});
